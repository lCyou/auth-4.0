package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"openid-aas/backend/config"
	"openid-aas/backend/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GitHubOAuthHandler handles GitHub OAuth flow
type GitHubOAuthHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

// NewGitHubOAuthHandler creates a new GitHub OAuth handler
func NewGitHubOAuthHandler(db *pgxpool.Pool, cfg *config.Config) *GitHubOAuthHandler {
	return &GitHubOAuthHandler{
		db:     db,
		config: cfg,
	}
}

// GetAuthURL returns the GitHub OAuth authorization URL
func (h *GitHubOAuthHandler) GetAuthURL(state string) string {
	baseURL := "https://github.com/login/oauth/authorize"
	params := url.Values{}
	params.Add("client_id", h.config.GitHubClientID)
	params.Add("redirect_uri", h.config.GitHubRedirectURI)
	params.Add("scope", "user:email read:user")
	params.Add("state", state)

	return baseURL + "?" + params.Encode()
}

// ExchangeCode exchanges authorization code for tokens
func (h *GitHubOAuthHandler) ExchangeCode(code string) (*GitHubTokenResponse, error) {
	tokenURL := "https://github.com/login/oauth/access_token"
	data := url.Values{}
	data.Set("client_id", h.config.GitHubClientID)
	data.Set("client_secret", h.config.GitHubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", h.config.GitHubRedirectURI)

	req, err := http.NewRequest("POST", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.URL.RawQuery = data.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp GitHubTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information from GitHub
func (h *GitHubOAuthHandler) GetUserInfo(accessToken string) (*GitHubUserInfo, error) {
	userInfoURL := "https://api.github.com/user"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user info failed: %s", string(body))
	}

	var userInfo GitHubUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	// Get user emails
	emails, err := h.GetUserEmails(accessToken)
	if err == nil && len(emails) > 0 {
		// Find primary email
		for _, email := range emails {
			if email.Primary && email.Verified {
				userInfo.Email = email.Email
				userInfo.EmailVerified = true
				break
			}
		}
		// If no primary email found, use first verified email
		if userInfo.Email == "" {
			for _, email := range emails {
				if email.Verified {
					userInfo.Email = email.Email
					userInfo.EmailVerified = true
					break
				}
			}
		}
	}

	return &userInfo, nil
}

// GetUserEmails retrieves user email addresses from GitHub
func (h *GitHubOAuthHandler) GetUserEmails(accessToken string) ([]GitHubEmail, error) {
	emailsURL := "https://api.github.com/user/emails"
	req, err := http.NewRequest("GET", emailsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user emails: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user emails failed: %s", string(body))
	}

	var emails []GitHubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, fmt.Errorf("failed to parse emails response: %w", err)
	}

	return emails, nil
}

// CreateOrUpdateUser creates or updates a user and their provider connection
func (h *GitHubOAuthHandler) CreateOrUpdateUser(ctx context.Context, userInfo *GitHubUserInfo, tokenResp *GitHubTokenResponse) (*models.User, error) {
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check if user exists by provider
	var user models.User
	providerUserID := fmt.Sprintf("%d", userInfo.ID)
	err = tx.QueryRow(ctx, `
		SELECT u.id, u.sub, u.name, u.email, u.email_verified, u.picture, u.created_at, u.updated_at
		FROM users u
		INNER JOIN user_providers up ON u.id = up.user_id
		WHERE up.provider = 'github' AND up.provider_user_id = $1
	`, providerUserID).Scan(
		&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		// Unexpected error occurred
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		// User doesn't exist, create new user
		userID := uuid.New()
		sub := fmt.Sprintf("github_%d", userInfo.ID)

		// Use login as name if name is not provided
		name := userInfo.Name
		if name == "" {
			name = userInfo.Login
		}

		// Ensure email is not empty
		email := userInfo.Email
		if email == "" {
			email = fmt.Sprintf("%s@users.noreply.github.com", userInfo.Login)
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO users (id, sub, name, email, email_verified, picture)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, sub, name, email, email_verified, picture, created_at, updated_at
		`, userID, sub, name, email, userInfo.EmailVerified, userInfo.AvatarURL).Scan(
			&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture, &user.CreatedAt, &user.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to create user (sub=%s, name=%s, email=%s): %w", sub, name, email, err)
		}

		// Create provider connection
		_, err = tx.Exec(ctx, `
			INSERT INTO user_providers (user_id, provider, provider_user_id, access_token, token_type, scope)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, user.ID, "github", providerUserID, tokenResp.AccessToken, tokenResp.TokenType, tokenResp.Scope)

		if err != nil {
			return nil, fmt.Errorf("failed to create provider connection: %w", err)
		}
	} else {
		// User exists, update information
		name := userInfo.Name
		if name == "" {
			name = userInfo.Login
		}

		_, err = tx.Exec(ctx, `
			UPDATE users
			SET name = $1, email = $2, email_verified = $3, picture = $4, updated_at = NOW()
			WHERE id = $5
		`, name, userInfo.Email, userInfo.EmailVerified, userInfo.AvatarURL, user.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}

		// Update provider connection
		_, err = tx.Exec(ctx, `
			UPDATE user_providers
			SET access_token = $1, token_type = $2, scope = $3, updated_at = NOW()
			WHERE user_id = $4 AND provider = 'github'
		`, tokenResp.AccessToken, tokenResp.TokenType, tokenResp.Scope, user.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to update provider connection: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &user, nil
}

// GitHubTokenResponse represents GitHub's token response
type GitHubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// GitHubUserInfo represents GitHub user information
type GitHubUserInfo struct {
	ID              int    `json:"id"`
	Login           string `json:"login"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"-"` // Set separately from emails endpoint
	AvatarURL       string `json:"avatar_url"`
	Bio             string `json:"bio"`
	Company         string `json:"company"`
	Location        string `json:"location"`
	Blog            string `json:"blog"`
	TwitterUsername string `json:"twitter_username"`
	PublicRepos     int    `json:"public_repos"`
	Followers       int    `json:"followers"`
	Following       int    `json:"following"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// GitHubEmail represents a GitHub user email
type GitHubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}
