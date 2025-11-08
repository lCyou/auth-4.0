package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"openid-aas/backend/config"
	"openid-aas/backend/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GoogleOAuthHandler handles Google OAuth flow
type GoogleOAuthHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

// NewGoogleOAuthHandler creates a new Google OAuth handler
func NewGoogleOAuthHandler(db *pgxpool.Pool, cfg *config.Config) *GoogleOAuthHandler {
	return &GoogleOAuthHandler{
		db:     db,
		config: cfg,
	}
}

// GetAuthURL returns the Google OAuth authorization URL
func (h *GoogleOAuthHandler) GetAuthURL(state string) string {
	baseURL := "https://accounts.google.com/o/oauth2/v2/auth"
	params := url.Values{}
	params.Add("client_id", h.config.GoogleClientID)
	params.Add("redirect_uri", h.config.GoogleRedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email")
	params.Add("state", state)
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")

	return baseURL + "?" + params.Encode()
}

// ExchangeCode exchanges authorization code for tokens
func (h *GoogleOAuthHandler) ExchangeCode(code string) (*GoogleTokenResponse, error) {
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", h.config.GoogleClientID)
	data.Set("client_secret", h.config.GoogleClientSecret)
	data.Set("redirect_uri", h.config.GoogleRedirectURI)
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(tokenURL, data)
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

	var tokenResp GoogleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information from Google
func (h *GoogleOAuthHandler) GetUserInfo(accessToken string) (*GoogleUserInfo, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

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

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return &userInfo, nil
}

// CreateOrUpdateUser creates or updates a user and their provider connection
func (h *GoogleOAuthHandler) CreateOrUpdateUser(ctx context.Context, userInfo *GoogleUserInfo, tokenResp *GoogleTokenResponse) (*models.User, error) {
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Check if user exists by provider
	var user models.User
	err = tx.QueryRow(ctx, `
		SELECT u.id, u.sub, u.name, u.email, u.email_verified, u.picture, u.created_at, u.updated_at
		FROM users u
		INNER JOIN user_providers up ON u.id = up.user_id
		WHERE up.provider = 'google' AND up.provider_user_id = $1
	`, userInfo.ID).Scan(
		&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		// User doesn't exist, create new user
		userID := uuid.New()
		sub := fmt.Sprintf("google_%s", userInfo.ID)

		err = tx.QueryRow(ctx, `
			INSERT INTO users (id, sub, name, email, email_verified, picture)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, sub, name, email, email_verified, picture, created_at, updated_at
		`, userID, sub, userInfo.Name, userInfo.Email, userInfo.VerifiedEmail, userInfo.Picture).Scan(
			&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture, &user.CreatedAt, &user.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		// Create provider connection
		_, err = tx.Exec(ctx, `
			INSERT INTO user_providers (user_id, provider, provider_user_id, access_token, refresh_token, id_token, scope, token_type)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, user.ID, "google", userInfo.ID, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.IDToken, tokenResp.Scope, tokenResp.TokenType)

		if err != nil {
			return nil, fmt.Errorf("failed to create provider connection: %w", err)
		}
	} else {
		// User exists, update information
		_, err = tx.Exec(ctx, `
			UPDATE users
			SET name = $1, email = $2, email_verified = $3, picture = $4, updated_at = NOW()
			WHERE id = $5
		`, userInfo.Name, userInfo.Email, userInfo.VerifiedEmail, userInfo.Picture, user.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}

		// Update provider connection
		_, err = tx.Exec(ctx, `
			UPDATE user_providers
			SET access_token = $1, refresh_token = $2, id_token = $3, scope = $4, token_type = $5, updated_at = NOW()
			WHERE user_id = $6 AND provider = 'google'
		`, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.IDToken, tokenResp.Scope, tokenResp.TokenType, user.ID)

		if err != nil {
			return nil, fmt.Errorf("failed to update provider connection: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &user, nil
}

// GoogleTokenResponse represents Google's token response
type GoogleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}
