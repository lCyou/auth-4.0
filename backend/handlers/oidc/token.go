package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"openid-aas/backend/config"
	"openid-aas/backend/models"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenHandler handles the OAuth/OIDC token endpoint
type TokenHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewTokenHandler(db *pgxpool.Pool, cfg *config.Config) *TokenHandler {
	return &TokenHandler{
		db:     db,
		config: cfg,
	}
}

// HandleToken processes token requests
func (h *TokenHandler) HandleToken(c *gin.Context) {
	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		h.handleRefreshTokenGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Grant type not supported",
		})
	}
}

func (h *TokenHandler) handleAuthorizationCodeGrant(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	codeVerifier := c.PostForm("code_verifier")

	// Validate required parameters
	if code == "" || redirectURI == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Validate client credentials
	var client models.Client
	err := h.db.QueryRow(context.Background(), `
		SELECT id, client_id, client_secret, client_name, redirect_uris
		FROM clients WHERE client_id = $1
	`, clientID).Scan(&client.ID, &client.ClientID, &client.ClientSecret, &client.ClientName, &client.RedirectURIs)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Validate client secret
	if client.ClientSecret != clientSecret {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Retrieve authorization code
	var authCode models.AuthorizationCode
	var user models.User
	err = h.db.QueryRow(context.Background(), `
		SELECT ac.id, ac.code, ac.client_id, ac.user_id, ac.redirect_uri, ac.scope, 
		       ac.code_challenge, ac.code_challenge_method, ac.nonce, ac.expires_at, ac.used,
		       u.id, u.sub, u.name, u.email, u.email_verified, u.picture
		FROM authorization_codes ac
		INNER JOIN users u ON ac.user_id = u.id
		WHERE ac.code = $1 AND ac.client_id = $2
	`, code, client.ID).Scan(
		&authCode.ID, &authCode.Code, &authCode.ClientID, &authCode.UserID,
		&authCode.RedirectURI, &authCode.Scope, &authCode.CodeChallenge,
		&authCode.CodeChallengeMethod, &authCode.Nonce, &authCode.ExpiresAt, &authCode.Used,
		&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code not found or invalid",
		})
		return
	}

	// Validate authorization code
	if authCode.Used {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code has already been used",
		})
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code has expired",
		})
		return
	}

	if authCode.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Redirect URI mismatch",
		})
		return
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Code verifier required",
			})
			return
		}

		var challenge string
		if authCode.CodeChallengeMethod == "S256" {
			hash := sha256.Sum256([]byte(codeVerifier))
			challenge = base64.RawURLEncoding.EncodeToString(hash[:])
		} else {
			challenge = codeVerifier
		}

		if challenge != authCode.CodeChallenge {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "Code verifier invalid",
			})
			return
		}
	}

	// Mark code as used
	_, err = h.db.Exec(context.Background(), `
		UPDATE authorization_codes SET used = true WHERE id = $1
	`, authCode.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to mark code as used",
		})
		return
	}

	// Generate access token
	accessTokenString, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate access token",
		})
		return
	}

	accessTokenID := uuid.New()
	expiresAt := time.Now().Add(time.Duration(h.config.AccessTokenExpiry) * time.Second)

	_, err = h.db.Exec(context.Background(), `
		INSERT INTO access_tokens (id, token, client_id, user_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, accessTokenID, accessTokenString, client.ID, user.ID, authCode.Scope, expiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to store access token",
		})
		return
	}

	// Generate refresh token
	refreshTokenString, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate refresh token",
		})
		return
	}

	refreshExpiresAt := time.Now().Add(time.Duration(h.config.RefreshTokenExpiry) * time.Second)

	_, err = h.db.Exec(context.Background(), `
		INSERT INTO refresh_tokens (token, client_id, user_id, access_token_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, refreshTokenString, client.ID, user.ID, accessTokenID, authCode.Scope, refreshExpiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to store refresh token",
		})
		return
	}

	// Generate ID token if openid scope is requested
	var idToken string
	if contains(authCode.Scope, "openid") {
		idToken, err = utils.GenerateIDToken(
			user.Sub, user.Name, user.Email, user.Picture,
			authCode.Nonce, client.ClientID, h.config.JWTIssuer,
			user.EmailVerified, h.config.AccessTokenExpiry,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to generate ID token",
			})
			return
		}
	}

	// Return token response
	response := gin.H{
		"access_token":  accessTokenString,
		"token_type":    "Bearer",
		"expires_in":    h.config.AccessTokenExpiry,
		"refresh_token": refreshTokenString,
		"scope":         authCode.Scope,
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	c.JSON(http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshTokenGrant(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if refreshToken == "" || clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Validate client
	var client models.Client
	err := h.db.QueryRow(context.Background(), `
		SELECT id, client_id, client_secret FROM clients WHERE client_id = $1
	`, clientID).Scan(&client.ID, &client.ClientID, &client.ClientSecret)

	if err != nil || client.ClientSecret != clientSecret {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Client authentication failed",
		})
		return
	}

	// Validate refresh token
	var rt models.RefreshToken
	var user models.User
	err = h.db.QueryRow(context.Background(), `
		SELECT rt.id, rt.token, rt.client_id, rt.user_id, rt.scope, rt.expires_at, rt.revoked,
		       u.id, u.sub, u.name, u.email, u.email_verified, u.picture
		FROM refresh_tokens rt
		INNER JOIN users u ON rt.user_id = u.id
		WHERE rt.token = $1 AND rt.client_id = $2
	`, refreshToken, client.ID).Scan(
		&rt.ID, &rt.Token, &rt.ClientID, &rt.UserID, &rt.Scope, &rt.ExpiresAt, &rt.Revoked,
		&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Refresh token not found or invalid",
		})
		return
	}

	if rt.Revoked || time.Now().After(rt.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Refresh token is revoked or expired",
		})
		return
	}

	// Generate new access token
	accessTokenString, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate access token",
		})
		return
	}

	accessTokenID := uuid.New()
	expiresAt := time.Now().Add(time.Duration(h.config.AccessTokenExpiry) * time.Second)

	_, err = h.db.Exec(context.Background(), `
		INSERT INTO access_tokens (id, token, client_id, user_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, accessTokenID, accessTokenString, client.ID, user.ID, rt.Scope, expiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to store access token",
		})
		return
	}

	// Update refresh token's access token reference
	_, err = h.db.Exec(context.Background(), `
		UPDATE refresh_tokens SET access_token_id = $1 WHERE id = $2
	`, accessTokenID, rt.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to update refresh token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessTokenString,
		"token_type":   "Bearer",
		"expires_in":   h.config.AccessTokenExpiry,
		"scope":        rt.Scope,
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)+1] == substr+" " || s[len(s)-len(substr)-1:] == " "+substr || len(s) > len(substr)+1 && strings.Contains(s, " "+substr+" ")))
}
