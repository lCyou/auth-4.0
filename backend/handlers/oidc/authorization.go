package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"openid-aas/backend/config"
	"openid-aas/backend/models"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthorizationHandler handles the OAuth/OIDC authorization endpoint
type AuthorizationHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewAuthorizationHandler(db *pgxpool.Pool, cfg *config.Config) *AuthorizationHandler {
	return &AuthorizationHandler{
		db:     db,
		config: cfg,
	}
}

// HandleAuthorize processes authorization requests
func (h *AuthorizationHandler) HandleAuthorize(c *gin.Context) {
	// Parse query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Validate response_type
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only 'code' response type is supported",
		})
		return
	}

	// Validate client
	var client models.Client
	err := h.db.QueryRow(context.Background(), `
		SELECT id, client_id, client_name, redirect_uris, grant_types, response_types, scope
		FROM clients WHERE client_id = $1
	`, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientName,
		&client.RedirectURIs, &client.GrantTypes, &client.ResponseTypes, &client.Scope,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	// Validate redirect URI
	validRedirectURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirectURI = true
			break
		}
	}

	if !validRedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	// Check if user is authenticated (from session or context)
	userID, exists := c.Get("user_id")
	if !exists {
		// User not authenticated - redirect to login
		// In a real implementation, this would redirect to your auth flow
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "login_required",
			"error_description": "User must be authenticated",
		})
		return
	}

	// Get user information
	var user models.User
	err = h.db.QueryRow(context.Background(), `
		SELECT id, sub, name, email, email_verified, picture
		FROM users WHERE id = $1
	`, userID).Scan(&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to retrieve user information",
		})
		return
	}

	// Generate authorization code
	code, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate authorization code",
		})
		return
	}

	// Store authorization code
	_, err = h.db.Exec(context.Background(), `
		INSERT INTO authorization_codes 
		(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, code, client.ID, user.ID, redirectURI, scope, codeChallenge, codeChallengeMethod, nonce, state, time.Now().Add(10*time.Minute))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to store authorization code",
		})
		return
	}

	// Build redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		redirectURL += fmt.Sprintf("&state=%s", state)
	}

	c.Redirect(http.StatusFound, redirectURL)
}
