package oidc

import (
	"context"
	"net/http"
	"strings"

	"openid-aas/backend/config"
	"openid-aas/backend/models"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserInfoHandler handles the OIDC userinfo endpoint
type UserInfoHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewUserInfoHandler(db *pgxpool.Pool, cfg *config.Config) *UserInfoHandler {
	return &UserInfoHandler{
		db:     db,
		config: cfg,
	}
}

// HandleUserInfo returns user information for the authenticated user
func (h *UserInfoHandler) HandleUserInfo(c *gin.Context) {
	// Extract access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "No authorization header provided",
		})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid authorization header format",
		})
		return
	}

	accessToken := parts[1]

	// Validate access token and get user info
	var user models.User
	var scope string
	err := h.db.QueryRow(context.Background(), `
		SELECT u.id, u.sub, u.name, u.email, u.email_verified, u.picture, at.scope
		FROM users u
		INNER JOIN access_tokens at ON u.id = at.user_id
		WHERE at.token = $1 AND at.revoked = false AND at.expires_at > NOW()
	`, accessToken).Scan(&user.ID, &user.Sub, &user.Name, &user.Email, &user.EmailVerified, &user.Picture, &scope)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Access token is invalid or expired",
		})
		return
	}

	// Build response based on requested scopes
	response := gin.H{
		"sub": user.Sub,
	}

	scopes := strings.Split(scope, " ")
	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		scopeMap[s] = true
	}

	if scopeMap["profile"] {
		response["name"] = user.Name
		response["picture"] = user.Picture
	}

	if scopeMap["email"] {
		response["email"] = user.Email
		response["email_verified"] = user.EmailVerified
	}

	c.JSON(http.StatusOK, response)
}
