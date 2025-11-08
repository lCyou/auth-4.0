package admin

import (
	"context"
	"net/http"
	"time"

	"openid-aas/backend/config"
	"openid-aas/backend/models"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler handles admin authentication
type AuthHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewAuthHandler(db *pgxpool.Pool, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		db:     db,
		config: cfg,
	}
}

// HandleLogin authenticates an admin user
func (h *AuthHandler) HandleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get admin from database
	var admin models.Admin
	err := h.db.QueryRow(context.Background(), `
		SELECT id, username, email, password_hash FROM admins WHERE username = $1
	`, req.Username).Scan(&admin.ID, &admin.Username, &admin.Email, &admin.PasswordHash)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password using crypt (PostgreSQL's password hash)
	var storedHash string
	err = h.db.QueryRow(context.Background(), `
		SELECT crypt($1, password_hash) = password_hash FROM admins WHERE id = $2
	`, req.Password, admin.ID).Scan(&storedHash)

	if err != nil || storedHash != "t" {
		// Fallback to bcrypt comparison for backward compatibility
		if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
	}

	// Generate session token
	sessionToken, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session"})
		return
	}

	// Store session
	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = h.db.Exec(context.Background(), `
		INSERT INTO admin_sessions (admin_id, session_token, expires_at)
		VALUES ($1, $2, $3)
	`, admin.ID, sessionToken, expiresAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_token": sessionToken,
		"expires_at":    expiresAt,
		"admin": gin.H{
			"id":       admin.ID,
			"username": admin.Username,
			"email":    admin.Email,
		},
	})
}

// HandleLogout invalidates an admin session
func (h *AuthHandler) HandleLogout(c *gin.Context) {
	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No session token provided"})
		return
	}

	_, err := h.db.Exec(context.Background(), `
		DELETE FROM admin_sessions WHERE session_token = $1
	`, sessionToken)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
