package admin

import (
	"context"
	"net/http"

	"openid-aas/backend/config"
	"openid-aas/backend/models"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsersHandler handles user management
type UsersHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewUsersHandler(db *pgxpool.Pool, cfg *config.Config) *UsersHandler {
	return &UsersHandler{
		db:     db,
		config: cfg,
	}
}

// HandleListUsers returns all users
func (h *UsersHandler) HandleListUsers(c *gin.Context) {
	rows, err := h.db.Query(context.Background(), `
		SELECT id, sub, name, email, email_verified, picture, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
	`)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Sub, &user.Name, &user.Email,
			&user.EmailVerified, &user.Picture,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// HandleGetUser returns a specific user with their provider connections
func (h *UsersHandler) HandleGetUser(c *gin.Context) {
	userID := c.Param("id")

	var user models.User
	err := h.db.QueryRow(context.Background(), `
		SELECT id, sub, name, email, email_verified, picture, created_at, updated_at
		FROM users WHERE id = $1
	`, userID).Scan(
		&user.ID, &user.Sub, &user.Name, &user.Email,
		&user.EmailVerified, &user.Picture,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Get provider connections
	rows, err := h.db.Query(context.Background(), `
		SELECT id, provider, provider_user_id, scope, created_at
		FROM user_providers WHERE user_id = $1
	`, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch providers"})
		return
	}
	defer rows.Close()

	providers := []gin.H{}
	for rows.Next() {
		var id, provider, providerUserID, scope string
		var createdAt interface{}
		if err := rows.Scan(&id, &provider, &providerUserID, &scope, &createdAt); err == nil {
			providers = append(providers, gin.H{
				"id":               id,
				"provider":         provider,
				"provider_user_id": providerUserID,
				"scope":            scope,
				"created_at":       createdAt,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user":      user,
		"providers": providers,
	})
}

// HandleDeleteUser deletes a user
func (h *UsersHandler) HandleDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	_, err := h.db.Exec(context.Background(), `
		DELETE FROM users WHERE id = $1
	`, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
