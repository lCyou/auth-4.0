package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminAuth middleware validates admin session
func AdminAuth(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken := c.GetHeader("X-Session-Token")
		if sessionToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No session token provided"})
			c.Abort()
			return
		}

		// Validate session
		var adminID uuid.UUID
		err := db.QueryRow(context.Background(), `
			SELECT admin_id FROM admin_sessions 
			WHERE session_token = $1 AND expires_at > NOW()
		`, sessionToken).Scan(&adminID)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
			c.Abort()
			return
		}

		c.Set("admin_id", adminID)
		c.Next()
	}
}
