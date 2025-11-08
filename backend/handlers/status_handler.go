package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ping はシンプルなステータスチェックエンドポイントです。
func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
	})
}

// DbPing はデータベース接続をチェックするエンドポイントのハンドラを返します。
func DbPing(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := db.Ping(context.Background())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status":  "error",
				"message": "Failed to ping database",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Successfully pinged database",
		})
	}
}
