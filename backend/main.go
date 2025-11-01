package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// ユーザーから提供されたデータベース接続情報
	connString := "postgres://user:password@localhost:5432/minus_four"

	// データベース接続プールを作成
	dbpool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create connection pool: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	// Ginルーターを作成
	r := gin.Default()

	// 既存の/pingエンドポイント
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong-v2",
		})
	})

	// データベース接続を確認する新しい/db-pingエンドポイント
	r.GET("/db-ping", func(c *gin.Context) {
		err := dbpool.Ping(context.Background())
		if err != nil {
			c.JSON(500, gin.H{
				"status":  "error",
				"message": "Failed to connect to database",
				"error":   err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Successfully connected to database",
		})
	})

	// サーバーを実行
	r.Run() // デフォルトでは :8080 でリッスンします
}