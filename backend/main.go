package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openid-aas/backend/config"
	"openid-aas/backend/database"
	"openid-aas/backend/routes"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize JWT keys
	if err := utils.InitializeKeys(); err != nil {
		log.Fatalf("Failed to initialize JWT keys: %v", err)
	}

	// Connect to database
	dbpool, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbpool.Close()

	log.Println("Successfully connected to database")

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	r := gin.Default()

	// Setup routes
	routes.Setup(r, dbpool, cfg)

	// HTTP server configuration
	srv := &http.Server{
		Addr:    ":" + cfg.ServerPort,
		Handler: r,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %s\n", err)
		}
	}()

	// Graceful shutdown
