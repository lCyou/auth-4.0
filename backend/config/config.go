package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	// Database
	DatabaseURL string

	// Server
	ServerPort string
	ServerHost string

	// OAuth Providers
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURI  string

	// JWT
	JWTSecretKey       string
	JWTIssuer          string
	AccessTokenExpiry  int // seconds
	RefreshTokenExpiry int // seconds

	// CORS
	AllowedOrigins []string

	// Environment
	Environment string // development, production
}

func LoadConfig() (*Config, error) {
	// .env ファイルを読み込む（存在しない場合は無視）
	_ = godotenv.Load()

	cfg := &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://user:password@localhost:5432/openid_aas?sslmode=disable"),
		ServerPort:  getEnv("SERVER_PORT", "8080"),
		ServerHost:  getEnv("SERVER_HOST", "http://localhost:8080"),

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURI:  getEnv("GOOGLE_REDIRECT_URI", "http://localhost:8080/api/auth/callback/google"),

		GitHubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURI:  getEnv("GITHUB_REDIRECT_URI", "http://localhost:8080/api/auth/callback/github"),

		JWTSecretKey:       getEnv("JWT_SECRET_KEY", "your-secret-key-change-this-in-production"),
		JWTIssuer:          getEnv("JWT_ISSUER", "http://localhost:8080"),
		AccessTokenExpiry:  3600,  // 1 hour
		RefreshTokenExpiry: 2592000, // 30 days

		AllowedOrigins: []string{
			getEnv("FRONTEND_URL", "http://localhost:3000"),
		},

		Environment: getEnv("ENVIRONMENT", "development"),
	}

	// 必須項目のバリデーション
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
