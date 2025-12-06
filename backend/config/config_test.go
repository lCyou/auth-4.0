package config

import (
	"os"
	"testing"
)

// TestLoadConfig tests loading configuration with default values
func TestLoadConfig(t *testing.T) {
	// Arrange
	// Set a required environment variable to avoid validation error
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
	defer os.Unsetenv("DATABASE_URL")

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg == nil {
		t.Error("LoadConfig() returned nil config")
	}
	if cfg.DatabaseURL == "" {
		t.Error("LoadConfig() returned config with empty DatabaseURL")
	}
}

// TestLoadConfig_MissingDatabaseURL tests that LoadConfig uses default when DATABASE_URL is missing
func TestLoadConfig_MissingDatabaseURL(t *testing.T) {
	// Arrange
	// Ensure DATABASE_URL is not set
	origValue := os.Getenv("DATABASE_URL")
	os.Unsetenv("DATABASE_URL")
	defer func() {
		if origValue != "" {
			os.Setenv("DATABASE_URL", origValue)
		}
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg == nil {
		t.Error("LoadConfig() returned nil config")
	}
	// Should use default value when DATABASE_URL is not set
	expectedDefault := "postgres://user:password@localhost:5432/openid_aas?sslmode=disable"
	if cfg.DatabaseURL != expectedDefault {
		t.Errorf("DatabaseURL = %v, want default %v", cfg.DatabaseURL, expectedDefault)
	}
}

// TestLoadConfig_CustomValues tests loading configuration with custom environment variables
func TestLoadConfig_CustomValues(t *testing.T) {
	// Arrange
	expectedDatabaseURL := "postgres://custom:custom@localhost:5432/customdb"
	expectedServerPort := "3000"
	expectedServerHost := "http://custom.example.com"
	expectedGoogleClientID := "custom-google-client-id"
	expectedJWTSecret := "custom-jwt-secret"

	os.Setenv("DATABASE_URL", expectedDatabaseURL)
	os.Setenv("SERVER_PORT", expectedServerPort)
	os.Setenv("SERVER_HOST", expectedServerHost)
	os.Setenv("GOOGLE_CLIENT_ID", expectedGoogleClientID)
	os.Setenv("JWT_SECRET_KEY", expectedJWTSecret)

	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("SERVER_HOST")
		os.Unsetenv("GOOGLE_CLIENT_ID")
		os.Unsetenv("JWT_SECRET_KEY")
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg.DatabaseURL != expectedDatabaseURL {
		t.Errorf("DatabaseURL = %v, want %v", cfg.DatabaseURL, expectedDatabaseURL)
	}
	if cfg.ServerPort != expectedServerPort {
		t.Errorf("ServerPort = %v, want %v", cfg.ServerPort, expectedServerPort)
	}
	if cfg.ServerHost != expectedServerHost {
		t.Errorf("ServerHost = %v, want %v", cfg.ServerHost, expectedServerHost)
	}
	if cfg.GoogleClientID != expectedGoogleClientID {
		t.Errorf("GoogleClientID = %v, want %v", cfg.GoogleClientID, expectedGoogleClientID)
	}
	if cfg.JWTSecretKey != expectedJWTSecret {
		t.Errorf("JWTSecretKey = %v, want %v", cfg.JWTSecretKey, expectedJWTSecret)
	}
}

// TestLoadConfig_DefaultValues tests that default values are used when environment variables are not set
func TestLoadConfig_DefaultValues(t *testing.T) {
	// Arrange
	// Set only required DATABASE_URL, clear other optional vars
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
	defer os.Unsetenv("DATABASE_URL")
	
	// Clear environment variables to ensure defaults are used
	envVars := []string{
		"SERVER_PORT", "SERVER_HOST", "GOOGLE_CLIENT_ID", 
		"GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
		"JWT_SECRET_KEY", "FRONTEND_URL", "ENVIRONMENT",
	}
	
	origValues := make(map[string]string)
	for _, key := range envVars {
		origValues[key] = os.Getenv(key)
		os.Unsetenv(key)
	}
	defer func() {
		for key, value := range origValues {
			if value != "" {
				os.Setenv(key, value)
			}
		}
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg.ServerPort != "8080" {
		t.Errorf("ServerPort = %v, want default 8080", cfg.ServerPort)
	}
	if cfg.ServerHost != "http://localhost:8080" {
		t.Errorf("ServerHost = %v, want default http://localhost:8080", cfg.ServerHost)
	}
	if cfg.Environment != "development" {
		t.Errorf("Environment = %v, want default development", cfg.Environment)
	}
	if cfg.AccessTokenExpiry != 3600 {
		t.Errorf("AccessTokenExpiry = %v, want default 3600", cfg.AccessTokenExpiry)
	}
	if cfg.RefreshTokenExpiry != 2592000 {
		t.Errorf("RefreshTokenExpiry = %v, want default 2592000", cfg.RefreshTokenExpiry)
	}
}

// TestLoadConfig_AllowedOrigins tests that allowed origins are set correctly
func TestLoadConfig_AllowedOrigins(t *testing.T) {
	// Arrange
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
	expectedFrontendURL := "http://localhost:4000"
	os.Setenv("FRONTEND_URL", expectedFrontendURL)
	
	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("FRONTEND_URL")
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if len(cfg.AllowedOrigins) != 1 {
		t.Errorf("AllowedOrigins length = %d, want 1", len(cfg.AllowedOrigins))
	}
	if cfg.AllowedOrigins[0] != expectedFrontendURL {
		t.Errorf("AllowedOrigins[0] = %v, want %v", cfg.AllowedOrigins[0], expectedFrontendURL)
	}
}

// TestLoadConfig_OAuthProviderSettings tests OAuth provider configuration
func TestLoadConfig_OAuthProviderSettings(t *testing.T) {
	// Arrange
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("GOOGLE_CLIENT_ID", "google-client-id")
	os.Setenv("GOOGLE_CLIENT_SECRET", "google-client-secret")
	os.Setenv("GOOGLE_REDIRECT_URI", "http://localhost:8080/callback/google")
	os.Setenv("GITHUB_CLIENT_ID", "github-client-id")
	os.Setenv("GITHUB_CLIENT_SECRET", "github-client-secret")
	os.Setenv("GITHUB_REDIRECT_URI", "http://localhost:8080/callback/github")

	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("GOOGLE_CLIENT_ID")
		os.Unsetenv("GOOGLE_CLIENT_SECRET")
		os.Unsetenv("GOOGLE_REDIRECT_URI")
		os.Unsetenv("GITHUB_CLIENT_ID")
		os.Unsetenv("GITHUB_CLIENT_SECRET")
		os.Unsetenv("GITHUB_REDIRECT_URI")
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg.GoogleClientID != "google-client-id" {
		t.Errorf("GoogleClientID = %v, want google-client-id", cfg.GoogleClientID)
	}
	if cfg.GoogleClientSecret != "google-client-secret" {
		t.Errorf("GoogleClientSecret = %v, want google-client-secret", cfg.GoogleClientSecret)
	}
	if cfg.GoogleRedirectURI != "http://localhost:8080/callback/google" {
		t.Errorf("GoogleRedirectURI = %v, want http://localhost:8080/callback/google", cfg.GoogleRedirectURI)
	}
	if cfg.GitHubClientID != "github-client-id" {
		t.Errorf("GitHubClientID = %v, want github-client-id", cfg.GitHubClientID)
	}
	if cfg.GitHubClientSecret != "github-client-secret" {
		t.Errorf("GitHubClientSecret = %v, want github-client-secret", cfg.GitHubClientSecret)
	}
	if cfg.GitHubRedirectURI != "http://localhost:8080/callback/github" {
		t.Errorf("GitHubRedirectURI = %v, want http://localhost:8080/callback/github", cfg.GitHubRedirectURI)
	}
}

// TestGetEnv_WithValue tests getEnv when environment variable is set
func TestGetEnv_WithValue(t *testing.T) {
	// Arrange
	key := "TEST_ENV_VAR"
	expectedValue := "test-value"
	defaultValue := "default-value"
	os.Setenv(key, expectedValue)
	defer os.Unsetenv(key)

	// Act
	result := getEnv(key, defaultValue)

	// Assert
	if result != expectedValue {
		t.Errorf("getEnv() = %v, want %v", result, expectedValue)
	}
}

// TestGetEnv_WithoutValue tests getEnv when environment variable is not set
func TestGetEnv_WithoutValue(t *testing.T) {
	// Arrange
	key := "NON_EXISTENT_ENV_VAR"
	defaultValue := "default-value"
	os.Unsetenv(key) // Ensure it's not set

	// Act
	result := getEnv(key, defaultValue)

	// Assert
	if result != defaultValue {
		t.Errorf("getEnv() = %v, want %v", result, defaultValue)
	}
}

// TestGetEnv_EmptyValue tests getEnv when environment variable is set to empty string
func TestGetEnv_EmptyValue(t *testing.T) {
	// Arrange
	key := "EMPTY_ENV_VAR"
	defaultValue := "default-value"
	os.Setenv(key, "")
	defer os.Unsetenv(key)

	// Act
	result := getEnv(key, defaultValue)

	// Assert
	// When env var is set to empty string, it should return default
	if result != defaultValue {
		t.Errorf("getEnv() = %v, want %v (default for empty env var)", result, defaultValue)
	}
}

// TestLoadConfig_JWTSettings tests JWT-related configuration
func TestLoadConfig_JWTSettings(t *testing.T) {
	// Arrange
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/testdb")
	os.Setenv("JWT_SECRET_KEY", "test-jwt-secret")
	os.Setenv("JWT_ISSUER", "http://test.example.com")

	defer func() {
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("JWT_SECRET_KEY")
		os.Unsetenv("JWT_ISSUER")
	}()

	// Act
	cfg, err := LoadConfig()

	// Assert
	if err != nil {
		t.Errorf("LoadConfig() returned error: %v", err)
	}
	if cfg.JWTSecretKey != "test-jwt-secret" {
		t.Errorf("JWTSecretKey = %v, want test-jwt-secret", cfg.JWTSecretKey)
	}
	if cfg.JWTIssuer != "http://test.example.com" {
		t.Errorf("JWTIssuer = %v, want http://test.example.com", cfg.JWTIssuer)
	}
	if cfg.AccessTokenExpiry != 3600 {
		t.Errorf("AccessTokenExpiry = %v, want 3600", cfg.AccessTokenExpiry)
	}
	if cfg.RefreshTokenExpiry != 2592000 {
		t.Errorf("RefreshTokenExpiry = %v, want 2592000", cfg.RefreshTokenExpiry)
	}
}
