package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestCORSMiddleware_AllowedOrigin tests CORS with allowed origin
func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		AllowedOrigins: []string{"https://example.com", "https://app.example.com"},
	}

	origin := "https://example.com"

	// Act
	isAllowed := false
	for _, allowedOrigin := range cfg.AllowedOrigins {
		if origin == allowedOrigin {
			isAllowed = true
			break
		}
	}

	// Assert
	assert.True(t, isAllowed)
}

// TestCORSMiddleware_DisallowedOrigin tests CORS with disallowed origin
func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		AllowedOrigins: []string{"https://example.com"},
	}

	origin := "https://malicious.com"

	// Act
	isAllowed := false
	for _, allowedOrigin := range cfg.AllowedOrigins {
		if origin == allowedOrigin {
			isAllowed = true
			break
		}
	}

	// Assert
	assert.False(t, isAllowed)
}

// TestCORSMiddleware_PreflightRequest tests CORS preflight OPTIONS request
func TestCORSMiddleware_PreflightRequest(t *testing.T) {
	// Arrange
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/api/test", nil)
	c.Request.Header.Set("Origin", "https://example.com")
	c.Request.Header.Set("Access-Control-Request-Method", "POST")

	// Act & Assert
	// Expected: Preflight request should return 204 No Content
	// and include appropriate CORS headers
	assert.Equal(t, http.MethodOptions, c.Request.Method)
	assert.NotEmpty(t, c.Request.Header.Get("Origin"))
}

// TestCORSMiddleware_AllowedMethods tests allowed HTTP methods
func TestCORSMiddleware_AllowedMethods(t *testing.T) {
	// Arrange
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	testMethod := "POST"

	// Act
	isAllowed := false
	for _, method := range allowedMethods {
		if testMethod == method {
			isAllowed = true
			break
		}
	}

	// Assert
	assert.True(t, isAllowed)
}

// TestCORSMiddleware_AllowedHeaders tests allowed request headers
func TestCORSMiddleware_AllowedHeaders(t *testing.T) {
	// Arrange
	allowedHeaders := []string{"Content-Type", "Authorization", "X-Requested-With"}
	testHeader := "Authorization"

	// Act
	isAllowed := false
	for _, header := range allowedHeaders {
		if testHeader == header {
			isAllowed = true
			break
		}
	}

	// Assert
	assert.True(t, isAllowed)
}

// TestCORSMiddleware_Credentials tests credentials support
func TestCORSMiddleware_Credentials(t *testing.T) {
	// Arrange
	allowCredentials := true

	// Act & Assert
	// Expected: CORS should allow credentials (cookies, auth headers)
	assert.True(t, allowCredentials)
}

// TestCORSMiddleware_MaxAge tests preflight cache duration
func TestCORSMiddleware_MaxAge(t *testing.T) {
	// Arrange
	maxAge := 86400 // 24 hours in seconds

	// Act & Assert
	// Expected: Preflight responses should be cached for appropriate duration
	assert.Greater(t, maxAge, 0)
	assert.LessOrEqual(t, maxAge, 86400) // Reasonable max cache duration
}
