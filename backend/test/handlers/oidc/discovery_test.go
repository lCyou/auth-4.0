package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/config"
	"openid-aas/backend/handlers/oidc"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestDiscoveryHandler_Success tests OIDC discovery endpoint
func TestDiscoveryHandler_Success(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		ServerHost:  "https://test.example.com",
		JWTIssuer:   "https://test.example.com",
	}

	handler := oidc.NewDiscoveryHandler(cfg)
	
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)

	// Act
	handler.HandleWellKnown(c)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "issuer")
	assert.Contains(t, w.Body.String(), "authorization_endpoint")
	assert.Contains(t, w.Body.String(), "token_endpoint")
	assert.Contains(t, w.Body.String(), "userinfo_endpoint")
	assert.Contains(t, w.Body.String(), "jwks_uri")
}

// TestDiscoveryHandler_ResponseFormat tests discovery response format
func TestDiscoveryHandler_ResponseFormat(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		ServerHost:  "https://test.example.com",
		JWTIssuer:   "https://test.example.com",
	}

	handler := oidc.NewDiscoveryHandler(cfg)
	
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)

	// Act
	handler.HandleWellKnown(c)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
}

// TestJWKSHandler_Success tests JWKS endpoint
func TestJWKSHandler_Success(t *testing.T) {
	// Arrange
	// Initialize keys before testing JWKS
	err := utils.InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to initialize keys: %v", err)
	}

	cfg := &config.Config{
		ServerHost: "https://test.example.com",
	}

	handler := oidc.NewDiscoveryHandler(cfg)
	
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/jwks", nil)

	// Act
	handler.HandleJWKS(c)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "keys")
}

// TestJWKSHandler_ResponseFormat tests JWKS response format
func TestJWKSHandler_ResponseFormat(t *testing.T) {
	// Arrange
	// Initialize keys before testing JWKS
	err := utils.InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to initialize keys: %v", err)
	}

	cfg := &config.Config{
		ServerHost: "https://test.example.com",
	}

	handler := oidc.NewDiscoveryHandler(cfg)
	
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/jwks", nil)

	// Act
	handler.HandleJWKS(c)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
}
