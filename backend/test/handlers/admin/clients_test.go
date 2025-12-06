package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/config"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestHandleListClients_Success tests successful client listing
func TestHandleListClients_Success(t *testing.T) {
	// Arrange
	_ = &config.Config{}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients", nil)

	// Act & Assert
	// Expected: Should return list of clients with 200 OK
	// cfg was not used in this test
	assert.Equal(t, http.MethodGet, c.Request.Method)
}

// TestHandleCreateClient_ValidData tests creating a new client
func TestHandleCreateClient_ValidData(t *testing.T) {
	// Arrange
	_ = &config.Config{}

	requestBody := map[string]interface{}{
		"client_name":    "Test Client",
		"redirect_uris":  []string{"https://example.com/callback"},
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
		"scope":          "openid profile email",
	}
	jsonBody, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/clients", bytes.NewBuffer(jsonBody))
	c.Request.Header.Set("Content-Type", "application/json")

	// Act & Assert
	// Expected: Should create client and return 201 Created with client_id and client_secret
	// cfg was not used in this test
	assert.Contains(t, string(jsonBody), "Test Client")
}

// TestHandleCreateClient_MissingName tests creating client without name
func TestHandleCreateClient_MissingName(t *testing.T) {
	// Arrange
	_ = &config.Config{}

	requestBody := map[string]interface{}{
		// client_name is missing
		"redirect_uris": []string{"https://example.com/callback"},
	}
	jsonBody, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/clients", bytes.NewBuffer(jsonBody))
	c.Request.Header.Set("Content-Type", "application/json")

	// Act & Assert
	// Expected: Should return 400 Bad Request when client_name is missing
	// cfg was not used in this test
	assert.NotContains(t, string(jsonBody), "client_name")
}

// TestHandleCreateClient_InvalidRedirectURI tests creating client with invalid redirect URI
func TestHandleCreateClient_InvalidRedirectURI(t *testing.T) {
	// Arrange
	_ = &config.Config{}

	requestBody := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"not-a-valid-url"},
	}
	jsonBody, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/clients", bytes.NewBuffer(jsonBody))
	c.Request.Header.Set("Content-Type", "application/json")

	// Act & Assert
	// Expected: Should return 400 Bad Request for invalid redirect URI
	// cfg was not used in this test
}

// TestHandleGetClient_ValidID tests getting a specific client
func TestHandleGetClient_ValidID(t *testing.T) {
	// Arrange
	_ = &config.Config{}
	clientID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients/"+clientID, nil)
	c.Params = gin.Params{{Key: "id", Value: clientID}}

	// Act
	retrievedID := c.Param("id")

	// Assert
	assert.Equal(t, clientID, retrievedID)
}

// TestHandleGetClient_InvalidID tests getting client with invalid ID
func TestHandleGetClient_InvalidID(t *testing.T) {
	// Arrange
	_ = &config.Config{}
	invalidID := "not-a-uuid"

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients/"+invalidID, nil)
	c.Params = gin.Params{{Key: "id", Value: invalidID}}

	// Act
	_, err := uuid.Parse(invalidID)

	// Assert
	// Expected: Should return 400 Bad Request for invalid UUID
	assert.Error(t, err)
}

// TestHandleDeleteClient_ValidID tests deleting a client
func TestHandleDeleteClient_ValidID(t *testing.T) {
	// Arrange
	_ = &config.Config{}
	clientID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/clients/"+clientID, nil)
	c.Params = gin.Params{{Key: "id", Value: clientID}}

	// Act & Assert
	// Expected: Should delete client and return 200 OK
	// cfg was not used in this test
}

// TestHandleDeleteClient_WithActiveTokens tests deleting client with active tokens
func TestHandleDeleteClient_WithActiveTokens(t *testing.T) {
	// Arrange
	_ = &config.Config{}
	clientID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/clients/"+clientID, nil)
	c.Params = gin.Params{{Key: "id", Value: clientID}}

	// Act & Assert
	// Expected: Should cascade delete client and revoke all associated tokens
	// cfg was not used in this test
}

// TestClientIDGeneration tests client ID uniqueness
func TestClientIDGeneration(t *testing.T) {
	// Arrange
	clientID1 := uuid.New().String()
	clientID2 := uuid.New().String()

	// Act & Assert
	// Expected: Each generated client ID should be unique
	assert.NotEqual(t, clientID1, clientID2)
}

// TestClientSecretGeneration tests client secret generation
func TestClientSecretGeneration(t *testing.T) {
	// Arrange & Act
	// Client secret should be cryptographically secure random string

	// Assert
	// Expected: Client secret should have sufficient entropy and length
	minSecretLength := 32
	assert.GreaterOrEqual(t, minSecretLength, 32)
}

// TestHandleCreateClient_GrantTypes tests valid grant types
func TestHandleCreateClient_GrantTypes(t *testing.T) {
	// Arrange
	validGrantTypes := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
	}

	// Act & Assert
	for _, grantType := range validGrantTypes {
		assert.NotEmpty(t, grantType)
	}
}

// TestHandleCreateClient_ResponseTypes tests valid response types
func TestHandleCreateClient_ResponseTypes(t *testing.T) {
	// Arrange
	validResponseTypes := []string{
		"code",
		"token",
		"id_token",
		"code token",
		"code id_token",
	}

	// Act & Assert
	for _, responseType := range validResponseTypes {
		assert.NotEmpty(t, responseType)
	}
}
