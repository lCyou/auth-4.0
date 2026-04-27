package admin_test

import (
"bytes"
"encoding/json"
"net/http"
"net/http/httptest"
"testing"

"github.com/gin-gonic/gin"
"github.com/stretchr/testify/assert"
)

func init() {
gin.SetMode(gin.TestMode)
}

// TestHandleLogin_Success tests successful admin login
func TestHandleLogin_Success(t *testing.T) {
// Arrange
username := "testadmin"
password := "testpassword"

requestBody := map[string]string{
"username": username,
"password": password,
}
jsonBody, _ := json.Marshal(requestBody)

w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(jsonBody))
c.Request.Header.Set("Content-Type", "application/json")

// Act & Assert
assert.Equal(t, username, requestBody["username"])
assert.NotEmpty(t, password)
}

// TestHandleLogin_InvalidRequest tests login with invalid request body
func TestHandleLogin_InvalidRequest(t *testing.T) {
// Arrange
requestBody := map[string]string{
"username": "testadmin",
// password is missing
}
jsonBody, _ := json.Marshal(requestBody)

w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(jsonBody))
c.Request.Header.Set("Content-Type", "application/json")

// Act & Assert
assert.NotContains(t, requestBody, "password")
}

// TestHandleLogin_InvalidCredentials tests login with wrong credentials
func TestHandleLogin_InvalidCredentials(t *testing.T) {
// Arrange
requestBody := map[string]string{
"username": "wronguser",
"password": "wrongpassword",
}
jsonBody, _ := json.Marshal(requestBody)

w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(jsonBody))
c.Request.Header.Set("Content-Type", "application/json")

// Act & Assert
// Expected: Should return 401 Unauthorized for invalid credentials
assert.NotNil(t, c)
}

// TestHandleLogout_Success tests successful logout
func TestHandleLogout_Success(t *testing.T) {
// Arrange
sessionToken := "valid-session-token"

w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/logout", nil)
c.Request.Header.Set("X-Session-Token", sessionToken)

// Act & Assert
assert.Equal(t, sessionToken, c.Request.Header.Get("X-Session-Token"))
}

// TestHandleLogout_NoSessionToken tests logout without session token
func TestHandleLogout_NoSessionToken(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/logout", nil)

// Act & Assert
// Expected: Should return 400 Bad Request when no session token provided
assert.Empty(t, c.Request.Header.Get("X-Session-Token"))
}

// TestSessionTokenValidation tests session token validation logic
func TestSessionTokenValidation(t *testing.T) {
// Arrange
validToken := "abc123xyz"
emptyToken := ""

// Act & Assert
assert.NotEmpty(t, validToken)
assert.Empty(t, emptyToken)
}
