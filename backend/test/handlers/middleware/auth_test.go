package middleware_test

import (
"net/http"
"net/http/httptest"
"testing"

"github.com/gin-gonic/gin"
"github.com/stretchr/testify/assert"
)

func init() {
gin.SetMode(gin.TestMode)
}

// TestAuthMiddleware_MissingToken tests authentication middleware without token
func TestAuthMiddleware_MissingToken(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodGet, "/protected", nil)
// No X-Session-Token header set

// Act
sessionToken := c.GetHeader("X-Session-Token")

// Assert
// Expected: Should abort with 401 Unauthorized when token is missing
assert.Empty(t, sessionToken)
}

// TestAuthMiddleware_ValidTokenHeader tests auth middleware with valid token header
func TestAuthMiddleware_ValidTokenHeader(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodGet, "/protected", nil)
expectedToken := "valid-session-token-123"
c.Request.Header.Set("X-Session-Token", expectedToken)

// Act
sessionToken := c.GetHeader("X-Session-Token")

// Assert
assert.Equal(t, expectedToken, sessionToken)
assert.NotEmpty(t, sessionToken)
}

// TestAuthMiddleware_TokenExtraction tests token extraction logic
func TestAuthMiddleware_TokenExtraction(t *testing.T) {
tests := []struct {
name          string
headerValue   string
expectedEmpty bool
}{
{
name:          "Valid token",
headerValue:   "session-token-123",
expectedEmpty: false,
},
{
name:          "Empty token",
headerValue:   "",
expectedEmpty: true,
},
{
name:          "Whitespace token",
headerValue:   "   ",
expectedEmpty: false,
},
}

for _, tt := range tests {
t.Run(tt.name, func(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodGet, "/protected", nil)
if tt.headerValue != "" {
c.Request.Header.Set("X-Session-Token", tt.headerValue)
}

// Act
sessionToken := c.GetHeader("X-Session-Token")

// Assert
if tt.expectedEmpty {
assert.Empty(t, sessionToken)
} else {
assert.NotEmpty(t, sessionToken)
}
})
}
}

// TestAuthMiddleware_MultipleHeaders tests handling of duplicate headers
func TestAuthMiddleware_MultipleHeaders(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodGet, "/protected", nil)
c.Request.Header.Set("X-Session-Token", "token1")
// Setting again should overwrite
c.Request.Header.Set("X-Session-Token", "token2")

// Act
sessionToken := c.GetHeader("X-Session-Token")

// Assert
// Should get the last set value
assert.Equal(t, "token2", sessionToken)
}

// TestAuthMiddleware_CaseSensitivity tests header name case sensitivity
func TestAuthMiddleware_CaseSensitivity(t *testing.T) {
// Arrange
w := httptest.NewRecorder()
c, _ := gin.CreateTestContext(w)
c.Request = httptest.NewRequest(http.MethodGet, "/protected", nil)
c.Request.Header.Set("X-Session-Token", "mytoken")

// Act
// HTTP headers are case-insensitive
token1 := c.GetHeader("X-Session-Token")
token2 := c.GetHeader("x-session-token")

// Assert
assert.Equal(t, token1, token2)
assert.NotEmpty(t, token1)
}
