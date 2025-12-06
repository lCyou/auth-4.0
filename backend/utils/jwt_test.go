package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestInitializeKeys tests RSA key pair generation
func TestInitializeKeys(t *testing.T) {
	// Arrange
	// (no setup needed)

	// Act
	err := InitializeKeys()

	// Assert
	if err != nil {
		t.Errorf("InitializeKeys() returned error: %v", err)
	}
	if privateKey == nil {
		t.Error("InitializeKeys() failed to initialize private key")
	}
	if publicKey == nil {
		t.Error("InitializeKeys() failed to initialize public key")
	}
}

// TestGetPublicKey tests retrieving the public key
func TestGetPublicKey(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	key := GetPublicKey()

	// Assert
	if key == nil {
		t.Error("GetPublicKey() returned nil")
	}
	if key != publicKey {
		t.Error("GetPublicKey() returned different key than publicKey")
	}
}

// TestGenerateAccessToken tests access token generation
func TestGenerateAccessToken(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	scope := "openid profile email"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	// Act
	token, err := GenerateAccessToken(sub, name, email, picture, scope, clientID, issuer, emailVerified, expirySeconds)

	// Assert
	if err != nil {
		t.Errorf("GenerateAccessToken() returned error: %v", err)
	}
	if token == "" {
		t.Error("GenerateAccessToken() returned empty token")
	}
	// Verify token has JWT format (three parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("GenerateAccessToken() returned invalid JWT format, got %d parts, want 3", len(parts))
	}
}

// TestGenerateAccessToken_VerifyClaims tests that access token contains correct claims
func TestGenerateAccessToken_VerifyClaims(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	scope := "openid profile email"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	// Act
	tokenString, err := GenerateAccessToken(sub, name, email, picture, scope, clientID, issuer, emailVerified, expirySeconds)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Assert - Parse and verify claims
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("Failed to parse token: %v", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.Sub != sub {
			t.Errorf("Sub = %v, want %v", claims.Sub, sub)
		}
		if claims.Name != name {
			t.Errorf("Name = %v, want %v", claims.Name, name)
		}
		if claims.Email != email {
			t.Errorf("Email = %v, want %v", claims.Email, email)
		}
		if claims.Picture != picture {
			t.Errorf("Picture = %v, want %v", claims.Picture, picture)
		}
		if claims.Scope != scope {
			t.Errorf("Scope = %v, want %v", claims.Scope, scope)
		}
		if claims.ClientID != clientID {
			t.Errorf("ClientID = %v, want %v", claims.ClientID, clientID)
		}
		if claims.EmailVerified != emailVerified {
			t.Errorf("EmailVerified = %v, want %v", claims.EmailVerified, emailVerified)
		}
		if claims.Issuer != issuer {
			t.Errorf("Issuer = %v, want %v", claims.Issuer, issuer)
		}
	} else {
		t.Error("Failed to extract claims from token")
	}
}

// TestGenerateIDToken tests ID token generation
func TestGenerateIDToken(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	nonce := "random-nonce"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	// Act
	token, err := GenerateIDToken(sub, name, email, picture, nonce, clientID, issuer, emailVerified, expirySeconds)

	// Assert
	if err != nil {
		t.Errorf("GenerateIDToken() returned error: %v", err)
	}
	if token == "" {
		t.Error("GenerateIDToken() returned empty token")
	}
	// Verify token has JWT format (three parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("GenerateIDToken() returned invalid JWT format, got %d parts, want 3", len(parts))
	}
}

// TestGenerateIDToken_WithNonce tests ID token generation with nonce
func TestGenerateIDToken_WithNonce(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	nonce := "random-nonce-value"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	// Act
	tokenString, err := GenerateIDToken(sub, name, email, picture, nonce, clientID, issuer, emailVerified, expirySeconds)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Assert - Parse and verify nonce claim
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("Failed to parse token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if nonceValue, exists := claims["nonce"]; !exists {
			t.Error("Nonce claim not found in token")
		} else if nonceValue != nonce {
			t.Errorf("Nonce = %v, want %v", nonceValue, nonce)
		}
	} else {
		t.Error("Failed to extract claims from token")
	}
}

// TestGenerateIDToken_WithoutNonce tests ID token generation without nonce
func TestGenerateIDToken_WithoutNonce(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	nonce := "" // Empty nonce
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	// Act
	tokenString, err := GenerateIDToken(sub, name, email, picture, nonce, clientID, issuer, emailVerified, expirySeconds)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Assert
	if tokenString == "" {
		t.Error("GenerateIDToken() returned empty token")
	}
	
	// Verify token can be parsed
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("Failed to parse token: %v", err)
	}
	if !token.Valid {
		t.Error("Generated token is invalid")
	}
}

// TestValidateToken tests token validation
func TestValidateToken(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	scope := "openid profile email"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := 3600

	tokenString, err := GenerateAccessToken(sub, name, email, picture, scope, clientID, issuer, emailVerified, expirySeconds)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	claims, err := ValidateToken(tokenString)

	// Assert
	if err != nil {
		t.Errorf("ValidateToken() returned error: %v", err)
	}
	if claims == nil {
		t.Error("ValidateToken() returned nil claims")
	}
	if claims.Sub != sub {
		t.Errorf("Claims.Sub = %v, want %v", claims.Sub, sub)
	}
}

// TestValidateToken_InvalidToken tests validation with invalid token
func TestValidateToken_InvalidToken(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	invalidToken := "invalid.token.string"

	// Act
	claims, err := ValidateToken(invalidToken)

	// Assert
	if err == nil {
		t.Error("ValidateToken() expected error for invalid token, got nil")
	}
	if claims != nil {
		t.Errorf("ValidateToken() returned claims = %v, want nil", claims)
	}
}

// TestValidateToken_ExpiredToken tests validation with expired token
func TestValidateToken_ExpiredToken(t *testing.T) {
	// Arrange
	err := InitializeKeys()
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}
	
	sub := "user123"
	name := "Test User"
	email := "test@example.com"
	picture := "https://example.com/pic.jpg"
	scope := "openid profile email"
	clientID := "client123"
	issuer := "https://example.com"
	emailVerified := true
	expirySeconds := -1 // Expired token (negative expiry)

	tokenString, err := GenerateAccessToken(sub, name, email, picture, scope, clientID, issuer, emailVerified, expirySeconds)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Wait a moment to ensure token is expired
	time.Sleep(100 * time.Millisecond)

	// Act
	claims, err := ValidateToken(tokenString)

	// Assert
	if err == nil {
		t.Error("ValidateToken() expected error for expired token, got nil")
	}
	if claims != nil {
		t.Errorf("ValidateToken() returned claims = %v, want nil for expired token", claims)
	}
}

// TestGenerateRandomString tests random string generation
func TestGenerateRandomString(t *testing.T) {
	// Arrange
	length := 32

	// Act
	str, err := GenerateRandomString(length)

	// Assert
	if err != nil {
		t.Errorf("GenerateRandomString() returned error: %v", err)
	}
	if len(str) != length {
		t.Errorf("GenerateRandomString() returned string of length %d, want %d", len(str), length)
	}
}

// TestGenerateRandomString_Uniqueness tests that random strings are unique
func TestGenerateRandomString_Uniqueness(t *testing.T) {
	// Arrange
	length := 32

	// Act
	str1, err1 := GenerateRandomString(length)
	str2, err2 := GenerateRandomString(length)

	// Assert
	if err1 != nil || err2 != nil {
		t.Errorf("GenerateRandomString() returned errors: %v, %v", err1, err2)
	}
	if str1 == str2 {
		t.Error("GenerateRandomString() produced identical strings")
	}
}

// TestGenerateRandomString_DifferentLengths tests generation with different lengths
func TestGenerateRandomString_DifferentLengths(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{"short", 8},
		{"medium", 32},
		{"long", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			length := tc.length

			// Act
			str, err := GenerateRandomString(length)

			// Assert
			if err != nil {
				t.Errorf("GenerateRandomString(%d) returned error: %v", length, err)
			}
			if len(str) != length {
				t.Errorf("GenerateRandomString(%d) returned string of length %d, want %d", length, len(str), length)
			}
		})
	}
}
