package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestHashPassword tests the password hashing functionality
func TestHashPassword(t *testing.T) {
	// Arrange
	password := "testPassword123"

	// Act
	hash, err := HashPassword(password)

	// Assert
	if err != nil {
		t.Errorf("HashPassword() returned error: %v", err)
	}
	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}
	if hash == password {
		t.Error("HashPassword() returned unhashed password")
	}
}

// TestHashPassword_DifferentPasswords tests that different passwords produce different hashes
func TestHashPassword_DifferentPasswords(t *testing.T) {
	// Arrange
	password1 := "password1"
	password2 := "password2"

	// Act
	hash1, err1 := HashPassword(password1)
	hash2, err2 := HashPassword(password2)

	// Assert
	if err1 != nil || err2 != nil {
		t.Errorf("HashPassword() returned errors: %v, %v", err1, err2)
	}
	if hash1 == hash2 {
		t.Error("HashPassword() produced same hash for different passwords")
	}
}

// TestCheckPasswordHash_ValidPassword tests password verification with correct password
func TestCheckPasswordHash_ValidPassword(t *testing.T) {
	// Arrange
	password := "correctPassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	result := CheckPasswordHash(password, hash)

	// Assert
	if !result {
		t.Error("CheckPasswordHash() returned false for valid password")
	}
}

// TestCheckPasswordHash_InvalidPassword tests password verification with incorrect password
func TestCheckPasswordHash_InvalidPassword(t *testing.T) {
	// Arrange
	password := "correctPassword"
	wrongPassword := "wrongPassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	result := CheckPasswordHash(wrongPassword, hash)

	// Assert
	if result {
		t.Error("CheckPasswordHash() returned true for invalid password")
	}
}

// TestGenerateJWT tests JWT token generation
func TestGenerateJWT(t *testing.T) {
	// Arrange
	userID := "test-user-id"
	secretKey := "test-secret-key"

	// Act
	token, err := GenerateJWT(userID, secretKey)

	// Assert
	if err != nil {
		t.Errorf("GenerateJWT() returned error: %v", err)
	}
	if token == "" {
		t.Error("GenerateJWT() returned empty token")
	}
}

// TestGenerateJWT_DifferentUsers tests that different users get different tokens
func TestGenerateJWT_DifferentUsers(t *testing.T) {
	// Arrange
	userID1 := "user1"
	userID2 := "user2"
	secretKey := "test-secret-key"

	// Act
	token1, err1 := GenerateJWT(userID1, secretKey)
	token2, err2 := GenerateJWT(userID2, secretKey)

	// Assert
	if err1 != nil || err2 != nil {
		t.Errorf("GenerateJWT() returned errors: %v, %v", err1, err2)
	}
	if token1 == token2 {
		t.Error("GenerateJWT() produced same token for different users")
	}
}

// TestValidateJWT_ValidToken tests JWT token validation with valid token
func TestValidateJWT_ValidToken(t *testing.T) {
	// Arrange
	userID := "test-user-id"
	secretKey := "test-secret-key"
	token, err := GenerateJWT(userID, secretKey)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	validatedUserID, err := ValidateJWT(token, secretKey)

	// Assert
	if err != nil {
		t.Errorf("ValidateJWT() returned error: %v", err)
	}
	if validatedUserID != userID {
		t.Errorf("ValidateJWT() returned userID = %v, want %v", validatedUserID, userID)
	}
}

// TestValidateJWT_InvalidToken tests JWT token validation with invalid token
func TestValidateJWT_InvalidToken(t *testing.T) {
	// Arrange
	secretKey := "test-secret-key"
	invalidToken := "invalid.token.string"

	// Act
	userID, err := ValidateJWT(invalidToken, secretKey)

	// Assert
	if err == nil {
		t.Error("ValidateJWT() expected error for invalid token, got nil")
	}
	if userID != "" {
		t.Errorf("ValidateJWT() returned userID = %v, want empty string", userID)
	}
}

// TestValidateJWT_WrongSecret tests JWT token validation with wrong secret
func TestValidateJWT_WrongSecret(t *testing.T) {
	// Arrange
	userID := "test-user-id"
	secretKey := "test-secret-key"
	wrongSecretKey := "wrong-secret-key"
	token, err := GenerateJWT(userID, secretKey)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	validatedUserID, err := ValidateJWT(token, wrongSecretKey)

	// Assert
	if err == nil {
		t.Error("ValidateJWT() expected error for wrong secret, got nil")
	}
	if validatedUserID != "" {
		t.Errorf("ValidateJWT() returned userID = %v, want empty string", validatedUserID)
	}
}

// TestValidateJWT_TokenClaims tests that JWT token contains correct claims
func TestValidateJWT_TokenClaims(t *testing.T) {
	// Arrange
	userID := "test-user-id"
	secretKey := "test-secret-key"
	tokenString, err := GenerateJWT(userID, secretKey)
	if err != nil {
		t.Fatalf("Failed to setup test: %v", err)
	}

	// Act
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	// Assert
	if err != nil {
		t.Errorf("Token parsing failed: %v", err)
	}
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if sub, ok := claims["sub"].(string); !ok || sub != userID {
			t.Errorf("Token sub claim = %v, want %v", sub, userID)
		}
		if _, ok := claims["iat"]; !ok {
			t.Error("Token missing iat claim")
		}
		if _, ok := claims["exp"]; !ok {
			t.Error("Token missing exp claim")
		}
	} else {
		t.Error("Failed to extract claims from token")
	}
}
