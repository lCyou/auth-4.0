package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// InitializeKeys generates RSA key pair for JWT signing
func InitializeKeys() error {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	publicKey = &privateKey.PublicKey
	return nil
}

// GetPublicKey returns the public key
func GetPublicKey() *rsa.PublicKey {
	return publicKey
}

// Claims represents JWT claims
type Claims struct {
	Sub           string   `json:"sub"`
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a new JWT access token
func GenerateAccessToken(sub, name, email, picture, scope, clientID, issuer string, emailVerified bool, expirySeconds int) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:           sub,
		Name:          name,
		Email:         email,
		EmailVerified: emailVerified,
		Picture:       picture,
		Scope:         scope,
		ClientID:      clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expirySeconds) * time.Second)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// GenerateIDToken creates a new JWT ID token for OpenID Connect
func GenerateIDToken(sub, name, email, picture, nonce, clientID, issuer string, emailVerified bool, expirySeconds int) (string, error) {
	now := time.Now()
	claims := Claims{
		Sub:           sub,
		Name:          name,
		Email:         email,
		EmailVerified: emailVerified,
		Picture:       picture,
		ClientID:      clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expirySeconds) * time.Second)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	// Add nonce if provided
	if nonce != "" {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":            claims.Sub,
			"name":           claims.Name,
			"email":          claims.Email,
			"email_verified": claims.EmailVerified,
			"picture":        claims.Picture,
			"nonce":          nonce,
			"aud":            claims.Audience,
			"iss":            claims.Issuer,
			"iat":            claims.IssuedAt.Unix(),
			"exp":            claims.ExpiresAt.Unix(),
			"nbf":            claims.NotBefore.Unix(),
			"jti":            claims.ID,
		})
		return token.SignedString(privateKey)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// ValidateToken validates a JWT token and returns the claims
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
