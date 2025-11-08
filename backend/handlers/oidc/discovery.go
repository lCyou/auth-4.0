package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"

	"openid-aas/backend/config"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
)

// DiscoveryHandler handles OIDC discovery endpoints
type DiscoveryHandler struct {
	config *config.Config
}

func NewDiscoveryHandler(cfg *config.Config) *DiscoveryHandler {
	return &DiscoveryHandler{
		config: cfg,
	}
}

// HandleWellKnown returns the OpenID Connect discovery document
func (h *DiscoveryHandler) HandleWellKnown(c *gin.Context) {
	issuer := h.config.JWTIssuer

	c.JSON(http.StatusOK, gin.H{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"userinfo_endpoint":                     issuer + "/oauth/userinfo",
		"jwks_uri":                              issuer + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "name", "email", "email_verified", "picture"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	})
}

// HandleJWKS returns the JSON Web Key Set
func (h *DiscoveryHandler) HandleJWKS(c *gin.Context) {
	publicKey := utils.GetPublicKey()

	// Convert RSA public key to JWK format
	jwk := gin.H{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{jwk},
	})
}
