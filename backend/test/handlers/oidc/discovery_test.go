package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/config"
	"openid-aas/backend/handlers/oidc"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newDiscoveryCfg() *config.Config {
	return &config.Config{
		ServerHost: "https://test.example.com",
		JWTIssuer:  "https://test.example.com",
	}
}

// TestDiscovery_RequiredFields は OpenID Connect Discovery ドキュメントに
// 必須フィールドが全て含まれることを検証する。
//
// Ref: OpenID Connect Discovery 1.0 §3
//
//	https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func TestDiscovery_RequiredFields(t *testing.T) {
	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	require.Equal(t, http.StatusOK, w.Code)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	// OpenID Connect Discovery 1.0 §3 で REQUIRED なフィールド
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, field := range requiredFields {
		assert.Contains(t, doc, field, "required field %q missing", field)
	}
}

// TestDiscovery_IssuerMatchesConfig は issuer が JWTIssuer と一致することを検証する。
//
// Ref: OpenID Connect Discovery 1.0 §3
//
//	"The iss value returned MUST be identical to the Issuer URL that was
//	 directly used to retrieve the configuration information."
//	https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func TestDiscovery_IssuerMatchesConfig(t *testing.T) {
	issuer := "https://auth.example.com"
	cfg := &config.Config{JWTIssuer: issuer, ServerHost: issuer}
	handler := oidc.NewDiscoveryHandler(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, issuer, doc["issuer"])
}

// TestDiscovery_EndpointURLs はエンドポイント URL が issuer を基底として構成されることを検証する。
//
// Ref: OpenID Connect Discovery 1.0 §3
//
//	https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func TestDiscovery_EndpointURLs(t *testing.T) {
	issuer := "https://test.example.com"
	cfg := &config.Config{JWTIssuer: issuer, ServerHost: issuer}
	handler := oidc.NewDiscoveryHandler(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	assert.Equal(t, issuer+"/oauth/authorize", doc["authorization_endpoint"])
	assert.Equal(t, issuer+"/oauth/token", doc["token_endpoint"])
	assert.Equal(t, issuer+"/oauth/userinfo", doc["userinfo_endpoint"])
	assert.Equal(t, issuer+"/oauth/jwks", doc["jwks_uri"])
}

// TestDiscovery_SupportedAlgorithms は署名アルゴリズムに RS256 が含まれることを検証する。
//
// Ref: OpenID Connect Core 1.0 §10.1
//
//	"Servers MUST support RS256."
//	https://openid.net/specs/openid-connect-core-1_0.html#SigEnc
func TestDiscovery_SupportedAlgorithms(t *testing.T) {
	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	algs, ok := doc["id_token_signing_alg_values_supported"].([]interface{})
	require.True(t, ok)
	var algStrs []string
	for _, a := range algs {
		algStrs = append(algStrs, a.(string))
	}
	assert.Contains(t, algStrs, "RS256")
}

// TestDiscovery_PKCEMethods は PKCE の S256 メソッドがサポートされていることを検証する。
//
// Ref: RFC 7636 §4.2
//
//	"If the client is capable of using "S256", it MUST use "S256"."
//	https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func TestDiscovery_PKCEMethods(t *testing.T) {
	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	methods, ok := doc["code_challenge_methods_supported"].([]interface{})
	require.True(t, ok, "code_challenge_methods_supported must be present")
	var methodStrs []string
	for _, m := range methods {
		methodStrs = append(methodStrs, m.(string))
	}
	assert.Contains(t, methodStrs, "S256", "S256 must be supported per RFC 7636")
}

// TestDiscovery_GrantTypes は authorization_code と refresh_token がサポートされることを検証する。
//
// Ref: RFC 6749 §4.1 (Authorization Code Grant)
//
//	https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
//
// Ref: RFC 6749 §6 (Refreshing an Access Token)
//
//	https://datatracker.ietf.org/doc/html/rfc6749#section-6
func TestDiscovery_GrantTypes(t *testing.T) {
	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))

	grantTypes, ok := doc["grant_types_supported"].([]interface{})
	require.True(t, ok)
	var grantStrs []string
	for _, g := range grantTypes {
		grantStrs = append(grantStrs, g.(string))
	}
	assert.Contains(t, grantStrs, "authorization_code")
	assert.Contains(t, grantStrs, "refresh_token")
}

// TestDiscovery_ContentType は Content-Type が application/json であることを検証する。
//
// Ref: OpenID Connect Discovery 1.0 §4
//
//	https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
func TestDiscovery_ContentType(t *testing.T) {
	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	handler.HandleWellKnown(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

// TestJWKS_RequiredFields は JWKS レスポンスに必須フィールドが含まれることを検証する。
//
// Ref: RFC 7517 §4 (JSON Web Key Parameters)
//
//	"kty" は REQUIRED。RSA 鍵には "n" と "e" も必須。
//	https://datatracker.ietf.org/doc/html/rfc7517#section-4
func TestJWKS_RequiredFields(t *testing.T) {
	require.NoError(t, utils.InitializeKeys())

	handler := oidc.NewDiscoveryHandler(newDiscoveryCfg())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/jwks", nil)
	handler.HandleJWKS(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	keys, ok := resp["keys"].([]interface{})
	require.True(t, ok, "keys array must be present")
	require.NotEmpty(t, keys)

	key := keys[0].(map[string]interface{})
	// RFC 7517 §4.1: kty は REQUIRED
	assert.Equal(t, "RSA", key["kty"])
	// RFC 7517 §6.3: RSA 公開鍵パラメータ
	assert.NotEmpty(t, key["n"], "RSA modulus (n) must be present")
	assert.NotEmpty(t, key["e"], "RSA exponent (e) must be present")
	// RFC 7517 §4.2: use (公開鍵の用途)
	assert.Equal(t, "sig", key["use"])
}
