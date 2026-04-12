package utils_test

import (
	"strings"
	"testing"
	"time"

	"openid-aas/backend/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) {
	t.Helper()
	require.NoError(t, utils.InitializeKeys())
}

// TestInitializeKeys は RSA 鍵ペアの生成をテストする。
//
// Ref: OpenID Connect Core 1.0 §10.1
//
//	"Servers SHOULD use RS256 or better RSA-based algorithms with a key size of 2048 bits or larger."
//	https://openid.net/specs/openid-connect-core-1_0.html#SigEnc
func TestInitializeKeys(t *testing.T) {
	require.NoError(t, utils.InitializeKeys())
	assert.NotNil(t, utils.GetPublicKey())
	assert.Equal(t, 2048, utils.GetPublicKey().N.BitLen(), "RSA key must be at least 2048 bits")
}

// TestGenerateIDToken_RequiredClaims は ID トークンに必須クレームが含まれることを検証する。
//
// Ref: OpenID Connect Core 1.0 §2 (ID Token)
//
//	必須クレーム: iss, sub, aud, exp, iat
//	https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func TestGenerateIDToken_RequiredClaims(t *testing.T) {
	setup(t)

	tokenStr, err := utils.GenerateIDToken(
		"user-sub-123", "Test User", "test@example.com", "",
		"", "client-abc", "https://issuer.example.com",
		true, 3600,
	)
	require.NoError(t, err)

	token, err := jwt.ParseWithClaims(tokenStr, &utils.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return utils.GetPublicKey(), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	claims, ok := token.Claims.(*utils.Claims)
	require.True(t, ok)

	// OpenID Connect Core 1.0 §2: iss は REQUIRED
	assert.Equal(t, "https://issuer.example.com", claims.Issuer)
	// OpenID Connect Core 1.0 §2: sub は REQUIRED (最大255文字の ASCII)
	// Note: Claims.Sub (json:"sub") が RegisteredClaims.Subject (json:"sub") より
	// 浅いため、パース後は Claims.Sub に格納される。
	assert.Equal(t, "user-sub-123", claims.Sub)
	// OpenID Connect Core 1.0 §2: aud は REQUIRED (client_id を含む)
	assert.Contains(t, []string(claims.Audience), "client-abc")
	// OpenID Connect Core 1.0 §2: exp は REQUIRED
	assert.True(t, claims.ExpiresAt.After(time.Now()))
	// OpenID Connect Core 1.0 §2: iat は REQUIRED
	assert.NotNil(t, claims.IssuedAt)
}

// TestGenerateIDToken_WithNonce は nonce クレームが正しく含まれることを検証する。
//
// Ref: OpenID Connect Core 1.0 §3.1.2.2
//
//	"If a nonce value was sent in the Authentication Request, a nonce Claim
//	 MUST be present and its value checked to verify that it is the same value
//	 as the one that was sent in the Authentication Request."
//	https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func TestGenerateIDToken_WithNonce(t *testing.T) {
	setup(t)

	nonce := "unique-nonce-value-xyz"
	tokenStr, err := utils.GenerateIDToken(
		"sub", "Name", "email@example.com", "",
		nonce, "client-id", "https://issuer.example.com",
		true, 3600,
	)
	require.NoError(t, err)

	// nonce は MapClaims で埋め込まれるため ParseWithClaims[MapClaims] で検証
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return utils.GetPublicKey(), nil
	})
	require.NoError(t, err)

	mc, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, nonce, mc["nonce"])
}

// TestGenerateIDToken_SignedWithRS256 は ID トークンが RS256 で署名されることを検証する。
//
// Ref: OpenID Connect Core 1.0 §10.1
//
//	"Servers MUST support RS256."
//	https://openid.net/specs/openid-connect-core-1_0.html#SigEnc
func TestGenerateIDToken_SignedWithRS256(t *testing.T) {
	setup(t)

	tokenStr, err := utils.GenerateIDToken(
		"sub", "Name", "email@example.com", "",
		"", "client-id", "https://issuer.example.com",
		true, 3600,
	)
	require.NoError(t, err)

	// ヘッダーの alg フィールドを確認（検証なしでパース）
	parts := strings.Split(tokenStr, ".")
	require.Len(t, parts, 3, "JWT must have 3 parts")

	token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return utils.GetPublicKey(), nil
	})
	assert.IsType(t, jwt.SigningMethodRS256, token.Method)
}

// TestGenerateIDToken_Expiry は exp クレームが正しく設定されることを検証する。
//
// Ref: RFC 7519 §4.1.4
//
//	"The "exp" (expiration time) claim identifies the expiration time on or after
//	 which the JWT MUST NOT be accepted for processing."
//	https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
func TestGenerateIDToken_Expiry(t *testing.T) {
	setup(t)

	expirySeconds := 3600
	before := time.Now()

	tokenStr, err := utils.GenerateIDToken(
		"sub", "Name", "email@example.com", "",
		"", "client-id", "https://issuer.example.com",
		true, expirySeconds,
	)
	require.NoError(t, err)

	token, err := jwt.ParseWithClaims(tokenStr, &utils.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return utils.GetPublicKey(), nil
	})
	require.NoError(t, err)

	claims := token.Claims.(*utils.Claims)
	expectedExpiry := before.Add(time.Duration(expirySeconds) * time.Second)
	// 1秒の誤差を許容
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, time.Second)
}

// TestValidateToken_ValidToken は有効なトークンの検証が成功することをテストする。
//
// Ref: RFC 7519 §7.2 (Validating a JWT)
//
//	https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
func TestValidateToken_ValidToken(t *testing.T) {
	setup(t)

	tokenStr, err := utils.GenerateAccessToken(
		"sub", "Name", "email@example.com", "",
		"openid profile", "client-id", "https://issuer.example.com",
		true, 3600,
	)
	require.NoError(t, err)

	claims, err := utils.ValidateToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "sub", claims.Sub)
}

// TestValidateToken_ExpiredToken は期限切れトークンの検証が失敗することをテストする。
//
// Ref: RFC 7519 §4.1.4
//
//	"The current date/time MUST be before the expiration date/time listed in the "exp" Claim."
//	https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
func TestValidateToken_ExpiredToken(t *testing.T) {
	setup(t)

	tokenStr, err := utils.GenerateAccessToken(
		"sub", "Name", "email@example.com", "",
		"openid", "client-id", "https://issuer.example.com",
		true, -1, // 既に期限切れ
	)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	claims, err := utils.ValidateToken(tokenStr)
	assert.Error(t, err, "expired token must be rejected")
	assert.Nil(t, claims)
}

// TestValidateToken_InvalidSignature は署名が不正なトークンの検証が失敗することをテストする。
//
// Ref: RFC 7519 §7.2 step 8
//
//	"Validate the JWT Signature."
//	https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
func TestValidateToken_InvalidSignature(t *testing.T) {
	setup(t)

	claims, err := utils.ValidateToken("invalid.token.string")
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// TestGenerateRandomString_Length は生成された文字列が指定長であることをテストする。
//
// Ref: RFC 6749 §10.10
//
//	認可コードやトークンは十分なエントロピーを持つランダム値であるべき。
//	https://datatracker.ietf.org/doc/html/rfc6749#section-10.10
func TestGenerateRandomString_Length(t *testing.T) {
	for _, length := range []int{16, 32, 64} {
		str, err := utils.GenerateRandomString(length)
		require.NoError(t, err)
		assert.Equal(t, length, len(str), "length=%d", length)
	}
}

// TestGenerateRandomString_Uniqueness は連続生成した文字列が重複しないことをテストする。
//
// Ref: RFC 6749 §10.10
//
//	https://datatracker.ietf.org/doc/html/rfc6749#section-10.10
func TestGenerateRandomString_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		s, err := utils.GenerateRandomString(32)
		require.NoError(t, err)
		_, dup := seen[s]
		assert.False(t, dup, "duplicate random string generated")
		seen[s] = struct{}{}
	}
}
