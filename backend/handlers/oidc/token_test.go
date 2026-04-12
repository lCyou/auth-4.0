package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestScopeContains verifies that scopeContains correctly identifies scope tokens.
//
// Scope syntax:
//   - RFC 6749 §3.3: "The value of the scope parameter is expressed as a list of
//     space-delimited, case-sensitive strings."
//     https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
//   - OpenID Connect Core 1.0 §3.1.2.1: Scope values "openid", "profile", "email"
//     https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//
// NOTE: このテストは fix/scope-contains-bug PR が develop にマージされると通るようになる。
func TestScopeContains(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		target   string
		expected bool
	}{
		// --- 正常系 ---
		{
			// RFC 6749 §3.3: スコープが単一トークンの場合
			name:     "single scope exact match",
			scope:    "openid",
			target:   "openid",
			expected: true,
		},
		{
			// RFC 6749 §3.3: リストの先頭にある場合
			name:     "target is first in list",
			scope:    "openid profile email",
			target:   "openid",
			expected: true,
		},
		{
			// RFC 6749 §3.3: リストの中間にある場合（旧実装がサイレントに失敗していた回帰ケース）
			name:     "target is middle in list (regression)",
			scope:    "openid profile email",
			target:   "profile",
			expected: true,
		},
		{
			// RFC 6749 §3.3: リストの末尾にある場合
			name:     "target is last in list",
			scope:    "openid profile email",
			target:   "email",
			expected: true,
		},
		// --- 異常系 ---
		{
			// RFC 6749 §3.3: スコープが存在しない場合
			name:     "target not in list",
			scope:    "openid profile",
			target:   "email",
			expected: false,
		},
		{
			// RFC 6749 §3.3: 部分文字列はマッチしてはならない
			name:     "partial match must not match",
			scope:    "openid profile email",
			target:   "open",
			expected: false,
		},
		{
			// RFC 6749 §3.3: 部分文字列はマッチしてはならない（suffix）
			name:     "suffix partial match must not match",
			scope:    "openid profile email",
			target:   "id",
			expected: false,
		},
		{
			// 空のスコープリスト
			name:     "empty scope string",
			scope:    "",
			target:   "openid",
			expected: false,
		},
		{
			// 空のターゲット
			name:     "empty target",
			scope:    "openid profile email",
			target:   "",
			expected: false,
		},
		{
			// RFC 6749 §3.3: スコープは大文字小文字を区別する
			name:     "case sensitive: uppercase should not match lowercase",
			scope:    "openid profile email",
			target:   "OpenID",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopeContains(tt.scope, tt.target)
			assert.Equal(t, tt.expected, got,
				"scopeContains(%q, %q) = %v, want %v", tt.scope, tt.target, got, tt.expected)
		})
	}
}
