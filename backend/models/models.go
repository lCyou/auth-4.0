package models

import (
	"time"

	"github.com/google/uuid"
)

// Admin represents an administrator
type Admin struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// User represents an end user
type User struct {
	ID            uuid.UUID `json:"id" db:"id"`
	Sub           string    `json:"sub" db:"sub"`
	Name          string    `json:"name" db:"name"`
	Email         string    `json:"email" db:"email"`
	PasswordHash  *string   `json:"-" db:"password_hash"` // 追加
	EmailVerified bool      `json:"email_verified" db:"email_verified"`
	Picture       string    `json:"picture" db:"picture"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// UserProvider represents external OAuth provider connection
type UserProvider struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	UserID         uuid.UUID  `json:"user_id" db:"user_id"`
	Provider       string     `json:"provider" db:"provider"`
	ProviderUserID string     `json:"provider_user_id" db:"provider_user_id"`
	AccessToken    string     `json:"-" db:"access_token"`
	RefreshToken   string     `json:"-" db:"refresh_token"`
	ExpiresAt      *time.Time `json:"expires_at" db:"expires_at"`
	IDToken        string     `json:"-" db:"id_token"`
	Scope          string     `json:"scope" db:"scope"`
	TokenType      string     `json:"token_type" db:"token_type"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// Client represents an OAuth/OIDC client application
type Client struct {
	ID                      uuid.UUID `json:"id" db:"id"`
	ClientID                string    `json:"client_id" db:"client_id"`
	ClientSecret            string    `json:"-" db:"client_secret"`
	ClientName              string    `json:"client_name" db:"client_name"`
	RedirectURIs            []string  `json:"redirect_uris" db:"redirect_uris"`
	GrantTypes              []string  `json:"grant_types" db:"grant_types"`
	ResponseTypes           []string  `json:"response_types" db:"response_types"`
	Scope                   string    `json:"scope" db:"scope"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

// AuthorizationCode represents an OAuth authorization code
type AuthorizationCode struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	Code                string    `json:"code" db:"code"`
	ClientID            uuid.UUID `json:"client_id" db:"client_id"`
	UserID              uuid.UUID `json:"user_id" db:"user_id"`
	RedirectURI         string    `json:"redirect_uri" db:"redirect_uri"`
	Scope               string    `json:"scope" db:"scope"`
	CodeChallenge       string    `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method" db:"code_challenge_method"`
	Nonce               string    `json:"nonce" db:"nonce"`
	State               string    `json:"state" db:"state"`
	ExpiresAt           time.Time `json:"expires_at" db:"expires_at"`
	Used                bool      `json:"used" db:"used"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

// AccessToken represents an OAuth access token
type AccessToken struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Token     string    `json:"token" db:"token"`
	ClientID  uuid.UUID `json:"client_id" db:"client_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	Scope     string    `json:"scope" db:"scope"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Revoked   bool      `json:"revoked" db:"revoked"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// RefreshToken represents an OAuth refresh token
type RefreshToken struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Token         string     `json:"token" db:"token"`
	ClientID      uuid.UUID  `json:"client_id" db:"client_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	AccessTokenID *uuid.UUID `json:"access_token_id" db:"access_token_id"`
	Scope         string     `json:"scope" db:"scope"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	Revoked       bool       `json:"revoked" db:"revoked"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// AdminSession represents an admin session
type AdminSession struct {
	ID           uuid.UUID `json:"id" db:"id"`
	AdminID      uuid.UUID `json:"admin_id" db:"admin_id"`
	SessionToken string    `json:"session_token" db:"session_token"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	ActorType    string                 `json:"actor_type" db:"actor_type"`
	ActorID      *uuid.UUID             `json:"actor_id" db:"actor_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id" db:"resource_id"`
	Details      map[string]interface{} `json:"details" db:"details"`
	IPAddress    string                 `json:"ip_address" db:"ip_address"`
	UserAgent    string                 `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}
