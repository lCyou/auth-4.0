package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"openid-aas/backend/auth"
	"openid-aas/backend/config"
	"openid-aas/backend/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoauth2 "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

// RegisterUserInput はユーザー登録時のリクエストボディを表します。
type RegisterUserInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// AuthHandler は認証関連のハンドラを保持します。
type AuthHandler struct {
	DB                *pgxpool.Pool
	Cfg               *config.Config
	GoogleOAuthConfig *oauth2.Config
}

// NewAuthHandler は新しい AuthHandler を作成します。
func NewAuthHandler(db *pgxpool.Pool, cfg *config.Config) *AuthHandler {
	googleOAuthConfig := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	return &AuthHandler{
		DB:                db,
		Cfg:               cfg,
		GoogleOAuthConfig: googleOAuthConfig,
	}
}

// RedirectToGoogle はユーザーをGoogleの認証ページにリダイレクトします。
func (h *AuthHandler) RedirectToGoogle(c *gin.Context) {
	// CSRF対策のためのstateを生成
	state, err := generateOauthState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}
	// stateをクッキーに保存
	c.SetCookie("oauthstate", state, 3600, "/", "", false, true)

	// 認証URLを生成
	url := h.GoogleOAuthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// HandleGoogleCallback はGoogleからのコールバックを処理します。
func (h *AuthHandler) HandleGoogleCallback(c *gin.Context) {
	// stateの検証
	cookieState, err := c.Cookie("oauthstate")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state cookie not set or expired"})
		return
	}
	queryState := c.Query("state")
	if cookieState != queryState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}

	// 認可コードを取得
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code not found"})
		return
	}

	// コードをトークンに交換
	token, err := h.GoogleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	// ユーザー情報を取得
	userInfo, err := getUserInfoFromGoogle(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// トランザクションを開始
	tx, err := h.DB.Begin(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	defer tx.Rollback(context.Background()) // エラー時はロールバック

	// ユーザーが存在するか確認、存在しない場合は作成
	var user models.User
	err = tx.QueryRow(context.Background(), "SELECT id, email, name, image, email_verified FROM users WHERE email = $1", userInfo.Email).Scan(&user.ID, &user.Email, &user.Name, &user.Image, &user.EmailVerified)
	if err == pgx.ErrNoRows {
		// ユーザーが存在しない場合、新規作成
		err = tx.QueryRow(context.Background(),
			"INSERT INTO users (name, email, image, email_verified) VALUES ($1, $2, $3, $4) RETURNING id, email, name, image, email_verified",
			userInfo.Name, userInfo.Email, userInfo.Picture, time.Now()).Scan(&user.ID, &user.Email, &user.Name, &user.Image, &user.EmailVerified)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user"})
		return
	}

	// accountsテーブルに情報を保存
	var accountID uuid.UUID
	err = tx.QueryRow(context.Background(),
		"INSERT INTO accounts (user_id, type, provider, provider_account_id, access_token, expires_at, token_type, scope, id_token) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (provider, provider_account_id) DO UPDATE SET access_token = EXCLUDED.access_token, expires_at = EXCLUDED.expires_at, updated_at = NOW() RETURNING id",
		user.ID, "oauth", "google", userInfo.Id, token.AccessToken, token.Expiry.Unix(), token.TokenType, token.Extra("scope"), token.Extra("id_token")).Scan(&accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create or update account"})
		return
	}

	// トランザクションをコミット
	if err := tx.Commit(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// JWTを生成
	jwtToken, err := auth.GenerateJWT(user.ID.String(), h.Cfg.JWTSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// フロントエンドにリダイレクト（トークンをクエリパラメータとして渡す）
	redirectURL := h.Cfg.FrontendURL + "?token=" + jwtToken
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// generateOauthState はCSRF対策のためのランダムな文字列を生成します。
func generateOauthState() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// getUserInfoFromGoogle はGoogleからユーザー情報を取得します。
func getUserInfoFromGoogle(token *oauth2.Token) (*googleoauth2.Userinfo, error) {
	client := option.WithTokenSource(oauth2.StaticTokenSource(token))
	oauth2Service, err := googleoauth2.NewService(context.Background(), client)
	if err != nil {
		return nil, err
	}

	userInfo, err := oauth2Service.Userinfo.Get().Do()
	if err != nil {
		return nil, err
	}
	return userInfo, nil
}

// RegisterUser は新しいユーザーを登録します。
func (h *AuthHandler) RegisterUser(c *gin.Context) {
	var input RegisterUserInput
	// リクエストボディを構造体にバインドし、バリデーションを実行
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// メールアドレスが既に存在するか確認
	var existingEmail string
	err := h.DB.QueryRow(context.Background(), "SELECT email FROM users WHERE email = $1", input.Email).Scan(&existingEmail)
	if err == nil { // err が nil の場合は、レコードが見つかったことを意味する
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
		return
	}

	// パスワードをハッシュ化
	hashedPassword, err := auth.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// 新しいユーザーを作成
	var newUser models.User
	err = h.DB.QueryRow(context.Background(),
		"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at, updated_at",
		input.Email, hashedPassword).Scan(&newUser.ID, &newUser.Email, &newUser.CreatedAt, &newUser.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "user": newUser})
}

// LoginUserInput はユーザーログイン時のリクエストボディを表します。
type LoginUserInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login はユーザーをログインさせ、JWTを返します。
func (h *AuthHandler) Login(c *gin.Context) {
	var input LoginUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := h.DB.QueryRow(context.Background(),
		"SELECT id, email, password_hash FROM users WHERE email = $1",
		input.Email).Scan(&user.ID, &user.Email, &user.PasswordHash)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if user.PasswordHash == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Password not set for this user. Try a different login method."})
		return
	}

	// パスワードを検証
	if !auth.CheckPasswordHash(input.Password, *user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// JWTを生成
	token, err := auth.GenerateJWT(user.ID.String(), h.Cfg.JWTSecretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}
