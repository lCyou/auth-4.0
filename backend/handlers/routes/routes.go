package routes

import (
	"crypto/rand"
	"encoding/base64"
	"openid-aas/backend/config"
	"openid-aas/backend/handlers/admin"
	"openid-aas/backend/handlers/middleware"
	"openid-aas/backend/handlers/oauth"
	"openid-aas/backend/handlers/oidc"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Setup(r *gin.Engine, db *pgxpool.Pool, cfg *config.Config) {
	// Middleware
	r.Use(middleware.CORS(cfg))

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// OpenID Connect Discovery endpoints
	discoveryHandler := oidc.NewDiscoveryHandler(cfg)
	r.GET("/.well-known/openid-configuration", discoveryHandler.HandleWellKnown)
	r.GET("/oauth/jwks", discoveryHandler.HandleJWKS)

	// OAuth/OIDC Provider endpoints
	authzHandler := oidc.NewAuthorizationHandler(db, cfg)
	tokenHandler := oidc.NewTokenHandler(db, cfg)
	userInfoHandler := oidc.NewUserInfoHandler(db, cfg)

	r.GET("/oauth/authorize", authzHandler.HandleAuthorize)
	r.POST("/oauth/token", tokenHandler.HandleToken)
	r.GET("/oauth/userinfo", userInfoHandler.HandleUserInfo)
	r.POST("/oauth/userinfo", userInfoHandler.HandleUserInfo)

	// External OAuth provider endpoints
	googleHandler := oauth.NewGoogleOAuthHandler(db, cfg)
	githubHandler := oauth.NewGitHubOAuthHandler(db, cfg)

	api := r.Group("/api")
	{
		// OAuth authentication endpoints for end users
		auth := api.Group("/auth")
		{
			auth.GET("/google", func(c *gin.Context) {
				// Generate cryptographically secure random state (RFC 6749)
				stateBytes := make([]byte, 32)
				if _, err := rand.Read(stateBytes); err != nil {
					c.JSON(500, gin.H{"error": "Failed to generate state"})
					return
				}
				state := base64.URLEncoding.EncodeToString(stateBytes)

				// Store state in cookie for validation
				c.SetCookie(
					"oauth_state_google",
					state,
					600, // 10 minutes
					"/",
					"",
					false, // secure (set to true in production with HTTPS)
					true,  // httpOnly
				)

				authURL := googleHandler.GetAuthURL(state)
				c.Redirect(302, authURL)
			})

			auth.GET("/callback/google", func(c *gin.Context) {
				code := c.Query("code")
				state := c.Query("state")
				errorParam := c.Query("error")

				// Check for OAuth errors
				if errorParam != "" {
					errorDesc := c.Query("error_description")
					c.JSON(400, gin.H{
						"error":             errorParam,
						"error_description": errorDesc,
					})
					return
				}

				if code == "" {
					c.JSON(400, gin.H{"error": "No authorization code"})
					return
				}

				// Validate state parameter (RFC 6749 Section 10.12)
				storedState, err := c.Cookie("oauth_state_google")
				if err != nil || storedState == "" {
					c.JSON(400, gin.H{"error": "Missing state cookie"})
					return
				}

				if state != storedState {
					c.JSON(400, gin.H{"error": "Invalid state parameter"})
					return
				}

				// Clear state cookie after validation
				c.SetCookie("oauth_state_google", "", -1, "/", "", false, true)

				// Exchange code for tokens
				tokenResp, err := googleHandler.ExchangeCode(code)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// Get user info
				userInfo, err := googleHandler.GetUserInfo(tokenResp.AccessToken)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// Create or update user
				user, err := googleHandler.CreateOrUpdateUser(c.Request.Context(), userInfo, tokenResp)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// TODO: Create session for user and redirect
				c.JSON(200, gin.H{
					"user":  user,
					"state": state,
				})
			})

			// GitHub OAuth endpoints
			auth.GET("/github", func(c *gin.Context) {
				// Generate cryptographically secure random state (RFC 6749)
				stateBytes := make([]byte, 32)
				if _, err := rand.Read(stateBytes); err != nil {
					c.JSON(500, gin.H{"error": "Failed to generate state"})
					return
				}
				state := base64.URLEncoding.EncodeToString(stateBytes)

				// Store state in cookie for validation
				c.SetCookie(
					"oauth_state",
					state,
					600, // 10 minutes
					"/",
					"",
					false, // secure (set to true in production with HTTPS)
					true,  // httpOnly
				)

				authURL := githubHandler.GetAuthURL(state)
				c.Redirect(302, authURL)
			})

			auth.GET("/callback/github", func(c *gin.Context) {
				code := c.Query("code")
				state := c.Query("state")

				if code == "" {
					c.JSON(400, gin.H{"error": "No authorization code"})
					return
				}

				// Validate state parameter (RFC 6749 Section 10.12)
				storedState, err := c.Cookie("oauth_state")
				if err != nil || storedState == "" {
					c.JSON(400, gin.H{"error": "Missing state cookie"})
					return
				}

				if state != storedState {
					c.JSON(400, gin.H{"error": "Invalid state parameter"})
					return
				}

				// Clear state cookie after validation
				c.SetCookie("oauth_state", "", -1, "/", "", false, true)

				// Exchange code for tokens
				tokenResp, err := githubHandler.ExchangeCode(code)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// Get user info
				userInfo, err := githubHandler.GetUserInfo(tokenResp.AccessToken)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// Create or update user
				user, err := githubHandler.CreateOrUpdateUser(c.Request.Context(), userInfo, tokenResp)
				if err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}

				// TODO: Create session for user and redirect
				c.JSON(200, gin.H{
					"user":  user,
					"state": state,
				})
			})
		}

		// Admin API endpoints
		adminAuth := admin.NewAuthHandler(db, cfg)
		api.POST("/admin/login", adminAuth.HandleLogin)
		api.POST("/admin/logout", adminAuth.HandleLogout)

		// Protected admin endpoints
		adminGroup := api.Group("/admin")
		adminGroup.Use(middleware.AdminAuth(db))
		{
			// Client management
			clientsHandler := admin.NewClientsHandler(db, cfg)
			adminGroup.GET("/clients", clientsHandler.HandleListClients)
			adminGroup.POST("/clients", clientsHandler.HandleCreateClient)
			adminGroup.GET("/clients/:id", clientsHandler.HandleGetClient)
			adminGroup.DELETE("/clients/:id", clientsHandler.HandleDeleteClient)

			// User management
			usersHandler := admin.NewUsersHandler(db, cfg)
			adminGroup.GET("/users", usersHandler.HandleListUsers)
			adminGroup.GET("/users/:id", usersHandler.HandleGetUser)
			adminGroup.DELETE("/users/:id", usersHandler.HandleDeleteUser)
		}
	}
}
