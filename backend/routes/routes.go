package routes

import (
	"openid-aas/backend/config"
	"openid-aas/backend/handlers/admin"
	"openid-aas/backend/handlers/oauth"
	"openid-aas/backend/handlers/oidc"
	"openid-aas/backend/middleware"

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

	api := r.Group("/api")
	{
		// OAuth authentication endpoints for end users
		auth := api.Group("/auth")
		{
			auth.GET("/google", func(c *gin.Context) {
				state := c.Query("state")
				if state == "" {
					state = "random_state" // TODO: Generate proper state
				}
				authURL := googleHandler.GetAuthURL(state)
				c.Redirect(302, authURL)
			})

			auth.GET("/callback/google", func(c *gin.Context) {
				code := c.Query("code")
				state := c.Query("state")

				if code == "" {
					c.JSON(400, gin.H{"error": "No authorization code"})
					return
				}

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
