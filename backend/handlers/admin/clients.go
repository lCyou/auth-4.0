package admin

import (
	"context"
	"net/http"

	"openid-aas/backend/config"
	"openid-aas/backend/models"
	"openid-aas/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
)

// ClientsHandler handles client application management
type ClientsHandler struct {
	db     *pgxpool.Pool
	config *config.Config
}

func NewClientsHandler(db *pgxpool.Pool, cfg *config.Config) *ClientsHandler {
	return &ClientsHandler{
		db:     db,
		config: cfg,
	}
}

// HandleListClients returns all client applications
func (h *ClientsHandler) HandleListClients(c *gin.Context) {
	rows, err := h.db.Query(context.Background(), `
		SELECT id, client_id, client_name, redirect_uris, grant_types, response_types, scope, created_at, updated_at
		FROM clients
		ORDER BY created_at DESC
	`)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch clients"})
		return
	}
	defer rows.Close()

	clients := []models.Client{}
	for rows.Next() {
		var client models.Client
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.ClientName,
			pq.Array(&client.RedirectURIs), pq.Array(&client.GrantTypes),
			pq.Array(&client.ResponseTypes), &client.Scope,
			&client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			continue
		}
		clients = append(clients, client)
	}

	c.JSON(http.StatusOK, gin.H{"clients": clients})
}

// HandleCreateClient creates a new client application
func (h *ClientsHandler) HandleCreateClient(c *gin.Context) {
	var req struct {
		ClientName              string   `json:"client_name" binding:"required"`
		RedirectURIs            []string `json:"redirect_uris" binding:"required"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		Scope                   string   `json:"scope"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Set defaults
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.Scope == "" {
		req.Scope = "openid profile email"
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Generate client ID and secret
	clientID, err := utils.GenerateRandomString(24)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate client ID"})
		return
	}

	clientSecret, err := utils.GenerateRandomString(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate client secret"})
		return
	}

	// Insert client
	var client models.Client
	err = h.db.QueryRow(context.Background(), `
		INSERT INTO clients (client_id, client_secret, client_name, redirect_uris, grant_types, response_types, scope, token_endpoint_auth_method)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, client_id, client_name, redirect_uris, grant_types, response_types, scope, token_endpoint_auth_method, created_at, updated_at
	`, clientID, clientSecret, req.ClientName, pq.Array(req.RedirectURIs), pq.Array(req.GrantTypes),
		pq.Array(req.ResponseTypes), req.Scope, req.TokenEndpointAuthMethod).Scan(
		&client.ID, &client.ClientID, &client.ClientName,
		pq.Array(&client.RedirectURIs), pq.Array(&client.GrantTypes),
		pq.Array(&client.ResponseTypes), &client.Scope,
		&client.TokenEndpointAuthMethod, &client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create client"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client":        client,
		"client_secret": clientSecret,
	})
}

// HandleGetClient returns a specific client
func (h *ClientsHandler) HandleGetClient(c *gin.Context) {
	clientID := c.Param("id")

	var client models.Client
	err := h.db.QueryRow(context.Background(), `
		SELECT id, client_id, client_name, redirect_uris, grant_types, response_types, scope, token_endpoint_auth_method, created_at, updated_at
		FROM clients WHERE id = $1
	`, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientName,
		pq.Array(&client.RedirectURIs), pq.Array(&client.GrantTypes),
		pq.Array(&client.ResponseTypes), &client.Scope,
		&client.TokenEndpointAuthMethod, &client.CreatedAt, &client.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Client not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"client": client})
}

// HandleDeleteClient deletes a client application
func (h *ClientsHandler) HandleDeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	_, err := h.db.Exec(context.Background(), `
		DELETE FROM clients WHERE id = $1
	`, clientID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete client"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Client deleted successfully"})
}
