package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openid-aas/backend/handlers/admin"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientColumns は HandleListClients / HandleGetClient が SELECT するカラム一覧
var clientColumns = []string{
	"id", "client_id", "client_name",
	"redirect_uris", "grant_types", "response_types",
	"scope", "token_endpoint_auth_method",
	"created_at", "updated_at",
}

// TestHandleListClients_Success はクライアント一覧の正常取得をテストする。
//
// Ref: RFC 7591 §2 (Dynamic Client Registration)
//
//	https://datatracker.ietf.org/doc/html/rfc7591#section-2
func TestHandleListClients_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	clientID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`SELECT (.+) FROM clients`).
		WillReturnRows(pgxmock.NewRows(clientColumns).
			AddRow(
				clientID, "client-abc", "Test Client",
				pq.Array([]string{"https://app.example.com/callback"}),
				pq.Array([]string{"authorization_code"}),
				pq.Array([]string{"code"}),
				"openid profile email", "client_secret_basic",
				now, now,
			))

	handler := admin.NewClientsHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients", nil)
	handler.HandleListClients(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	clients, ok := resp["clients"].([]interface{})
	require.True(t, ok)
	assert.Len(t, clients, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleListClients_Empty は登録クライアントがゼロ件の場合に空配列が返ることをテストする。
func TestHandleListClients_Empty(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectQuery(`SELECT (.+) FROM clients`).
		WillReturnRows(pgxmock.NewRows(clientColumns))

	handler := admin.NewClientsHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients", nil)
	handler.HandleListClients(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	clients := resp["clients"].([]interface{})
	assert.Empty(t, clients)
}

// TestHandleCreateClient_Success はクライアント作成の正常系をテストする。
//
// Ref: RFC 7591 §3.1 (Client Registration Request)
//
//	redirect_uris は REQUIRED。
//	https://datatracker.ietf.org/doc/html/rfc7591#section-3.1
func TestHandleCreateClient_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	newID := uuid.New()
	now := time.Now()

	// INSERT ... RETURNING
	mock.ExpectQuery(`INSERT INTO clients`).
		WillReturnRows(pgxmock.NewRows(clientColumns).
			AddRow(
				newID, "generated-client-id", "My App",
				pq.Array([]string{"https://app.example.com/callback"}),
				pq.Array([]string{"authorization_code"}),
				pq.Array([]string{"code"}),
				"openid profile email", "client_secret_basic",
				now, now,
			))

	handler := admin.NewClientsHandler(mock, newTestConfig())

	body, _ := json.Marshal(map[string]interface{}{
		"client_name":   "My App",
		"redirect_uris": []string{"https://app.example.com/callback"},
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/clients", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")
	handler.HandleCreateClient(c)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// 作成直後のみ client_secret が返る
	assert.NotEmpty(t, resp["client_secret"], "client_secret must be returned on creation only")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleCreateClient_MissingRequiredFields は必須フィールド欠落で400が返ることをテストする。
//
// Ref: RFC 7591 §3.2.2 (Client Registration Error Response)
//
//	https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
func TestHandleCreateClient_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body map[string]interface{}
	}{
		{"missing client_name", map[string]interface{}{"redirect_uris": []string{"https://example.com"}}},
		{"missing redirect_uris", map[string]interface{}{"client_name": "App"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			handler := admin.NewClientsHandler(mock, newTestConfig())

			body, _ := json.Marshal(tt.body)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/clients", bytes.NewBuffer(body))
			c.Request.Header.Set("Content-Type", "application/json")
			handler.HandleCreateClient(c)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// TestHandleGetClient_Success はクライアント取得の正常系をテストする。
func TestHandleGetClient_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	clientID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`SELECT (.+) FROM clients WHERE id`).
		WithArgs(clientID.String()).
		WillReturnRows(pgxmock.NewRows(clientColumns).
			AddRow(
				clientID, "client-abc", "Test Client",
				pq.Array([]string{"https://app.example.com/callback"}),
				pq.Array([]string{"authorization_code"}),
				pq.Array([]string{"code"}),
				"openid profile email", "client_secret_basic",
				now, now,
			))

	handler := admin.NewClientsHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients/"+clientID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: clientID.String()}}
	handler.HandleGetClient(c)

	require.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleGetClient_NotFound は存在しないクライアントで404が返ることをテストする。
func TestHandleGetClient_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	clientID := uuid.New()
	mock.ExpectQuery(`SELECT (.+) FROM clients WHERE id`).
		WithArgs(clientID.String()).
		WillReturnRows(pgxmock.NewRows(clientColumns)) // 0件

	handler := admin.NewClientsHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/clients/"+clientID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: clientID.String()}}
	handler.HandleGetClient(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandleDeleteClient_Success はクライアント削除の正常系をテストする。
func TestHandleDeleteClient_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	clientID := uuid.New()
	mock.ExpectExec(`DELETE FROM clients WHERE id`).
		WithArgs(clientID.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	handler := admin.NewClientsHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/clients/"+clientID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: clientID.String()}}
	handler.HandleDeleteClient(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
