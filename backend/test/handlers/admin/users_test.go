package admin_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openid-aas/backend/handlers/admin"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var userColumns = []string{
	"id", "sub", "name", "email", "email_verified", "picture", "created_at", "updated_at",
}

// TestHandleListUsers_Success はユーザー一覧の正常取得をテストする。
//
// Ref: OpenID Connect Core 1.0 §5.1 (Standard Claims)
//
//	sub, name, email, email_verified, picture は標準クレームとして定義されている。
//	https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func TestHandleListUsers_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`SELECT (.+) FROM users`).
		WillReturnRows(pgxmock.NewRows(userColumns).
			AddRow(userID, "github_12345", "Test User", "test@example.com", true, "", now, now))

	handler := admin.NewUsersHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	handler.HandleListUsers(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	users, ok := resp["users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, users, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleListUsers_Empty はユーザーゼロ件の場合に空配列が返ることをテストす���。
func TestHandleListUsers_Empty(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectQuery(`SELECT (.+) FROM users`).
		WillReturnRows(pgxmock.NewRows(userColumns))

	handler := admin.NewUsersHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	handler.HandleListUsers(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp["users"].([]interface{}))
}

// TestHandleGetUser_Success はユーザー取得の正常系をテス��する。
// プロバイダー連携情報も合わせて返す。
func TestHandleGetUser_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id`).
		WithArgs(userID.String()).
		WillReturnRows(pgxmock.NewRows(userColumns).
			AddRow(userID, "github_12345", "Test User", "test@example.com", true, "", now, now))

	mock.ExpectQuery(`SELECT (.+) FROM user_providers WHERE user_id`).
		WithArgs(userID.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "provider", "provider_user_id", "scope", "created_at"}).
			AddRow(uuid.New().String(), "github", "12345", "user:email read:user", now))

	handler := admin.NewUsersHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users/"+userID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: userID.String()}}
	handler.HandleGetUser(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp, "user")
	assert.Contains(t, resp, "providers")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleGetUser_NotFound ��存在しないユーザーで404が返ることをテストする。
func TestHandleGetUser_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	mock.ExpectQuery(`SELECT (.+) FROM users WHERE id`).
		WithArgs(userID.String()).
		WillReturnRows(pgxmock.NewRows(userColumns))

	handler := admin.NewUsersHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users/"+userID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: userID.String()}}
	handler.HandleGetUser(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestHandleDeleteUser_Success はユーザー削除の正常系��テストする。
// CASCADE により user_providers も削除される（DB制約で保証）。
func TestHandleDeleteUser_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	userID := uuid.New()
	mock.ExpectExec(`DELETE FROM users WHERE id`).
		WithArgs(userID.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	handler := admin.NewUsersHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+userID.String(), nil)
	c.Params = gin.Params{{Key: "id", Value: userID.String()}}
	handler.HandleDeleteUser(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
