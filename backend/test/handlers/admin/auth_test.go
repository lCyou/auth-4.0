package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/config"
	"openid-aas/backend/handlers/admin"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestConfig() *config.Config {
	return &config.Config{
		JWTIssuer:  "https://test.example.com",
		ServerPort: "8080",
	}
}

func mustBcrypt(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

// TestHandleLogin_Success は正しい認証情報でのログイン成功をテストする。
//
// 管理者セッションの発行フロー:
//   - セッショントークンはサーバー側で生成されクライアントに返却される
//   - 有効期限は24時間
func TestHandleLogin_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	adminID := uuid.New()
	hashedPassword := mustBcrypt(t, "testpassword")

	// SELECT クエリ: admin レコードを取得
	mock.ExpectQuery(`SELECT id, username, email, password_hash FROM admins WHERE username`).
		WithArgs("testadmin").
		WillReturnRows(pgxmock.NewRows([]string{"id", "username", "email", "password_hash"}).
			AddRow(adminID, "testadmin", "testadmin@example.com", hashedPassword))

	// INSERT: セッション作成
	mock.ExpectExec(`INSERT INTO admin_sessions`).
		WithArgs(adminID, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	handler := admin.NewAuthHandler(mock, newTestConfig())

	body, _ := json.Marshal(map[string]string{
		"username": "testadmin",
		"password": "testpassword",
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.HandleLogin(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["session_token"])
	assert.NotNil(t, resp["admin"])
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleLogin_WrongPassword は誤ったパスワードで401が返ることをテストする。
func TestHandleLogin_WrongPassword(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	adminID := uuid.New()
	hashedPassword := mustBcrypt(t, "correctpassword")

	mock.ExpectQuery(`SELECT id, username, email, password_hash FROM admins WHERE username`).
		WithArgs("testadmin").
		WillReturnRows(pgxmock.NewRows([]string{"id", "username", "email", "password_hash"}).
			AddRow(adminID, "testadmin", "testadmin@example.com", hashedPassword))

	handler := admin.NewAuthHandler(mock, newTestConfig())

	body, _ := json.Marshal(map[string]string{
		"username": "testadmin",
		"password": "wrongpassword",
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.HandleLogin(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleLogin_UnknownUsername は存在しないユーザー名で401が返ることをテストする。
// タイミング攻撃対策として、ユーザーが存在しない場合も同じ 401 を返す。
func TestHandleLogin_UnknownUsername(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectQuery(`SELECT id, username, email, password_hash FROM admins WHERE username`).
		WithArgs("nonexistent").
		WillReturnError(assert.AnError)

	handler := admin.NewAuthHandler(mock, newTestConfig())

	body, _ := json.Marshal(map[string]string{
		"username": "nonexistent",
		"password": "anypassword",
	})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.HandleLogin(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleLogin_MissingFields は必須フィールドが欠けたリクエストで400が返ることをテストする。
func TestHandleLogin_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body map[string]string
	}{
		{"missing password", map[string]string{"username": "admin"}},
		{"missing username", map[string]string{"password": "pass"}},
		{"empty body", map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			require.NoError(t, err)
			defer mock.Close()

			handler := admin.NewAuthHandler(mock, newTestConfig())

			body, _ := json.Marshal(tt.body)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(body))
			c.Request.Header.Set("Content-Type", "application/json")

			handler.HandleLogin(c)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// TestHandleLogin_ResponseShape はレスポンスボディのフィールドをテストする。
func TestHandleLogin_ResponseShape(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	adminID := uuid.New()
	hashedPassword := mustBcrypt(t, "pass")

	mock.ExpectQuery(`SELECT id, username, email, password_hash FROM admins WHERE username`).
		WithArgs("admin").
		WillReturnRows(pgxmock.NewRows([]string{"id", "username", "email", "password_hash"}).
			AddRow(adminID, "admin", "admin@example.com", hashedPassword))
	mock.ExpectExec(`INSERT INTO admin_sessions`).
		WithArgs(adminID, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	handler := admin.NewAuthHandler(mock, newTestConfig())

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "pass"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.HandleLogin(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// レスポンスに必須フィールドが含まれることを確認
	assert.Contains(t, resp, "session_token")
	assert.Contains(t, resp, "expires_at")
	assert.Contains(t, resp, "admin")

	adminObj, ok := resp["admin"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, adminObj, "id")
	assert.Contains(t, adminObj, "username")
	assert.Contains(t, adminObj, "email")
	// password_hash がレスポンスに含まれないことを確認（情報漏洩防止）
	assert.NotContains(t, adminObj, "password_hash")
}

// TestHandleLogout_Success は正しいセッショントークンでのログアウトをテストする。
func TestHandleLogout_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	mock.ExpectExec(`DELETE FROM admin_sessions WHERE session_token`).
		WithArgs("valid-token").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	handler := admin.NewAuthHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/logout", nil)
	c.Request.Header.Set("X-Session-Token", "valid-token")

	handler.HandleLogout(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestHandleLogout_NoToken はセッショントークンなしで400が返ることをテストする。
func TestHandleLogout_NoToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	handler := admin.NewAuthHandler(mock, newTestConfig())

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/admin/logout", nil)

	handler.HandleLogout(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
