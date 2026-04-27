package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"openid-aas/backend/handlers/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pashagolub/pgxmock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestAdminAuth_ValidToken は有効なセッショントークンで認証が通ることをテストする。
func TestAdminAuth_ValidToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	adminID := uuid.New()
	mock.ExpectQuery(`SELECT admin_id FROM admin_sessions WHERE session_token`).
		WithArgs("valid-token").
		WillReturnRows(pgxmock.NewRows([]string{"admin_id"}).AddRow(adminID))

	router := gin.New()
	router.GET("/protected", middleware.AdminAuth(mock), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAdminAuth_ValidToken_SetsAdminID は認証後に admin_id がコンテキストにセットされることをテストする。
func TestAdminAuth_ValidToken_SetsAdminID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	adminID := uuid.New()
	mock.ExpectQuery(`SELECT admin_id FROM admin_sessions WHERE session_token`).
		WithArgs("valid-token").
		WillReturnRows(pgxmock.NewRows([]string{"admin_id"}).AddRow(adminID))

	var capturedAdminID interface{}
	router := gin.New()
	router.GET("/protected", middleware.AdminAuth(mock), func(c *gin.Context) {
		capturedAdminID = c.MustGet("admin_id")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, adminID, capturedAdminID)
}

// TestAdminAuth_MissingToken はトークンなしで401が返ることをテストする。
func TestAdminAuth_MissingToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	router := gin.New()
	router.GET("/protected", middleware.AdminAuth(mock), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	// DB クエリは実行されないことを確認
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestAdminAuth_ExpiredOrInvalidToken は無効・期限切れトークンで401が返ることをテストする。
func TestAdminAuth_ExpiredOrInvalidToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	// DB がレコードなしを返す（トークン無効または期限切れ）
	mock.ExpectQuery(`SELECT admin_id FROM admin_sessions WHERE session_token`).
		WithArgs("expired-token").
		WillReturnRows(pgxmock.NewRows([]string{"admin_id"})) // 空の結果セット

	router := gin.New()
	router.GET("/protected", middleware.AdminAuth(mock), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Session-Token", "expired-token")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}
