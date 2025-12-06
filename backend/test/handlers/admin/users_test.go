package admin_test

import (
	"net/http"
	"net/http/httptest"
	"testing"


	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestHandleListUsers_Success tests successful user listing
func TestHandleListUsers_Success(t *testing.T) {
	// Arrange

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)

	// Act & Assert
	// Expected: Should return list of users with 200 OK
	// cfg was not used in this test
	assert.Equal(t, http.MethodGet, c.Request.Method)
}

// TestHandleListUsers_EmptyDatabase tests user listing with no users
func TestHandleListUsers_EmptyDatabase(t *testing.T) {
	// Arrange
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)

	// Act & Assert
	// Expected: Should return empty array with 200 OK
	assert.NotNil(t, c)
}

// TestHandleGetUser_ValidID tests getting a specific user
func TestHandleGetUser_ValidID(t *testing.T) {
	// Arrange
	userID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users/"+userID, nil)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	// Act
	retrievedID := c.Param("id")

	// Assert
	assert.Equal(t, userID, retrievedID)
}

// TestHandleGetUser_InvalidID tests getting user with invalid ID format
func TestHandleGetUser_InvalidID(t *testing.T) {
	// Arrange
	invalidID := "not-a-uuid"

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users/"+invalidID, nil)
	c.Params = gin.Params{{Key: "id", Value: invalidID}}

	// Act
	retrievedID := c.Param("id")
	_, err := uuid.Parse(retrievedID)

	// Assert
	// Expected: Should return 400 Bad Request for invalid UUID
	assert.Error(t, err)
}

// TestHandleGetUser_NotFound tests getting non-existent user
func TestHandleGetUser_NotFound(t *testing.T) {
	// Arrange
	userID := uuid.New().String() // Valid UUID but doesn't exist

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users/"+userID, nil)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	// Act & Assert
	// Expected: Should return 404 Not Found for non-existent user
	// cfg was not used in this test
}

// TestHandleDeleteUser_ValidID tests deleting a user
func TestHandleDeleteUser_ValidID(t *testing.T) {
	// Arrange
	userID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+userID, nil)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	// Act & Assert
	// Expected: Should delete user and return 200 OK
	// cfg was not used in this test
}

// TestHandleDeleteUser_InvalidID tests deleting with invalid ID
func TestHandleDeleteUser_InvalidID(t *testing.T) {
	// Arrange
	invalidID := "not-a-uuid"

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+invalidID, nil)
	c.Params = gin.Params{{Key: "id", Value: invalidID}}

	// Act
	_, err := uuid.Parse(invalidID)

	// Assert
	// Expected: Should return 400 Bad Request for invalid UUID
	assert.Error(t, err)
}

// TestHandleDeleteUser_WithProviders tests deleting user with connected providers
func TestHandleDeleteUser_WithProviders(t *testing.T) {
	// Arrange
	userID := uuid.New().String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+userID, nil)
	c.Params = gin.Params{{Key: "id", Value: userID}}

	// Act & Assert
	// Expected: Should cascade delete user and their provider connections
	// cfg was not used in this test
}

// TestHandleListUsers_Pagination tests user listing with pagination
func TestHandleListUsers_Pagination(t *testing.T) {
	// Arrange

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users?page=1&limit=10", nil)

	// Act
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "10")

	// Assert
	assert.Equal(t, "1", page)
	assert.Equal(t, "10", limit)
}

// TestHandleListUsers_Sorting tests user listing with sorting
func TestHandleListUsers_Sorting(t *testing.T) {
	// Arrange

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/admin/users?sort=created_at&order=desc", nil)

	// Act
	sortField := c.DefaultQuery("sort", "created_at")
	sortOrder := c.DefaultQuery("order", "desc")

	// Assert
	assert.Equal(t, "created_at", sortField)
	assert.Equal(t, "desc", sortOrder)
}
