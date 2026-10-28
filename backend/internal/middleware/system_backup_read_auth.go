package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"

	"clawreef/internal/repository"
	"github.com/gin-gonic/gin"
)

var systemBackupRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func SystemBackupRequestID(c *gin.Context) string {
	if id := c.GetHeader("X-Request-ID"); systemBackupRequestIDPattern.MatchString(id) {
		return id
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "request_unavailable"
	}
	return hex.EncodeToString(bytes[:])
}

// SystemBackupReadFixtureAuth applies the normal access-token and administrator
// checks while returning the system-backup error envelope. The fixture remains
// opt-in until the system_backup.read role bindings are available.
func SystemBackupReadFixtureAuth(userRepo repository.UserRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		fail := func(status int, code, message string) {
			c.JSON(status, gin.H{"code": code, "message": message, "details": gin.H{}, "request_id": SystemBackupRequestID(c)})
			c.Abort()
		}
		token, ok := extractToken(c)
		if !ok {
			fail(http.StatusUnauthorized, "authentication_required", "Authentication required")
			return
		}
		claims, err := validateUserAccessToken(token)
		if err != nil {
			fail(http.StatusUnauthorized, "authentication_required", "Invalid or expired token")
			return
		}
		user, err := userRepo.GetByID(claims.UserID)
		if err != nil {
			fail(http.StatusInternalServerError, "internal_error", "User lookup is unavailable")
			return
		}
		if user == nil {
			fail(http.StatusUnauthorized, "authentication_required", "User not found")
			return
		}
		if user.Role != "admin" {
			fail(http.StatusForbidden, "permission_denied", "System backup read access denied")
			return
		}
		c.Set("userID", claims.UserID)
		c.Set("userRole", user.Role)
		c.Set("user", user)
		c.Next()
	}
}
