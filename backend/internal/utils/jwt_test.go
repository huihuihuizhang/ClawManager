package utils

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGeneratedTokensHaveUniqueSessionIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		raw, err := GenerateToken(TokenClaims{UserID: 42, TokenType: "access"}, "synthetic-secret", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := ValidateToken(raw, "synthetic-secret")
		if err != nil {
			t.Fatal(err)
		}
		if len(claims.ID) != 32 || seen[claims.ID] || claims.UserID != 42 || claims.TokenType != "access" || claims.IssuedAt == nil || claims.ExpiresAt == nil {
			t.Fatal("session ID collision or changed claims")
		}
		seen[claims.ID] = true
	}
}

func TestBackupSessionHTTPFailures(t *testing.T) {
	for message, status := range map[string]int{"system_backup_session_rejected": 401, "system_backup_session_unavailable": 503} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		HandleError(c, errors.New(message))
		if w.Code != status {
			t.Fatalf("status %d want %d", w.Code, status)
		}
	}
}
