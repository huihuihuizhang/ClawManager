package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSystemBackupReadFixtureAuthRejectsMissingAndInvalidTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/read", SystemBackupReadFixtureAuth(nil), func(c *gin.Context) { c.Status(200) })
	for _, token := range []string{"", "Bearer invalid"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/read", nil)
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		req.Header.Set("X-Request-ID", "fixture_auth_test")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["code"] != "authentication_required" || body["request_id"] != "fixture_auth_test" {
			t.Fatalf("unexpected error: %v", body)
		}
	}
}
