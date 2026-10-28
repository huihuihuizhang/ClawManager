package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"clawreef/internal/systembackupapi"
	"github.com/gin-gonic/gin"
)

func TestBackupTaskRouteCompositionFailsClosedWithoutApplication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registerBackupReadLive(router.Group("/api/v1/admin"), &liveBackupRead{})
	registerBackupTaskMutations(router.Group("/api/v1/admin"), systembackupapi.NewHandler(linkedSystemBackupTaskApplication(nil, nil)))
	for _, path := range []string{"/system-backups", "/system-backup-preflights"} {
		for _, method := range []string{"POST", "GET"} {
			target := "/api/v1/admin" + path
			if method == "GET" {
				target += "/sbk_11111111-2222-3333-4444-555555555555"
			}
			w := httptest.NewRecorder()
			request := httptest.NewRequest(method, target, strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "unwired-key-123456")
			router.ServeHTTP(w, request)
			if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"not_ready"`) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%s %s: unwired runtime escaped: %d %s", method, path, w.Code, w.Body)
			}
		}
	}
}
