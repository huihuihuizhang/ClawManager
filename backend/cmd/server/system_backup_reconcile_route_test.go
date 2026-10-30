package main

import (
	"net/http/httptest"
	"testing"

	"clawreef/internal/systembackupapi"
	"github.com/gin-gonic/gin"
)

func TestPublicBackupReconcileRouteFailsClosedWithoutApplication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerBackupTaskMutations(r.Group("/api/v1/admin"), systembackupapi.NewHandler(nil))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/system-backups/sbk_11111111-1111-4111-8111-111111111111/reconcile", nil))
	if w.Code != 503 {
		t.Fatalf("reconciliation route unavailable: got %d, want explicit not_ready", w.Code)
	}
}
