package main

import (
	sec "clawreef/internal/systembackupsecurity"
	"database/sql"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigMutationProductionSelectionRequiresOriginalPinnedSourceBeforeComposition(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if p, e := loadBackupConfigMutationProduction(nil, "original_db", strings.Repeat("s", 32), getenv); e != nil || p != nil {
		t.Fatal("disabled factory opened input", e)
	}
	env["SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED"] = "true"
	if p, e := loadBackupConfigMutationProduction(nil, "original_db", strings.Repeat("s", 32), getenv); e == nil || p != nil {
		t.Fatal("missing actual SQL/session accepted")
	}
	env["SYSTEM_BACKUP_READ_SESSIONS_ENABLED"] = "true"
	env["SYSTEM_BACKUP_READ_LIVE_ENABLED"] = "true"
	file := filepath.Join(t.TempDir(), "composition.json")
	if os.WriteFile(file, []byte(`{"Passed":true}`), 0600) != nil {
		t.Fatal("fixture")
	}
	env["SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"] = file
	env["SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256"] = strings.Repeat("0", 64)
	// This disconnected pointer is never queried: source SHA must reject first.
	if p, e := loadBackupConfigMutationProduction(new(sql.DB), "original_db", strings.Repeat("s", 32), getenv); e == nil || p != nil {
		t.Fatal("untrusted input reached original owner construction")
	}
}

func TestConfigMutationLiveRouteMountRetainsClosedProduction(t *testing.T) {
	r := gin.New()
	admin := r.Group("/api/v1/admin")
	registerBackupConfigMutationLive(admin, &sec.ConfigMutationProduction{})
	for _, x := range []struct{ method, path string }{{http.MethodPut, sec.ConfigMutationPath}, {http.MethodPost, sec.ConfigRollbackPath}} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(x.method, x.path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatal("unconstructed production handler opened", x.path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, sec.ConfigMutationPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("unexpected mutation method mounted", w.Code)
	}
}
