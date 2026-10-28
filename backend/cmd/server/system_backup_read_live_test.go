package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

func liveReadTestSetup(t *testing.T) (*sql.DB, *systembackupsecurity.SQLLoginSessions, map[string]string) {
	t.Helper()
	db := new(sql.DB) // Scope construction does not query until a valid token is presented.
	sessions, err := systembackupsecurity.NewSQLLoginSessions(db,
		systembackupsecurity.DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "testdb"},
		"installation_test", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pins, err := json.Marshal(systembackupsecurity.SystemBackupReadPins{
		InstallationID: "installation_test", ConfigVersion: 1, RBACVersion: "rbac-v1",
		RBACSHA256: strings.Repeat("a", 64), RegistryDirectory: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "read-pins.json")
	if err := os.WriteFile(path, pins, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pins)
	return db, sessions, map[string]string{
		"SYSTEM_BACKUP_READ_LIVE_ENABLED":   "true",
		"SYSTEM_BACKUP_READ_PINS_PATH":      path,
		"SYSTEM_BACKUP_READ_PINS_SHA256":    hex.EncodeToString(digest[:]),
		"SYSTEM_BACKUP_READ_CURSOR_KEY_HEX": hex.EncodeToString([]byte(strings.Repeat("c", 32))),
	}
}

func TestLiveBackupReadRequiresPinnedAuthorityAndSessions(t *testing.T) {
	db, sessions, env := liveReadTestSetup(t)
	getenv := func(key string) string { return env[key] }
	if live, err := loadLiveBackupRead(nil, nil, func(string) string { return "" }); err != nil || live != nil {
		t.Fatal("default live read was enabled", err)
	}
	if live, err := loadLiveBackupRead(db, nil, getenv); err == nil || live == nil || live.authorizer != nil {
		t.Fatal("missing session recorder was not kept unavailable")
	}
	delete(env, "SYSTEM_BACKUP_READ_CURSOR_KEY_HEX")
	if live, err := loadLiveBackupRead(db, sessions, getenv); err == nil || live == nil || live.authorizer != nil {
		t.Fatal("missing dedicated cursor key was accepted")
	}
	env["SYSTEM_BACKUP_READ_CURSOR_KEY_HEX"] = hex.EncodeToString([]byte(strings.Repeat("c", 32)))
	live, err := loadLiveBackupRead(db, sessions, getenv)
	if err != nil || live == nil || live.authorizer == nil {
		t.Fatal("valid deployment pin rejected", err)
	}
	env["SYSTEM_BACKUP_READ_PINS_SHA256"] = strings.Repeat("0", 64)
	if live, err := loadLiveBackupRead(db, sessions, getenv); err == nil || live == nil || live.authorizer != nil {
		t.Fatal("incorrect read pin was accepted")
	}
	env["SYSTEM_BACKUP_READ_LIVE_ENABLED"] = "yes"
	if live, err := loadLiveBackupRead(db, sessions, getenv); err == nil || live != nil {
		t.Fatal("ambiguous live read switch accepted")
	}
}

func TestLiveBackupReadHTTPFailsClosedWithoutCurrentAuthorization(t *testing.T) {
	db, sessions, env := liveReadTestSetup(t)
	live, err := loadLiveBackupRead(db, sessions, func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registerBackupReadLive(router.Group("/api/v1/admin"), live)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/v1/admin/system-backups", http.StatusUnauthorized},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001/events", http.StatusUnauthorized},
		{"/api/v1/admin/system-restore-drills/sdr_00000000-0000-4000-8000-000000000001/events", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-preflights/spf_00000000-0000-4000-8000-000000000001/events", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-artifact-verifications/sav_00000000-0000-4000-8000-000000000001/events", http.StatusUnauthorized},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001/events?status=pending", http.StatusBadRequest},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001/events?limit=0", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-operations", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-artifact-verifications/sav_00000000-0000-4000-8000-000000000001", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-artifact-verifications/sav_00000000-0000-4000-8000-000000000001?ignored=1", http.StatusBadRequest},
		{"/api/v1/admin/system-restore-drills/sdr_00000000-0000-4000-8000-000000000001", http.StatusUnauthorized},
		{"/api/v1/admin/system-restore-drills/sdr_00000000-0000-4000-8000-000000000001?ignored=1", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-operations/sop_00000000-0000-4000-8000-000000000001", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-config", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-config/versions", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-config/versions/1", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-config?version=1", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-config/versions?status=enabled", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-config/versions/01", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-config/versions/9007199254740992", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-config/versions/1?unexpected=1", http.StatusBadRequest},
		{"/api/v1/admin/system-backups?status=pending&status=failed", http.StatusBadRequest},
		{"/api/v1/admin/system-backups?limit=%", http.StatusBadRequest},
		{"/api/v1/admin/system-backups?limit=10&status=%ZZ", http.StatusBadRequest},
		{"/api/v1/admin/system-backups?limit=10;status=failed", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-operations?cursor=%FF%", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-config/versions?limit=2&ignored=%ZZ", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-operations?status=running", http.StatusBadRequest},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001", http.StatusServiceUnavailable},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if response.Code != tc.want || response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("X-System-Backup-Data-Source") == "fixture" {
			t.Fatalf("%s: status=%d body=%s", tc.path, response.Code, response.Body.String())
		}
	}
}
