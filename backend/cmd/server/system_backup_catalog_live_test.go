package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clawreef/internal/systembackupcontract"
	"github.com/gin-gonic/gin"
)

func TestLivePublicationReadPreservesOriginalSignedJSON(t *testing.T) {
	// Serialization boundary DATA, never a valid signing/read authorization.
	raw := []byte(`{"payload":{"original":"<source>&\u2028"},"signature":{"value":"DATA"}}`)
	sum := sha256.Sum256(raw)
	result := systembackupcontract.CatalogRecordResource{ID: "scr_00000000-0000-4000-8000-000000000001", RecordSHA256: hex.EncodeToString(sum[:]), Record: raw}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	writePublicationReadJSON(c, result)
	var got systembackupcontract.CatalogRecordResource
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || !bytes.Equal(got.Record, raw) || got.RecordSHA256 != result.RecordSHA256 {
		t.Fatal("HTTP serialization rewrote original signed record bytes")
	}
}

func TestLivePublicationReadRoutesRequireOriginalRequestScope(t *testing.T) {
	db, sessions, env := liveReadTestSetup(t)
	live, e := loadLiveBackupRead(db, sessions, func(k string) string { return env[k] })
	if e != nil {
		t.Fatal(e)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	registerBackupReadLive(router.Group("/api/v1/admin"), live)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/v1/admin/system-backup-catalog-records", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-catalog-records/scr_00000000-0000-4000-8000-000000000001", http.StatusUnauthorized},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001/manifest", http.StatusUnauthorized},
		{"/api/v1/admin/system-backup-catalog-records?status=succeeded", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-catalog-records?limit=0", http.StatusBadRequest},
		{"/api/v1/admin/system-backup-catalog-records?limit=1&limit=2", http.StatusBadRequest},
		{"/api/v1/admin/system-backups/sbk_00000000-0000-4000-8000-000000000001/manifest?version=latest", http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("publication route authorization/query boundary", tc.path, w.Code)
		}
	}
}

func TestLivePublicationReadMaterialsFailClosedAtStartup(t *testing.T) {
	if reader, e := loadPublicationHTTPRead(func(string) string { return "" }); e != nil || reader != nil {
		t.Fatal("missing materials enabled reader")
	}
	if reader, e := loadPublicationHTTPRead(func(k string) string {
		if k == "SYSTEM_BACKUP_PUBLICATION_READ_FILE" {
			return "missing-relative-material.json"
		}
		return ""
	}); e == nil || reader != nil {
		t.Fatal("unpinned material enabled reader")
	}
}
