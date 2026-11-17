package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

func lateFixture(t *testing.T) *backupMutationFirstLoad {
	t.Helper()
	// Paths below are test-local; production construction separately restricts
	// actual deployment paths. Injection is per-instance and not exposed by env.
	root := t.TempDir()
	return &backupMutationFirstLoad{db: new(sql.DB), database: "original_db", secret: strings.Repeat("s", 32), document: filepath.Join(root, "composition.json"), pin: filepath.Join(root, "composition.sha256"), getenv: func(string) string { return "" }, load: loadBackupConfigMutationProduction}
}
func lateWritePin(t *testing.T, s *backupMutationFirstLoad, v string) {
	t.Helper()
	if err := os.WriteFile(s.pin, []byte(v), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFirstLoadDirectSelectionUnchanged(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	for _, enabled := range []string{"", "false", "true"} {
		env["SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED"] = enabled
		a, ea := loadBackupConfigMutationStartup(nil, "original_db", strings.Repeat("s", 32), get)
		b, eb := loadBackupConfigMutationProduction(nil, "original_db", strings.Repeat("s", 32), get)
		if a != b || (ea == nil) != (eb == nil) {
			t.Fatal("direct mode behavior changed", enabled)
		}
		late, e := newBackupMutationFirstLoad(nil, "original_db", "", get)
		if e != nil || late != nil {
			t.Fatal("direct mode installed late loader")
		}
	}
}
func TestFirstLoadConfigurationRejectsAmbiguousAuthority(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixed /run mount admission is Linux deployment only")
	}
	env := map[string]string{"SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED": "true", "SYSTEM_BACKUP_READ_LIVE_ENABLED": "true", "SYSTEM_BACKUP_READ_SESSIONS_ENABLED": "true", "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE": "/run/system-backup/runtime/app.json", backupMutationLatePin: "/run/system-backup/runtime/app.sha256"}
	get := func(k string) string { return env[k] }
	db := new(sql.DB)
	secret := strings.Repeat("s", 32)
	if _, e := newBackupMutationFirstLoad(db, "original_db", secret, get); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ k, v string }{{"SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256", strings.Repeat("a", 64)}, {backupMutationLatePin, "/tmp/pin"}, {backupMutationLatePin, env["SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"]}, {"SYSTEM_BACKUP_READ_LIVE_ENABLED", "false"}, {"SYSTEM_BACKUP_READ_SESSIONS_ENABLED", "false"}, {"SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED", "false"}} {
		old := env[tc.k]
		env[tc.k] = tc.v
		if _, e := newBackupMutationFirstLoad(db, "original_db", secret, get); e == nil {
			t.Fatal("ambiguous startup accepted", tc.k)
		}
		env[tc.k] = old
	}
}
func TestFirstLoadMissingMalformedPinNeverConstructsAndCanRetry(t *testing.T) {
	s := lateFixture(t)
	var calls int
	s.load = func(*sql.DB, string, string, func(string) string) (*sec.ConfigMutationProduction, error) {
		calls++
		return &sec.ConfigMutationProduction{}, nil
	}
	if p, e := s.get(); p != nil || e == nil {
		t.Fatal("missing pin accepted")
	}
	for _, pin := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("a", 64) + "\n"} {
		lateWritePin(t, s, pin)
		if p, e := s.get(); p != nil || e == nil {
			t.Fatal("malformed pin accepted")
		}
	}
	if calls != 0 {
		t.Fatal("loader reached before valid pin")
	}
	lateWritePin(t, s, strings.Repeat("a", 64))
	if p, e := s.get(); e != nil || p == nil || calls != 1 {
		t.Fatal("missing/bad input poisoned retry")
	}
	s.Close()
}
func TestFirstLoadStrictFailureAndPinChangeDoNotCommit(t *testing.T) {
	s := lateFixture(t)
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	lateWritePin(t, s, first)
	var calls int
	s.load = func(_ *sql.DB, _ string, _ string, env func(string) string) (*sec.ConfigMutationProduction, error) {
		calls++
		if env("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE") != s.document {
			t.Fatal("request changed fixed document")
		}
		if calls == 1 {
			return nil, errors.New("original strict owner rejected")
		}
		if calls == 2 {
			lateWritePin(t, s, second)
			return &sec.ConfigMutationProduction{}, nil
		}
		if env("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256") != second {
			t.Fatal("retry used stale pin")
		}
		return &sec.ConfigMutationProduction{}, nil
	}
	for i := 0; i < 2; i++ {
		if p, e := s.get(); p != nil || e == nil || s.production != nil {
			t.Fatal("partial/changed load committed")
		}
	}
	if p, e := s.get(); p == nil || e != nil || calls != 3 {
		t.Fatal("original failure cannot retry")
	}
	s.Close()
}
func TestFirstLoadConcurrentSuccessIsSingleAndImmutable(t *testing.T) {
	s := lateFixture(t)
	lateWritePin(t, s, strings.Repeat("a", 64))
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	want := &sec.ConfigMutationProduction{}
	s.load = func(*sql.DB, string, string, func(string) string) (*sec.ConfigMutationProduction, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return want, nil
	}
	const count = 24
	start := make(chan struct{})
	got := make(chan *sec.ConfigMutationProduction, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; p, e := s.get(); got <- p; errs <- e }()
	}
	close(start)
	<-entered
	close(release)
	wg.Wait()
	close(got)
	close(errs)
	for p := range got {
		if p != want {
			t.Fatal("different production returned")
		}
	}
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent construction repeated")
	}
	lateWritePin(t, s, strings.Repeat("b", 64))
	if p, e := s.get(); p != want || e != nil || calls.Load() != 1 {
		t.Fatal("successful instance reloaded")
	}
	if e := os.Remove(s.pin); e != nil {
		t.Fatal(e)
	}
	if p, e := s.get(); p != want || e != nil {
		t.Fatal("committed loader reread pin")
	}
	s.Close()
	if p, e := s.get(); p != nil || e == nil {
		t.Fatal("closed loader reused")
	}
	s.Close()
}
func TestFirstLoadCloseBeforeInitialization(t *testing.T) {
	s := lateFixture(t)
	s.Close()
	if p, e := s.get(); p != nil || e == nil {
		t.Fatal("closed cold loader accepted")
	}
}
func TestFirstLoadMountsOnlyOriginalRoutesAndFailsClosed(t *testing.T) {
	r := gin.New()
	s := lateFixture(t)
	registerBackupConfigMutationFirstLoad(r.Group("/api/v1/admin"), s)
	routes := r.Routes()
	if len(routes) != 2 {
		t.Fatal("extra route")
	}
	for _, route := range routes {
		if !((route.Method == http.MethodPut && route.Path == sec.ConfigMutationPath) || (route.Method == http.MethodPost && route.Path == sec.ConfigRollbackPath)) {
			t.Fatal("unexpected route", route.Method, route.Path)
		}
	}
	for _, route := range routes {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(route.Method, route.Path, nil))
		if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cold route did not fail closed")
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, sec.ConfigMutationPath, nil))
	if w.Code != 404 {
		t.Fatal("new mutation method exposed")
	}
}

func TestFirstLoadRetainsOriginalStrictCompositionValidation(t *testing.T) {
	s := lateFixture(t)
	s.getenv = func(k string) string {
		switch k {
		case "SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED", "SYSTEM_BACKUP_READ_SESSIONS_ENABLED", "SYSTEM_BACKUP_READ_LIVE_ENABLED":
			return "true"
		}
		return ""
	}
	// Exact SHA is not authority: original strict decoder must reject fake owner DATA.
	raw := []byte(`{"Passed":true}`)
	if err := os.WriteFile(s.document, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	lateWritePin(t, s, hex.EncodeToString(sum[:]))
	if p, err := s.get(); p != nil || err == nil || s.production != nil {
		t.Fatal("late mode bypassed original strict loader")
	}
	s.Close()
}
