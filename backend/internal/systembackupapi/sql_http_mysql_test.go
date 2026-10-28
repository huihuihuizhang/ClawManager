package systembackupapi

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	"github.com/golang-jwt/jwt/v5"
)

const admissionRBAC = `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"rbac-admission-v1","installation_id":"installation_admission","bindings":[{"actor_id":"42","subject":"user:42","role":"operator"},{"actor_id":"43","subject":"user:43","role":"viewer"}]}`

func liveAdmissionHTTP(t *testing.T, db *sql.DB, writer TaskWriter) (*Handler, string, string) {
	t.Helper()
	ctx := context.Background()
	var identity security.DatabaseIdentity
	if err := db.QueryRow("SELECT @@server_uuid,DATABASE()").Scan(&identity.ServerUUID, &identity.Database); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	hash := digestJSON([]byte(admissionRBAC))
	path := filepath.Join(root, "rbac_bindings", "rbac-admission-v1", hash+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(admissionRBAC), 0600); err != nil {
		t.Fatal(err)
	}
	pins, _ := json.Marshal(security.SystemBackupReadPins{InstallationID: "installation_admission", ConfigVersion: 1, RBACVersion: "rbac-admission-v1", RBACSHA256: hash, RegistryDirectory: root})
	pinPath := filepath.Join(root, "pins.json")
	if err := os.WriteFile(pinPath, pins, 0600); err != nil {
		t.Fatal(err)
	}
	key := []byte(strings.Repeat("synthetic-key-", 4))
	sessions, err := security.NewSQLLoginSessions(db, identity, "installation_admission", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sessions.Close)
	tokens := []string{}
	for _, id := range []int64{42, 43} {
		password := "synthetic-not-a-login-password"
		if _, err = db.Exec("INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(?,?,?,?,'admin',TRUE)", id, "admission-user-"+strconv.FormatInt(id, 10), "synthetic-"+strconv.FormatInt(id, 10)+"@example.invalid", password); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Add(-time.Second)
		sign := func(kind string, expiry time.Duration) string {
			s, e := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": id, "token_type": kind, "jti": kind + "-admission-unique", "iat": now.Unix(), "exp": now.Add(expiry).Unix()}).SignedString(key)
			if e != nil {
				t.Fatal(e)
			}
			return s
		}
		access, refresh := sign("access", time.Hour), sign("refresh", 2*time.Hour)
		if err = sessions.RecordPair(ctx, security.LoginSessionPair{UserID: id, CredentialSHA256: digestJSON([]byte(password)), AccessToken: access, RefreshToken: refresh}); err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, access)
	}
	actions, err := security.LoadSystemBackupActionAuthorizer(sessions, pinPath, digestJSON(pins))
	if err != nil {
		t.Fatal(err)
	}
	reads, err := security.LoadSystemBackupReadAuthorizer(sessions, pinPath, digestJSON(pins))
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewSQLApplication(db, actions, reads, writer, SQLTaskDetails{DB: db}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(app), tokens[0], tokens[1]
}

func TestSQLTaskRealHTTPAuthorityAndReadback(t *testing.T) {
	db, w := submissionMySQL(t)
	handler, operator, viewer := liveAdmissionHTTP(t, db, w)
	send := func(auth, key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://example.invalid/api/v1/admin/system-backups", strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		handler.Create(res, r, read.BackupTask, "12345678-1234-4234-8234-123456789abc")
		return res
	}
	denied := send(viewer, "viewer-create-key-001", `{}`)
	if denied.Code != 403 {
		t.Fatalf("viewer status %d %s", denied.Code, denied.Body.String())
	}
	first := send(operator, "operator-create-key-001", `{}`)
	if first.Code != 202 {
		t.Fatalf("operator status %d %s", first.Code, first.Body.String())
	}
	location := first.Header().Get("Location")
	replay := send(operator, "operator-create-key-001", `{}`)
	if replay.Code != 202 || replay.Header().Get("Location") != location {
		t.Fatal("replay mismatch", replay.Code)
	}
	conflict := send(operator, "operator-create-key-001", `{"task_purpose":"functional_test"}`)
	if conflict.Code != 409 {
		t.Fatal("missing idempotency conflict", conflict.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "https://example.invalid"+location, nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+operator)
	detail, err := handler.application.ReadBackup(r, strings.TrimPrefix(location, "/api/v1/admin/system-backups/"))
	if err != nil || detail.Task.Status != "pending" || detail.AcceptanceReady || detail.Consistency != nil {
		t.Fatal("real persisted detail", err)
	}
	cancelTask := func(auth, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://example.invalid"+location+"/cancel", strings.NewReader(`{}`))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+auth)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		handler.Cancel(res, r, read.BackupTask, strings.TrimPrefix(location, "/api/v1/admin/system-backups/"), "12345678-1234-4234-8234-123456789abc")
		return res
	}
	if res := cancelTask(viewer, "viewer-cancel-key-001"); res.Code != 403 {
		t.Fatal("viewer cancellation", res.Code)
	}
	// An expired controller claim is not proof that its execution has stopped.
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET controller_owner='previous-controller',controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))"); err != nil {
		t.Fatal(err)
	}
	if res := cancelTask(operator, "operator-cancel-key-001"); res.Code != 409 {
		t.Fatal("claimed task cancellation", res.Code, res.Body.String())
	}
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET controller_owner=NULL,controller_lease_expires_at=NULL"); err != nil {
		t.Fatal(err)
	}
	// Audit failure must roll back both the operation and task transition.
	if _, err = db.Exec("CREATE TRIGGER reject_cancel_audit BEFORE INSERT ON system_backup_v2_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'"); err != nil {
		t.Fatal(err)
	}
	if res := cancelTask(operator, "operator-cancel-key-001"); res.Code != 503 {
		t.Fatal("audit failure status", res.Code, res.Body.String())
	}
	var pending, operations int
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_backups WHERE status='pending'").Scan(&pending); err != nil || pending != 1 {
		t.Fatal("failed cancellation changed task", pending, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_operations").Scan(&operations); err != nil || operations != 0 {
		t.Fatal("failed cancellation left operation", operations, err)
	}
	if _, err = db.Exec("DROP TRIGGER reject_cancel_audit"); err != nil {
		t.Fatal(err)
	}
	// Capture configuration can disappear during recovery; safe unstarted
	// cancellation still uses its independent control capacity report.
	app := handler.application.(*SQLApplication)
	app.writer = DisabledTaskWriter{}
	canceled := cancelTask(operator, "operator-cancel-key-001")
	if canceled.Code != 202 {
		t.Fatalf("cancel %d %s", canceled.Code, canceled.Body.String())
	}
	replayedCancel := cancelTask(operator, "operator-cancel-key-001")
	if replayedCancel.Code != 202 || replayedCancel.Header().Get("Location") != canceled.Header().Get("Location") {
		t.Fatal("cancellation replay", replayedCancel.Code)
	}
	detail, err = handler.application.ReadBackup(r, strings.TrimPrefix(location, "/api/v1/admin/system-backups/"))
	if err != nil || detail.Task.Status != "canceled" || detail.Task.CanCancel || detail.Execution.CurrentAttemptNumber != nil {
		t.Fatal("canceled detail", err)
	}
	app.writer = w
	if _, err = db.Exec("UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE user_id=42"); err != nil {
		t.Fatal(err)
	}
	revoked := send(operator, "operator-create-key-001", `{}`)
	if revoked.Code != 403 {
		t.Fatal("revoked replay accepted", revoked.Code)
	}
	var n int
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_backups").Scan(&n); err != nil || n != 1 {
		t.Fatal("unauthorized write", n, err)
	}
}
