package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
	"github.com/golang-jwt/jwt/v5"
)

type readScopeTestState struct {
	base           *registrationTestState
	identity       DatabaseIdentity
	session        string
	until          time.Time
	revoked        bool
	inactive       bool
	userFailure    bool
	sessionFailure bool
	missingSession bool
}

type readScopeTestConnector struct{ state *readScopeTestState }

func (c readScopeTestConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c readScopeTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &readScopeTestConn{registrationTestConn: registrationTestConn{c.state.base}, state: c.state}, nil
}

type readScopeTestConn struct {
	registrationTestConn
	state *readScopeTestState
}

func (c *readScopeTestConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	if options.Isolation != driver.IsolationLevel(sql.LevelReadCommitted) {
		return nil, errors.New("read committed required")
	}
	return c.Begin()
}

func (c *readScopeTestConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case query == "SELECT @@server_uuid,DATABASE()":
		return registrationRow(c.state.identity.ServerUUID, c.state.identity.Database), nil
	case strings.Contains(query, "SELECT password_hash FROM users"):
		if c.state.userFailure {
			return nil, errors.New("user query unavailable")
		}
		if c.state.inactive || len(args) != 1 || args[0].Value != int64(42) {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow("synthetic-password-hash"), nil
	case strings.Contains(query, "FROM system_backup_v2_admin_sessions"):
		if c.state.sessionFailure {
			return nil, errors.New("session query unavailable")
		}
		if len(args) != 2 || args[0].Value != "installation_synthetic" || args[1].Value != c.state.session {
			return nil, errors.New("session query escaped scope")
		}
		if c.state.missingSession {
			return &registrationTestRows{width: 6}, nil
		}
		return registrationRow(int64(42), "user:42", registrationHash("synthetic-password-hash"), c.state.until, c.state.revoked, time.Now().UTC()), nil
	case strings.HasPrefix(query, "SELECT COALESCE(MAX(id),0) FROM system_backup_v2_backups"):
		if len(args) != 1 || args[0].Value != "installation_synthetic" {
			return nil, errors.New("task query escaped authorized installation")
		}
		return registrationRow(int64(0)), nil
	}
	return c.registrationTestConn.QueryContext(ctx, query, args)
}

func TestSystemBackupReadScopeRechecksSessionAndConfig(t *testing.T) {
	root := t.TempDir()
	raw := `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"rbac-v1","installation_id":"installation_synthetic","bindings":[{"actor_id":"42","subject":"user:42","role":"viewer"}]}`
	digest := registrationHash(raw)
	file := filepath.Join(root, "rbac_bindings", "rbac-v1", digest+".json")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	secret := []byte(strings.Repeat("k", 32))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": int64(42), "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/api/v1/admin/system-backups", nil)
	requestContext, cancelRequest := context.WithCancel(request.Context())
	defer cancelRequest()
	request = request.WithContext(requestContext)
	request.Header.Set("Authorization", "Bearer "+token)
	identity := DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "synthetic"}
	state := &readScopeTestState{base: &registrationTestState{config: RegistrationConfig{
		ProviderRegistryVersion: "p1", ProviderRegistrySHA256: strings.Repeat("a", 64),
		StrongAuthRegistryVersion: "s1", StrongAuthRegistrySHA256: strings.Repeat("b", 64),
		RBACRegistryVersion: "rbac-v1", RBACRegistrySHA256: digest, NonceKeyVersion: "v1",
	}}, identity: identity, session: registrationHash(token), until: now.Add(time.Hour)}
	db := sql.OpenDB(readScopeTestConnector{state})
	defer db.Close()
	sessions, err := NewSQLLoginSessions(db, identity, "installation_synthetic", secret)
	if err != nil {
		t.Fatal(err)
	}
	pins := SystemBackupReadPins{InstallationID: "installation_synthetic", ConfigVersion: 1,
		RBACVersion: "rbac-v1", RBACSHA256: digest, RegistryDirectory: root}
	pinned, err := json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	pinsPath := filepath.Join(root, "read-pins.json")
	if err := os.WriteFile(pinsPath, pinned, 0600); err != nil {
		t.Fatal(err)
	}
	authorizer, err := LoadSystemBackupReadAuthorizer(sessions, pinsPath, registrationHash(string(pinned)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSystemBackupReadAuthorizer(nil, pinsPath, registrationHash(string(pinned))); err == nil {
		t.Fatal("missing session recorder accepted")
	}
	if _, err := LoadSystemBackupReadAuthorizer(sessions, pinsPath, strings.Repeat("0", 64)); err == nil {
		t.Fatal("incorrect deployment pin accepted")
	}
	other := pins
	other.InstallationID = "installation_other"
	otherBytes, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinsPath, otherBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSystemBackupReadAuthorizer(sessions, pinsPath, registrationHash(string(otherBytes))); err == nil {
		t.Fatal("read pin selected another installation")
	}
	extra := []byte(strings.TrimSuffix(string(pinned), "}") + `,"unknown":"value"}`)
	if err := os.WriteFile(pinsPath, extra, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSystemBackupReadAuthorizer(sessions, pinsPath, registrationHash(string(extra))); err == nil {
		t.Fatal("unknown deployment field accepted")
	}
	if err := os.WriteFile(pinsPath, pinned, 0600); err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest("POST", request.URL.String(), nil)
	post.Header.Set("Authorization", "Bearer "+token)
	if _, err := authorizer.Scope(post); err == nil {
		t.Fatal("read authority accepted mutation")
	}
	if _, err := authorizer.Scope(httptest.NewRequest("GET", request.URL.String(), nil)); err != ErrSystemBackupReadAuthentication {
		t.Fatal("read authority accepted missing access token")
	}
	scope, err := authorizer.Scope(request)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := systembackupread.NewReader(db, scope)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.ListTasks(scope.Context(), systembackupread.PageRequest{Kind: systembackupread.BackupTask, Limit: 20})
	if err != nil || page.InstallationID != "installation_synthetic" || len(page.Items) != 0 {
		t.Fatal("D reader did not consume A scope", page.InstallationID, err)
	}
	for _, failure := range []*bool{&state.userFailure, &state.sessionFailure} {
		*failure = true
		_, err := reader.ListTasks(scope.Context(), systembackupread.PageRequest{Kind: systembackupread.BackupTask, Limit: 20})
		*failure = false
		if !errors.Is(err, ErrProviderEvidenceStorage) || !errors.Is(err, systembackupread.ErrDenied) {
			t.Fatal("session storage failure lost its unavailable cause", err)
		}
	}
	state.missingSession = true
	_, err = reader.ListTasks(scope.Context(), systembackupread.PageRequest{Kind: systembackupread.BackupTask, Limit: 20})
	state.missingSession = false
	if !errors.Is(err, ErrRegistrationPermission) || errors.Is(err, ErrProviderEvidenceStorage) {
		t.Fatal("missing session was not denied", err)
	}
	ctx := scope.Context()
	begin := func() *sql.Tx {
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	tx := begin()
	if _, err := scope.AuthorizeRead(context.Background(), tx); err != ErrRegistrationPermission {
		t.Fatal("scope accepted another request context", err)
	}
	installation, err := scope.AuthorizeRead(ctx, tx)
	if err != nil || installation != "installation_synthetic" {
		t.Fatal("valid viewer denied", installation, err)
	}
	if err := scope.RecheckRead(ctx, tx, installation); err != nil {
		t.Fatal("valid recheck denied", err)
	}
	if err := scope.RecheckRead(ctx, tx, "installation_other"); err != ErrRegistrationPermission {
		t.Fatal("cross-installation recheck accepted", err)
	}
	state.revoked = true
	if err := scope.RecheckRead(ctx, tx, installation); err != ErrRegistrationPermission {
		t.Fatal("revocation after page read accepted", err)
	}
	_ = tx.Rollback()

	tx = begin()
	if _, err := scope.AuthorizeRead(ctx, tx); err != ErrRegistrationPermission {
		t.Fatal("revoked session accepted", err)
	}
	_ = tx.Rollback()
	state.revoked = false

	tx = begin()
	if _, err := scope.AuthorizeRead(ctx, tx); err != nil {
		t.Fatal(err)
	}
	state.inactive = true
	if err := scope.RecheckRead(ctx, tx, installation); err != ErrRegistrationPermission {
		t.Fatal("inactive user after page read accepted", err)
	}
	_ = tx.Rollback()
	state.inactive = false

	tx = begin()
	if _, err := scope.AuthorizeRead(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(strings.Replace(raw, "viewer", "operator", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scope.RecheckRead(ctx, tx, installation); err != ErrRegistrationUnavailable {
		t.Fatal("changed RBAC file accepted", err)
	}
	_ = tx.Rollback()
	if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}

	tx = begin()
	if _, err := scope.AuthorizeRead(ctx, tx); err != nil {
		t.Fatal(err)
	}
	state.base.config.RBACRegistrySHA256 = strings.Repeat("c", 64)
	if err := scope.RecheckRead(ctx, tx, installation); err != ErrRegistrationUnavailable {
		t.Fatal("config drift accepted", err)
	}
	_ = tx.Rollback()

	cancelRequest()
	tx, err = db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scope.AuthorizeRead(ctx, tx); err != ErrRegistrationPermission {
		t.Fatal("completed request reused", err)
	}
	_ = tx.Rollback()
}
