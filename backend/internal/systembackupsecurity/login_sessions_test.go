package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"testing"
	"time"
)

// Transactional test double: proves rollback/issuance boundaries, not MySQL
// locking semantics. Real server verification remains a separate gate.
type loginSessionRow struct {
	user                int64
	subject, credential string
	expires             time.Time
	revoked             bool
}
type loginSessionDB struct {
	now, finalNow                                     time.Time
	password, role, server                            string
	active                                            bool
	offset                                            int64
	revokedBefore                                     *time.Time
	rows, pending                                     map[string]loginSessionRow
	writes, failWrite, commits, audits, pendingAudits int
	commitUnknown                                     bool
	onCommit                                          func()
}
type loginSessionConnector struct{ s *loginSessionDB }

func (c loginSessionConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c loginSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &loginSessionConn{c.s}, nil
}

type loginSessionConn struct{ s *loginSessionDB }

func (*loginSessionConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*loginSessionConn) Close() error                        { return nil }
func (c *loginSessionConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (c *loginSessionConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("isolation")
	}
	c.s.pending = map[string]loginSessionRow{}
	for k, v := range c.s.rows {
		c.s.pending[k] = v
	}
	c.s.writes = 0
	c.s.pendingAudits = 0
	return &loginSessionTx{c.s}, nil
}
func (c *loginSessionConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if strings.Contains(q, "origin_installation_id=?") && args[0].Value != "installation_sessions" {
		return nil, errors.New("installation mismatch")
	}
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		return registrationRow(s.server, "synthetic"), nil
	case strings.HasPrefix(q, "SELECT password_hash,role,is_active"):
		if args[0].Value != int64(42) {
			return nil, errors.New("user mismatch")
		}
		return registrationRow(s.password, s.role, s.active), nil
	case strings.HasPrefix(q, "SELECT password_hash FROM users"):
		if !s.active || s.role != "admin" {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(s.password), nil
	case strings.Contains(q, "TIMESTAMPDIFF"):
		return registrationRow(s.now, s.offset), nil
	case q == "SELECT UTC_TIMESTAMP(6)":
		return registrationRow(s.finalNow), nil
	case strings.HasPrefix(q, "SELECT revoked_before"):
		if s.revokedBefore == nil {
			return &registrationTestRows{width: 1}, nil
		}
		return registrationRow(*s.revokedBefore), nil
	case strings.HasPrefix(q, "SELECT user_id,subject,credential_hash"):
		v, ok := s.pending[args[1].Value.(string)]
		if !ok {
			return &registrationTestRows{width: 6}, nil
		}
		return registrationRow(v.user, v.subject, v.credential, v.expires, v.revoked, s.now), nil
	case strings.HasPrefix(q, "SELECT COUNT(*) FROM system_backup_v2_admin_sessions"):
		if !strings.Contains(q, "revoked=FALSE") {
			return nil, errors.New("revoked rows counted")
		}
		n := int64(0)
		for _, v := range s.pending {
			if !v.revoked && v.expires.After(s.now) {
				n++
			}
		}
		return registrationRow(n), nil
	}
	return nil, errors.New("unexpected query")
}
func (c *loginSessionConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	s.writes++
	if s.failWrite == s.writes {
		return nil, errors.New("PRIVATE_SQL_ERROR")
	}
	switch {
	case strings.HasPrefix(q, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE"):
		k := args[1].Value.(string)
		v, ok := s.pending[k]
		if !ok || v.revoked {
			return driver.RowsAffected(0), nil
		}
		v.revoked = true
		s.pending[k] = v
	case strings.HasPrefix(q, "DELETE FROM system_backup_v2_admin_sessions"):
		for k, v := range s.pending {
			if !v.expires.After(s.now) {
				delete(s.pending, k)
			}
		}
	case strings.HasPrefix(q, "INSERT INTO system_backup_v2_admin_sessions"):
		if strings.Contains(q, "DUPLICATE") {
			return nil, errors.New("must not revive")
		}
		k := args[1].Value.(string)
		if _, ok := s.pending[k]; ok {
			return nil, errors.New("duplicate")
		}
		s.pending[k] = loginSessionRow{user: args[2].Value.(int64), subject: args[3].Value.(string), credential: args[4].Value.(string), expires: args[5].Value.(time.Time)}
	case strings.HasPrefix(q, "INSERT INTO audit_logs"):
		action := args[1].Value.(string)
		if action != "system_backup.session.login" && action != "system_backup.session.refresh" {
			return nil, errors.New("audit action")
		}
		s.pendingAudits++
	default:
		return nil, errors.New("unexpected write")
	}
	return driver.RowsAffected(1), nil
}

type loginSessionTx struct{ s *loginSessionDB }

func (t *loginSessionTx) Commit() error {
	t.s.rows = t.s.pending
	t.s.pending = nil
	t.s.commits++
	t.s.audits += t.s.pendingAudits
	if t.s.onCommit != nil {
		t.s.onCommit()
	}
	if t.s.commitUnknown {
		return errors.New("PRIVATE_COMMIT_ERROR")
	}
	return nil
}
func (t *loginSessionTx) Rollback() error { t.s.pending = nil; t.s.pendingAudits = 0; return nil }

func loginSessionsFixture(t *testing.T) (*SQLLoginSessions, *loginSessionDB, func() LoginSessionPair) {
	t.Helper()
	now := time.Now().UTC()
	state := &loginSessionDB{now: now, finalNow: now, password: "verified-password-hash", role: "admin", server: "11111111-2222-3333-4444-555555555555", active: true, rows: map[string]loginSessionRow{}}
	db := sql.OpenDB(loginSessionConnector{state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	secret := []byte(strings.Repeat("s", 32))
	s, err := NewSQLLoginSessions(db, DatabaseIdentity{ServerUUID: state.server, Database: "synthetic"}, "installation_sessions", secret)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	mint := func() LoginSessionPair {
		index++
		pair := LoginSessionPair{UserID: 42, CredentialSHA256: registrationHash(state.password)}
		for _, kind := range []string{"access", "refresh"} {
			expiry := now.Add(15 * time.Minute)
			if kind == "refresh" {
				expiry = now.Add(24 * time.Hour)
			}
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": kind, "jti": fmt.Sprintf("%s-%d", kind, index), "iat": now.Add(-2 * time.Second).Unix(), "exp": expiry.Unix()}).SignedString(secret)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "access" {
				pair.AccessToken = raw
			} else {
				pair.RefreshToken = raw
			}
		}
		return pair
	}
	return s, state, mint
}

func TestLoginSessionsIssueRotateReplayAndPasswordChange(t *testing.T) {
	s, db, mint := loginSessionsFixture(t)
	ctx := context.Background()
	first := mint()
	if err := s.RecordPair(ctx, first); err != nil {
		t.Fatal(err)
	}
	if len(db.rows) != 2 || db.audits != 1 {
		t.Fatal("pair and audit not committed together")
	}
	next := mint()
	next.PreviousRefreshToken = first.RefreshToken
	if err := s.RecordPair(ctx, next); err != nil {
		t.Fatal(err)
	}
	if !db.rows[registrationHash(first.RefreshToken)].revoked || db.audits != 2 {
		t.Fatal("parent was not consumed")
	}
	replay := mint()
	replay.PreviousRefreshToken = first.RefreshToken
	if err := s.RecordPair(ctx, replay); err != ErrLoginSessionRejected {
		t.Fatalf("replay: %v", err)
	}
	db.password = "changed-password-hash"
	changed := mint()
	changed.PreviousRefreshToken = next.RefreshToken
	if err := s.RecordPair(ctx, changed); err != ErrLoginSessionRejected {
		t.Fatalf("old refresh rebound to new credential: %v", err)
	}
	if len(db.rows) != 4 || db.audits != 2 {
		t.Fatal("rejected refresh committed state")
	}
}

func TestLoginSessionsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*loginSessionDB, *LoginSessionPair)
	}{
		{"credential changed", func(d *loginSessionDB, p *LoginSessionPair) { d.password = "new" }},
		{"disabled", func(d *loginSessionDB, p *LoginSessionPair) { d.active = false }},
		{"database mismatch", func(d *loginSessionDB, p *LoginSessionPair) { d.server = "different" }},
		{"database not UTC", func(d *loginSessionDB, p *LoginSessionPair) { d.offset = 3600000000 }},
		{"logout epoch", func(d *loginSessionDB, p *LoginSessionPair) { d.revokedBefore = &d.now }},
		{"wrong user", func(d *loginSessionDB, p *LoginSessionPair) { p.UserID = 43 }},
		{"access used as refresh", func(d *loginSessionDB, p *LoginSessionPair) { p.RefreshToken = p.AccessToken }},
		{"unregistered parent", func(d *loginSessionDB, p *LoginSessionPair) { p.PreviousRefreshToken = p.RefreshToken }},
		{"expired at commit", func(d *loginSessionDB, p *LoginSessionPair) { d.finalNow = d.now.Add(time.Hour) }},
		{"stale database clock", func(d *loginSessionDB, p *LoginSessionPair) { d.finalNow = d.now.Add(-time.Minute) }},
		{"session limit", func(d *loginSessionDB, p *LoginSessionPair) {
			for i := 0; i < 255; i++ {
				d.rows[fmt.Sprint(i)] = loginSessionRow{expires: d.now.Add(time.Hour)}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, d, mint := loginSessionsFixture(t)
			p := mint()
			tc.mutate(d, &p)
			if err := s.RecordPair(context.Background(), p); err == nil {
				t.Fatal("accepted")
			}
			if d.commits != 0 || d.audits != 0 {
				t.Fatal("committed rejection")
			}
		})
	}
}

func TestLoginSessionsRefreshRollback(t *testing.T) {
	for fail := 1; fail <= 5; fail++ {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			s, d, mint := loginSessionsFixture(t)
			first := mint()
			if err := s.RecordPair(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			d.failWrite = fail
			next := mint()
			next.PreviousRefreshToken = first.RefreshToken
			if err := s.RecordPair(context.Background(), next); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("write failure: %v", err)
			}
			if len(d.rows) != 2 || d.rows[registrationHash(first.RefreshToken)].revoked || d.audits != 1 {
				t.Fatal("partial rotation persisted")
			}
		})
	}
}

func TestLoginSessionsParentBinding(t *testing.T) {
	for _, kind := range []string{"missing", "revoked", "user", "subject", "credential", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			s, d, mint := loginSessionsFixture(t)
			first := mint()
			if err := s.RecordPair(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			k := registrationHash(first.RefreshToken)
			v := d.rows[k]
			switch kind {
			case "revoked":
				v.revoked = true
			case "user":
				v.user = 43
			case "subject":
				v.subject = "user:43"
			case "credential":
				v.credential = registrationHash("other")
			case "expiry":
				v.expires = d.now.Add(-time.Second)
			}
			d.rows[k] = v
			if kind == "missing" {
				delete(d.rows, k)
			}
			next := mint()
			next.PreviousRefreshToken = first.RefreshToken
			if err := s.RecordPair(context.Background(), next); err != ErrLoginSessionRejected {
				t.Fatalf("parent %s: %v", kind, err)
			}
			if d.commits != 1 {
				t.Fatal("bad parent committed")
			}
		})
	}
}

func TestLoginSessionsBusinessUsersAndCommitBoundary(t *testing.T) {
	t.Run("non admin legacy refresh", func(t *testing.T) {
		s, d, mint := loginSessionsFixture(t)
		d.role = "user"
		p := mint()
		p.PreviousRefreshToken = "legacy token validated by existing auth service"
		if err := s.RecordPair(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		if len(d.rows) != 0 || d.audits != 0 {
			t.Fatal("business user enrolled")
		}
	})
	t.Run("unknown commit", func(t *testing.T) {
		s, d, mint := loginSessionsFixture(t)
		d.commitUnknown = true
		if err := s.RecordPair(context.Background(), mint()); err != ErrLoginSessionUnavailable {
			t.Fatalf("commit: %v", err)
		}
	})
	t.Run("cancelled after commit", func(t *testing.T) {
		s, d, mint := loginSessionsFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d.onCommit = cancel
		if err := s.RecordPair(ctx, mint()); err != ErrLoginSessionRejected {
			t.Fatalf("cancel: %v", err)
		}
	})
	t.Run("revoked rows do not exhaust live cap", func(t *testing.T) {
		s, d, mint := loginSessionsFixture(t)
		for i := 0; i < 256; i++ {
			d.rows[fmt.Sprint(i)] = loginSessionRow{expires: d.now.Add(time.Hour), revoked: true}
		}
		if err := s.RecordPair(context.Background(), mint()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLoginSessionsRejectInvalidTokenClaims(t *testing.T) {
	for _, kind := range []string{"jti", "iat", "exp", "user", "type", "signature", "algorithm"} {
		t.Run(kind, func(t *testing.T) {
			s, _, mint := loginSessionsFixture(t)
			p := mint()
			claims := jwt.MapClaims{"user_id": 42, "token_type": "access", "jti": "unique", "iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
			method := jwt.SigningMethodHS256
			secret := s.secret
			switch kind {
			case "jti", "iat", "exp":
				delete(claims, kind)
			case "user":
				claims["user_id"] = 43
			case "type":
				claims["token_type"] = "refresh"
			case "signature":
				secret = []byte(strings.Repeat("x", 32))
			case "algorithm":
				method = jwt.SigningMethodHS384
			}
			p.AccessToken, _ = jwt.NewWithClaims(method, claims).SignedString(secret)
			if err := s.RecordPair(context.Background(), p); err != ErrLoginSessionRejected {
				t.Fatalf("claims: %v", err)
			}
		})
	}
}
