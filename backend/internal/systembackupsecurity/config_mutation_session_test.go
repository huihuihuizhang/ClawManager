package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Model SQL tests exercise current row changes, binding and caller ownership;
// they do not substitute for the separately gated MySQL locking acceptance.
type mutationSessionDB struct {
	loginSessionDB
	queries []string
	failAt  int
}
type mutationSessionConnector struct{ s *mutationSessionDB }

func (c mutationSessionConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mutationSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &mutationSessionConn{loginSessionConn{&c.s.loginSessionDB}, c.s}, nil
}

type mutationSessionConn struct {
	loginSessionConn
	s *mutationSessionDB
}

func (c *mutationSessionConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries = append(c.s.queries, q)
	if c.s.failAt == len(c.s.queries) {
		return nil, errors.New("PRIVATE session SQL failure")
	}
	if strings.HasPrefix(q, "SELECT password_hash FROM users") && (len(args) != 1 || args[0].Value != int64(42)) {
		return nil, errors.New("wrong user lock")
	}
	if strings.HasPrefix(q, "SELECT user_id,subject,credential_hash") && (len(args) != 2 || args[0].Value != "installation_sessions" || args[1].Value != strings.Repeat("a", 64)) {
		return nil, errors.New("wrong session scope")
	}
	if strings.HasPrefix(q, "SELECT revoked_before") && (len(args) != 2 || args[0].Value != "installation_sessions" || args[1].Value != int64(42)) {
		return nil, errors.New("wrong revocation scope")
	}
	if strings.HasPrefix(q, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF") {
		return registrationRow(c.s.finalNow, c.s.offset), nil
	}
	return c.loginSessionConn.QueryContext(ctx, q, args)
}
func (c *mutationSessionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.writes++
	return nil, errors.New("session check must not write")
}

type mutationSessionFixture struct {
	s            *SQLLoginSessions
	model        *mutationSessionDB
	actor        RegistrationActor
	tx           *sql.Tx
	ctx          context.Context
	installation string
	notBefore    time.Time
}

func newMutationSessionFixture(t *testing.T) *mutationSessionFixture {
	t.Helper()
	now := time.Date(2026, 10, 15, 1, 30, 0, 0, time.UTC)
	a := RegistrationActor{UserID: 42, Subject: "user:42", Session: strings.Repeat("a", 64), SessionIssuedAt: now.Add(-time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
	m := &mutationSessionDB{loginSessionDB: loginSessionDB{now: now, finalNow: now, password: "current-password-hash", role: "admin", server: "11111111-2222-3333-4444-555555555555", active: true,
		rows: map[string]loginSessionRow{a.Session: {user: a.UserID, subject: a.Subject, credential: registrationHash("current-password-hash"), expires: a.SessionExpiresAt}}}}
	db := sql.OpenDB(mutationSessionConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := NewSQLLoginSessions(db, DatabaseIdentity{ServerUUID: m.server, Database: "synthetic"}, "installation_sessions", []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return &mutationSessionFixture{s, m, a, tx, context.Background(), "installation_sessions", now}
}
func (f *mutationSessionFixture) check() error {
	return f.s.CheckConfigMutationSession(f.ctx, f.tx, f.installation, f.actor, f.notBefore)
}
func (f *mutationSessionFixture) session(edit func(*loginSessionRow)) {
	row := f.model.pending[f.actor.Session]
	edit(&row)
	f.model.pending[f.actor.Session] = row
}

func TestConfigMutationSQLSessionUsesCurrentRowsAndFreshClock(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*mutationSessionFixture)
		want error
	}{
		{"active", func(*mutationSessionFixture) {}, nil},
		{"longer-db-session", func(f *mutationSessionFixture) {
			f.session(func(r *loginSessionRow) { r.expires = r.expires.Add(time.Hour) })
		}, nil},
		{"old-revocation", func(f *mutationSessionFixture) {
			v := f.actor.SessionIssuedAt.Add(-time.Microsecond)
			f.model.revokedBefore = &v
		}, nil},
		{"inactive", func(f *mutationSessionFixture) { f.model.active = false }, ErrRegistrationPermission},
		{"demoted-business-role", func(f *mutationSessionFixture) { f.model.role = "user" }, ErrRegistrationPermission},
		{"password-changed", func(f *mutationSessionFixture) { f.model.password = "new-password-hash" }, ErrRegistrationPermission},
		{"session-missing", func(f *mutationSessionFixture) { delete(f.model.pending, f.actor.Session) }, ErrRegistrationPermission},
		{"session-revoked", func(f *mutationSessionFixture) { f.session(func(r *loginSessionRow) { r.revoked = true }) }, ErrRegistrationPermission},
		{"session-user-mismatch", func(f *mutationSessionFixture) { f.session(func(r *loginSessionRow) { r.user++ }) }, ErrRegistrationPermission},
		{"session-subject-mismatch", func(f *mutationSessionFixture) { f.session(func(r *loginSessionRow) { r.subject = "user:7" }) }, ErrRegistrationPermission},
		{"session-expired", func(f *mutationSessionFixture) { f.session(func(r *loginSessionRow) { r.expires = f.notBefore }) }, ErrRegistrationPermission},
		{"session-shortened-but-live", func(f *mutationSessionFixture) {
			f.session(func(r *loginSessionRow) { r.expires = f.actor.SessionExpiresAt.Add(-time.Microsecond) })
		}, ErrRegistrationPermission},
		{"revoked-at-issue", func(f *mutationSessionFixture) { v := f.actor.SessionIssuedAt; f.model.revokedBefore = &v }, ErrRegistrationPermission},
		{"revoked-after-issue", func(f *mutationSessionFixture) {
			v := f.actor.SessionIssuedAt.Add(time.Microsecond)
			f.model.revokedBefore = &v
		}, ErrRegistrationPermission},
		{"invalid-revocation-row", func(f *mutationSessionFixture) { v := time.Time{}; f.model.revokedBefore = &v }, ErrRegistrationUnavailable},
		{"clock-expired-after-row-check", func(f *mutationSessionFixture) { f.model.finalNow = f.actor.SessionExpiresAt }, ErrRegistrationPermission},
		{"clock-backward", func(f *mutationSessionFixture) { f.model.finalNow = f.notBefore.Add(-time.Microsecond) }, ErrRegistrationUnavailable},
		{"non-utc-connection", func(f *mutationSessionFixture) { f.model.offset = 1 }, ErrRegistrationUnavailable},
		{"zero-clock", func(f *mutationSessionFixture) { f.model.finalNow = time.Time{} }, ErrRegistrationUnavailable},
		{"foreign-server", func(f *mutationSessionFixture) { f.model.server = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }, ErrRegistrationUnavailable},
		{"foreign-database", func(f *mutationSessionFixture) { f.s.identity.Database = "foreign" }, ErrRegistrationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMutationSessionFixture(t)
			tc.edit(f)
			if err := f.check(); !errors.Is(err, tc.want) {
				t.Fatal("session decision", err, "want", tc.want)
			}
			if f.model.writes != 0 || f.model.commits != 0 {
				t.Fatal("session check changed caller transaction")
			}
			if tc.want == nil {
				if len(f.model.queries) != 5 || !strings.Contains(f.model.queries[1], "users") || !strings.Contains(f.model.queries[2], "admin_sessions") || !strings.Contains(f.model.queries[3], "admin_revocations") || !strings.Contains(f.model.queries[4], "TIMESTAMPDIFF") {
					t.Fatal("live locks and final UTC check required", f.model.queries)
				}
			}
		})
	}
}

func TestConfigMutationSQLSessionRejectsInvalidBoundaryAndPrivateFailures(t *testing.T) {
	for name, edit := range map[string]func(*mutationSessionFixture){
		"nil-source":              func(f *mutationSessionFixture) { f.s = nil },
		"nil-context":             func(f *mutationSessionFixture) { f.ctx = nil },
		"canceled-context":        func(f *mutationSessionFixture) { c, cancel := context.WithCancel(f.ctx); cancel(); f.ctx = c },
		"nil-tx":                  func(f *mutationSessionFixture) { f.tx = nil },
		"foreign-installation":    func(f *mutationSessionFixture) { f.installation = "installation_foreign" },
		"zero-boundary":           func(f *mutationSessionFixture) { f.notBefore = time.Time{} },
		"invalid-source-identity": func(f *mutationSessionFixture) { f.s.identity = DatabaseIdentity{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newMutationSessionFixture(t)
			edit(f)
			if err := f.check(); err != ErrRegistrationUnavailable || len(f.model.queries) != 0 {
				t.Fatal("invalid boundary reached SQL", err)
			}
		})
	}
	for name, edit := range map[string]func(*RegistrationActor){
		"user":             func(a *RegistrationActor) { a.UserID = 0 },
		"subject":          func(a *RegistrationActor) { a.Subject = "user:7" },
		"session":          func(a *RegistrationActor) { a.Session = "raw-jwt-is-not-a-session-pin" },
		"issue-missing":    func(a *RegistrationActor) { a.SessionIssuedAt = time.Time{} },
		"issued-in-future": func(a *RegistrationActor) { a.SessionIssuedAt = a.SessionExpiresAt.Add(-time.Second) },
		"expiry-missing":   func(a *RegistrationActor) { a.SessionExpiresAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newMutationSessionFixture(t)
			edit(&f.actor)
			if err := f.check(); err != ErrRegistrationPermission || len(f.model.queries) != 0 {
				t.Fatal("unauthenticated actor reached SQL", err)
			}
		})
	}
	for phase := 1; phase <= 5; phase++ {
		f := newMutationSessionFixture(t)
		f.model.failAt = phase
		if err := f.check(); err != ErrRegistrationUnavailable {
			t.Fatal("storage failure leaked or admitted", phase, err)
		}
	}
}

func TestConfigMutationSQLSessionRechecksRevocationOnSameTransaction(t *testing.T) {
	f := newMutationSessionFixture(t)
	if err := f.check(); err != nil {
		t.Fatal(err)
	}
	f.session(func(r *loginSessionRow) { r.revoked = true })
	if err := f.check(); err != ErrRegistrationPermission {
		t.Fatal("memoized current session authorization", err)
	}
	if f.model.commits != 0 || f.model.writes != 0 {
		t.Fatal("helper committed or wrote")
	}
}
