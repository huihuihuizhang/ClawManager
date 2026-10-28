package systembackupcatrust

// Real loopback TLS and temporary exact files; the SQL driver/policy are
// synthetic. These tests do not establish deployment permission or InnoDB locks.
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type candidateCAStateTest struct {
	now                         time.Time
	server, database            string
	queries, commits, rollbacks int
	afterIdentity               func()
	rollbackDone                chan struct{}
}
type candidateCAConnector struct{ state *candidateCAStateTest }

func (c candidateCAConnector) Driver() driver.Driver { return candidateCADriver{} }
func (c candidateCAConnector) Connect(context.Context) (driver.Conn, error) {
	return &candidateCAConn{c.state}, nil
}

type candidateCADriver struct{}

func (candidateCADriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type candidateCAConn struct{ s *candidateCAStateTest }

func (*candidateCAConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected CA prepare")
}
func (*candidateCAConn) Close() error                { return nil }
func (c *candidateCAConn) Begin() (driver.Tx, error) { return &candidateCATx{c.s}, nil }
func (c *candidateCAConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type candidateCATx struct{ s *candidateCAStateTest }

func (t *candidateCATx) Commit() error { t.s.commits++; return nil }
func (t *candidateCATx) Rollback() error {
	t.s.rollbacks++
	if t.s.rollbackDone != nil {
		close(t.s.rollbackDone)
	}
	return nil
}

type candidateCARows struct {
	v    []driver.Value
	done bool
}

func (r *candidateCARows) Columns() []string {
	out := make([]string, len(r.v))
	for i := range out {
		out[i] = fmt.Sprint(i)
	}
	return out
}
func (*candidateCARows) Close() error { return nil }
func (r *candidateCARows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.v)
	return nil
}
func (c *candidateCAConn) QueryContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.s.queries++
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return &candidateCARows{v: []driver.Value{c.s.server, c.s.database, c.s.now, int64(0)}}, nil
	case "SELECT UTC_TIMESTAMP(6)":
		return &candidateCARows{v: []driver.Value{c.s.now}}, nil
	case "SELECT @@server_uuid,DATABASE()":
		if c.s.afterIdentity != nil {
			c.s.afterIdentity()
		}
		return &candidateCARows{v: []driver.Value{c.s.server, c.s.database}}, nil
	}
	return nil, errors.New("unexpected CA SQL")
}

type candidateCASyntheticPolicy struct{ deadline time.Time }

func (p candidateCASyntheticPolicy) LockAndAuthorize(context.Context, pd.SQL, pd.Scope) (pd.GuardPlan, error) {
	return pd.GuardPlan{BindingHash: pd.Hash(strings.Repeat("a", 64)), Deadlines: []time.Time{p.deadline}}, nil
}
func (candidateCASyntheticPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func candidateCAPrepared(t *testing.T, contexts ...context.Context) (fixture, *PreparedCandidateCA) {
	t.Helper()
	f := newFixture(t, false)
	*f.clock = f.clock.UTC().Truncate(time.Microsecond)
	ctx := context.Background()
	if len(contexts) != 0 {
		ctx = contexts[0]
	}
	p, err := f.v.PrepareCandidateAttempt(ctx, f.grant, f.config)
	if err != nil || p == nil || p.DependencyDeadline() == nil {
		t.Fatal("original TLS preparation", err)
	}
	return f, p
}
func candidateCAGuard(t *testing.T, f fixture, p *PreparedCandidateCA, s *candidateCAStateTest, work func(context.Context, *pd.Transaction) error) error {
	t.Helper()
	s.rollbackDone = make(chan struct{})
	db := sql.OpenDB(candidateCAConnector{s})
	defer db.Close()
	ctx := p.state.ctx
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	deadline, err := p.DependencyDeadline().Time()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := pd.NewTransactions(db, pd.Scope{ServerUUID: pd.ServerUUID(f.grant.ServerUUID), Database: pd.Database(f.grant.Database), Installation: pd.Installation(f.grant.InstallationID)}, candidateCASyntheticPolicy{deadline})
	if err != nil {
		t.Fatal(err)
	}
	err = runner.GuardInTx(ctx, tx, work)
	if err != nil {
		tx.Rollback()
		// BeginTx's ctx may have started background rollback; wait for the
		// driver before inspecting completion counters.
		select {
		case <-s.rollbackDone:
		case <-time.After(5 * time.Second):
			t.Fatal("CA rollback did not finish")
		}
		return err
	}
	return tx.Commit()
}

func TestCandidateCAUsesOriginalTLSAndCurrentFilesWithoutAnotherNetworkCall(t *testing.T) {
	for _, mode := range []string{"normal", "removed_CA", "changed_CA", "removed_descriptor", "changed_descriptor", "late_removed_CA", "late_changed_descriptor", "late_SQL_expiry", "late_SQL_rollback", "late_canceled", "wrong_database"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f, p := candidateCAPrepared(t, ctx)
			f.server.Close()
			f.v.now = func() time.Time { t.Fatal("late wall-clock callback"); return time.Time{} }
			s := &candidateCAStateTest{now: *f.clock, server: f.grant.ServerUUID, database: f.grant.Database}
			mutate := func() {
				var err error
				switch mode {
				case "removed_CA", "late_removed_CA":
					err = os.Remove(f.v.binding.CAFile)
				case "changed_CA":
					err = os.WriteFile(f.v.binding.CAFile, []byte("PRIVATE changed CA"), 0600)
				case "removed_descriptor":
					err = os.Remove(f.v.binding.DescriptorFile)
				case "changed_descriptor", "late_changed_descriptor":
					err = os.WriteFile(f.v.binding.DescriptorFile, []byte(`{}`), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if !strings.HasPrefix(mode, "late_") {
				mutate()
			}
			var check *CandidateCACheck
			err := candidateCAGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
				if mode == "wrong_database" {
					s.database = "other"
				}
				var err error
				check, err = p.CheckCandidate(ctx, tx)
				if err != nil {
					return err
				}
				if strings.HasPrefix(mode, "late_") {
					mutate()
				}
				if mode == "late_SQL_expiry" {
					s.afterIdentity = func() { s.now = p.state.expires }
				}
				if mode == "late_SQL_rollback" {
					s.afterIdentity = func() { s.now = s.now.Add(-time.Microsecond) }
				}
				if mode == "late_canceled" {
					s.afterIdentity = cancel
				}
				return check.Recheck(ctx, tx)
			})
			if mode == "normal" {
				if err != nil || s.commits != 1 {
					t.Fatal("original files rejected", err)
				}
			} else if err == nil || s.commits != 0 || s.rollbacks != 1 {
				t.Fatal("changed/stale material committed", mode, err, s)
			}
			if f.handshakes.Load() != 1 {
				t.Fatal("late resource check repeated TLS")
			}
			before := s.queries
			if check != nil && check.Recheck(p.state.ctx, check.tx) == nil {
				t.Fatal("closed write capability reused")
			}
			if _, err := p.CheckCandidate(p.state.ctx, nil); err == nil || s.queries != before {
				t.Fatal("prepared one-shot resource reused")
			}
		})
	}
}

func TestCandidateCAAttemptDefersOnlyPhysicalFailureWithoutPermissionOrDeadline(t *testing.T) {
	for _, mode := range []string{"missing_CA", "wrong_CA_bytes", "missing_descriptor", "expired_leaf", "wrong_hostname", "expired_original_window"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, mode == "expired_leaf")
			*f.clock = f.clock.UTC().Truncate(time.Microsecond)
			switch mode {
			case "missing_CA":
				if err := os.Remove(f.v.binding.CAFile); err != nil {
					t.Fatal(err)
				}
			case "wrong_CA_bytes":
				if err := os.WriteFile(f.v.binding.CAFile, []byte("wrong"), 0600); err != nil {
					t.Fatal(err)
				}
				f.v.binding.CASHA256 = sum([]byte("wrong"))
			case "missing_descriptor":
				if err := os.Remove(f.v.binding.DescriptorFile); err != nil {
					t.Fatal(err)
				}
			case "wrong_hostname":
				f.v.host = "other.invalid"
			case "expired_original_window":
				*f.clock = f.v.binding.ExpiresAt
			}
			p, err := f.v.PrepareCandidateAttempt(context.Background(), f.grant, f.config)
			if err != nil || p == nil || p.DependencyDeadline() != nil {
				t.Fatal("resource failure converted to usable observation", err)
			}
			if checked, err := p.CheckCandidate(context.Background(), nil); err == nil || checked != nil {
				t.Fatal("closed resource failure authorized new use")
			}
		})
	}
	for _, mode := range []string{"wrong_scope", "wrong_config", "zero_config", "nil_context", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, false)
			g, c, ctx := f.grant, f.config, context.Background()
			switch mode {
			case "wrong_scope":
				g.InstallationID += "_other"
			case "wrong_config":
				g.ConfigSHA256 = strings.Repeat("a", 64)
			case "zero_config":
				c = sec.BootstrapConfig{}
			case "nil_context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if p, err := f.v.PrepareCandidateAttempt(ctx, g, c); err == nil || p != nil || f.handshakes.Load() != 0 {
				t.Fatal("input/authority scope error deferred", err)
			}
		})
	}
}

func TestCandidateCAOriginalDeadlineOwnershipContextAndRedaction(t *testing.T) {
	f, p := candidateCAPrepared(t)
	original := *p.DependencyDeadline()
	borrowed := p.DependencyDeadline()
	*borrowed = pd.Timestamp("9999-12-31T23:59:59.000000Z")
	if *p.DependencyDeadline() != original {
		t.Fatal("caller extended private original deadline")
	}
	for _, v := range []any{p, *p, &CandidateCACheck{state: p.state}, CandidateCACheck{state: p.state}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, f.v.binding.CAFile) || strings.Contains(out, f.v.binding.CASHA256) || strings.Contains(out, f.v.binding.Endpoint) {
				t.Fatal("material pins formatted")
			}
		}
		if raw, err := json.Marshal(v); err == nil || len(raw) != 0 {
			t.Fatal("material pins serialized")
		}
	}
	var prepared PreparedCandidateCA
	var checked CandidateCACheck
	if json.Unmarshal([]byte(`{}`), &prepared) == nil || json.Unmarshal([]byte(`{}`), &checked) == nil {
		t.Fatal("JSON manufactured material observation")
	}
	s := &candidateCAStateTest{now: *f.clock, server: f.grant.ServerUUID, database: f.grant.Database}
	err := candidateCAGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
		before := s.queries
		other := context.WithValue(ctx, struct{}{}, "other")
		if check, err := p.CheckCandidate(other, tx); err == nil || check != nil || s.queries != before {
			t.Fatal("wrong context reached file/SQL checks")
		}
		if _, err := p.CheckCandidate(ctx, tx); err == nil {
			t.Fatal("failed context binding renewed one-shot")
		}
		return sec.ErrRegistrationUnavailable
	})
	if err == nil || s.commits != 0 {
		t.Fatal("wrong context observation committed")
	}
	for _, fraction := range []int{0, 1, 999} {
		raw := time.Date(2026, 10, 26, 1, 0, 0, fraction, time.FixedZone("original offset", 90*60))
		prepared := &PreparedCandidateCA{state: &candidateCAState{ready: true, expires: raw}}
		stamp := prepared.DependencyDeadline()
		if stamp == nil {
			t.Fatal("raw deadline lost")
		}
		got, err := stamp.Time()
		want := raw.UTC().Truncate(time.Microsecond)
		if fraction != 0 {
			want = want.Add(time.Microsecond)
		}
		if err != nil || !got.Equal(want) {
			t.Fatal("fractional original deadline floored", got, err)
		}
	}
}
