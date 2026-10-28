package systembackupnoncebootstrap

// Exact temporary material files and the real D transaction capability, with a
// synthetic SQL driver/policy. This does not prove InnoDB rows/gaps or authority.
import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type candidateNonceSQLState struct {
	now                time.Time
	server, database   string
	configs, retained  [][]driver.Value
	queries            []string
	cutoffs            []time.Time
	commits, rollbacks int
	afterIdentity      func()
	rollbackDone       chan struct{}
}
type candidateNonceConnector struct{ s *candidateNonceSQLState }

func (c candidateNonceConnector) Driver() driver.Driver { return candidateNonceDriver{} }
func (c candidateNonceConnector) Connect(context.Context) (driver.Conn, error) {
	return &candidateNonceConn{c.s}, nil
}

type candidateNonceDriver struct{}

func (candidateNonceDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}

type candidateNonceConn struct{ s *candidateNonceSQLState }

func (*candidateNonceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected nonce prepare")
}
func (*candidateNonceConn) Close() error                { return nil }
func (c *candidateNonceConn) Begin() (driver.Tx, error) { return &candidateNonceTx{c.s}, nil }
func (c *candidateNonceConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type candidateNonceTx struct{ s *candidateNonceSQLState }

func (t *candidateNonceTx) Commit() error { t.s.commits++; return nil }
func (t *candidateNonceTx) Rollback() error {
	t.s.rollbacks++
	if t.s.rollbackDone != nil {
		close(t.s.rollbackDone)
	}
	return nil
}
func (c *candidateNonceConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s := c.s
	s.queries = append(s.queries, q)
	switch q {
	case "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return &rows{values: [][]driver.Value{{s.server, s.database, s.now, int64(0)}}, columns: []string{"server", "db", "now", "offset"}}, nil
	case "SELECT UTC_TIMESTAMP(6)":
		return &rows{values: [][]driver.Value{{s.now}}, columns: []string{"now"}}, nil
	case "SELECT @@server_uuid,DATABASE()":
		if s.afterIdentity != nil {
			s.afterIdentity()
		}
		return &rows{values: [][]driver.Value{{s.server, s.database}}, columns: []string{"server", "db"}}, nil
	case candidateNonceConfigSQL:
		if len(args) != 0 {
			return nil, errors.New("global config unexpectedly filtered")
		}
		return &rows{values: append([][]driver.Value(nil), s.configs...), columns: []string{"id", "installation", "version", "config", "enabled", "key_version", "identity"}}, nil
	case candidateNonceRetainedSQL:
		if len(args) != 1 {
			return nil, errors.New("wrong retained cutoff")
		}
		cutoff, ok := args[0].Value.(time.Time)
		if !ok {
			return nil, errors.New("not original cutoff")
		}
		s.cutoffs = append(s.cutoffs, cutoff)
		filtered := [][]driver.Value{}
		for _, row := range s.retained {
			if until, ok := row[2].(time.Time); ok && !until.After(cutoff) {
				continue
			}
			filtered = append(filtered, row)
		}
		return &rows{values: filtered, columns: []string{"id", "version", "until"}}, nil
	}
	return nil, errors.New("unexpected nonce SQL")
}

type candidateNonceSyntheticPolicy struct{ p *PreparedCandidateNonce }

func (p candidateNonceSyntheticPolicy) LockAndAuthorize(ctx context.Context, tx pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	// Record the REQUIRED earlier global config prefix; this fake driver cannot
	// prove actual locking. Deliberately do not validate foreign resource values
	// here: L3 historical reads must precede new-use resource validation.
	r, err := tx.QueryContext(ctx, candidateNonceConfigSQL)
	if err != nil {
		return pd.GuardPlan{}, err
	}
	for r.Next() {
		var a, b, c, d, f, g string
		var e bool
		if err = r.Scan(&a, &b, &c, &d, &e, &f, &g); err != nil {
			r.Close()
			return pd.GuardPlan{}, err
		}
	}
	if err = r.Err(); err != nil {
		r.Close()
		return pd.GuardPlan{}, err
	}
	if err = r.Close(); err != nil {
		return pd.GuardPlan{}, err
	}
	deadline, err := p.p.DependencyDeadline().Time()
	if err != nil {
		return pd.GuardPlan{}, err
	}
	return pd.GuardPlan{BindingHash: pd.Hash(strings.Repeat("a", 64)), Deadlines: []time.Time{deadline}}, nil
}
func (candidateNonceSyntheticPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func candidateNoncePrepared(t *testing.T, contexts ...context.Context) (fixture, *PreparedCandidateNonce, *candidateNonceSQLState) {
	t.Helper()
	f := setup(t)
	*f.clock = f.clock.UTC().Truncate(time.Microsecond)
	ctx := context.Background()
	if len(contexts) != 0 {
		ctx = contexts[0]
	}
	p, err := f.v.PrepareCandidateAttempt(ctx, f.g, f.c)
	if err != nil || p == nil || p.DependencyDeadline() == nil {
		t.Fatal(err)
	}
	s := &candidateNonceSQLState{now: *f.clock, server: f.g.ServerUUID, database: f.g.Database,
		configs:  [][]driver.Value{{int64(1), "installation_foreign", int64(7), "original_foreign_config", false, f.active.Version, f.active.IdentityHash}},
		retained: [][]driver.Value{{int64(1), "retained-v0", f.clock.Add(30 * time.Minute)}, {int64(2), "retained-v0", f.clock.Add(45 * time.Minute)}}}
	return f, p, s
}
func candidateNonceNewConfig(f fixture, s *candidateNonceSQLState) {
	s.configs = append(s.configs, []driver.Value{int64(99), f.g.InstallationID, int64(1), f.g.ConfigSHA256, false, f.active.Version, f.active.IdentityHash})
}
func candidateNonceGuard(t *testing.T, f fixture, p *PreparedCandidateNonce, s *candidateNonceSQLState, work func(context.Context, *pd.Transaction) error) error {
	t.Helper()
	s.rollbackDone = make(chan struct{})
	db := sql.OpenDB(candidateNonceConnector{s})
	defer db.Close()
	ctx := p.state.ctx
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	runner, err := pd.NewTransactions(db, pd.Scope{ServerUUID: pd.ServerUUID(f.g.ServerUUID), Database: pd.Database(f.g.Database), Installation: pd.Installation(f.g.InstallationID)}, candidateNonceSyntheticPolicy{p})
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.GuardInTx(ctx, tx, work); err != nil {
		tx.Rollback()
		select {
		case <-s.rollbackDone:
		case <-time.After(5 * time.Second):
			t.Fatal("nonce rollback did not finish")
		}
		return err
	}
	return tx.Commit()
}

func TestCandidateNonceGlobalSourcesAndOriginalCurrentMaterials(t *testing.T) {
	for _, mode := range []string{"normal", "unknown_foreign_config", "conflicting_foreign_identity", "unknown_retained", "retention_too_long", "null_retention", "removed_active", "removed_retained", "changed_active", "changed_retained", "changed_descriptor", "late_removed_retained", "late_changed_descriptor", "wrong_database", "late_SQL_expiry", "late_SQL_rollback", "late_canceled", "caller_binding_mutated"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f, p, s := candidateNoncePrepared(t, ctx)
			keys := append([]Key(nil), f.v.binding.Keys...)
			f.v.now = func() time.Time { t.Fatal("late material check called wall clock"); return time.Time{} }
			mutate := func() {
				var err error
				switch mode {
				case "removed_active":
					err = os.Remove(keys[0].MaterialFile)
				case "removed_retained", "late_removed_retained":
					err = os.Remove(keys[1].MaterialFile)
				case "changed_active":
					err = os.WriteFile(keys[0].MaterialFile, bytes.Repeat([]byte{9}, 32), 0600)
				case "changed_retained":
					err = os.WriteFile(keys[1].MaterialFile, bytes.Repeat([]byte{9}, 32), 0600)
				case "changed_descriptor", "late_changed_descriptor":
					err = os.WriteFile(keys[1].DescriptorFile, []byte(`{}`), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "unknown_foreign_config":
				s.configs[0][5] = "unknown-version"
			case "conflicting_foreign_identity":
				s.configs[0][6] = strings.Repeat("e", 64)
			case "unknown_retained":
				s.retained[0][1] = "unknown-version"
			case "retention_too_long":
				s.retained[1][2] = f.clock.Add(2 * time.Hour)
			case "null_retention":
				s.retained[0][2] = nil
			case "caller_binding_mutated":
				f.v.binding.Keys[0].MaterialFile = "PRIVATE caller replacement"
			}
			if !strings.HasPrefix(mode, "late_") {
				mutate()
			}
			var checked *CandidateNonceCheck
			err := candidateNonceGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
				if mode == "wrong_database" {
					s.database = "other"
				}
				var err error
				checked, err = p.LockReferences(ctx, tx)
				if err != nil {
					return err
				}
				candidateNonceNewConfig(f, s)
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
				return checked.Recheck(ctx, tx)
			})
			positive := mode == "normal" || mode == "caller_binding_mutated"
			if positive {
				if err != nil || s.commits != 1 {
					t.Fatal("original global source refused", err)
				}
			} else if err == nil || s.commits != 0 || s.rollbacks != 1 {
				t.Fatal("invalid material/global state committed", mode, err)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("material diagnostics escaped")
			}
			before := len(s.queries)
			if checked != nil && checked.Recheck(p.state.ctx, checked.tx) == nil {
				t.Fatal("closed transaction reused")
			}
			if _, err := p.LockReferences(p.state.ctx, nil); err == nil || len(s.queries) != before {
				t.Fatal("prepared resource reused")
			}
		})
	}
}

func TestCandidateNonceFinalGlobalSetAllowsOnlyIntendedDisabledConfig(t *testing.T) {
	for _, mode := range []string{"missing_new", "extra_new", "wrong_new_nonce", "new_enabled", "foreign_hash_changed", "foreign_removed", "foreign_added", "retention_shortened", "retention_extended"} {
		t.Run(mode, func(t *testing.T) {
			f, p, s := candidateNoncePrepared(t)
			err := candidateNonceGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
				checked, err := p.LockReferences(ctx, tx)
				if err != nil {
					return err
				}
				if mode != "missing_new" {
					candidateNonceNewConfig(f, s)
				}
				switch mode {
				case "extra_new":
					candidateNonceNewConfig(f, s)
				case "wrong_new_nonce":
					s.configs[len(s.configs)-1][5] = "retained-v0"
					s.configs[len(s.configs)-1][6] = f.v.binding.Keys[1].IdentityHash
				case "new_enabled":
					s.configs[len(s.configs)-1][4] = true
				case "foreign_hash_changed":
					s.configs[0][3] = "unauthorized_foreign_change"
				case "foreign_removed":
					s.configs = s.configs[1:]
				case "foreign_added":
					s.configs = append([][]driver.Value{{int64(2), "installation_foreign_added", int64(1), "foreign_extra", false, f.active.Version, f.active.IdentityHash}}, s.configs...)
				case "retention_shortened":
					s.retained[1][2] = f.clock.Add(40 * time.Minute)
				case "retention_extended":
					s.retained[1][2] = f.clock.Add(50 * time.Minute)
				}
				return checked.Recheck(ctx, tx)
			})
			if err == nil || s.commits != 0 {
				t.Fatal("unexpected global post-state accepted", mode)
			}
		})
	}
}

func TestCandidateNonceStreamsDuplicateRowsAndRetainsOriginalCutoff(t *testing.T) {
	f, p, s := candidateNoncePrepared(t)
	// Legacy UNION produces one config tuple and one retained MAX, despite more
	// than 20,000 raw duplicates. A new raw-row cap would reject lawful input.
	for i := 0; i < 20001; i++ {
		s.configs = append(s.configs, []driver.Value{int64(i + 2), "installation_foreign", int64(i + 8), "original_foreign_config", false, f.active.Version, f.active.IdentityHash})
		s.retained = append(s.retained, []driver.Value{int64(i + 3), "retained-v0", f.clock.Add(30 * time.Minute)})
	}
	// Already-expired unknown keys were excluded by the ORIGINAL WHERE cutoff.
	s.retained = append(s.retained, []driver.Value{int64(99999), "expired-unknown", *f.clock})
	err := candidateNonceGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
		checked, err := p.LockReferences(ctx, tx)
		if err != nil {
			return err
		}
		candidateNonceNewConfig(f, s)
		s.now = s.now.Add(2 * time.Microsecond)
		return checked.Recheck(ctx, tx)
	})
	if err != nil || s.commits != 1 || len(s.cutoffs) != 2 || !s.cutoffs[0].Equal(s.cutoffs[1]) || !s.cutoffs[0].Equal(*f.clock) {
		t.Fatal("duplicate semantics/cutoff changed", err, s.cutoffs)
	}
	if len(s.queries) < 3 || s.queries[1] != candidateNonceConfigSQL {
		t.Fatal("missing earlier global config prefix")
	}
}

func TestCandidateNonceAttemptFailureContextDeadlineAndRedaction(t *testing.T) {
	for _, mode := range []string{"missing_active", "missing_retained", "wrong_length", "changed_descriptor", "expired_mapping"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			switch mode {
			case "missing_active":
				if err := os.Remove(f.v.binding.Keys[0].MaterialFile); err != nil {
					t.Fatal(err)
				}
			case "missing_retained":
				if err := os.Remove(f.v.binding.Keys[1].MaterialFile); err != nil {
					t.Fatal(err)
				}
			case "wrong_length":
				if err := os.WriteFile(f.v.binding.Keys[1].MaterialFile, make([]byte, 31), 0600); err != nil {
					t.Fatal(err)
				}
				f.v.binding.Keys[1].MaterialSHA256 = hash(make([]byte, 31))
			case "changed_descriptor":
				if err := os.WriteFile(f.v.binding.Keys[0].DescriptorFile, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired_mapping":
				*f.clock = f.v.binding.ExpiresAt
			}
			p, err := f.v.PrepareCandidateAttempt(context.Background(), f.g, f.c)
			if err != nil || p == nil || p.DependencyDeadline() != nil {
				t.Fatal("physical failure became authority/deadline", err)
			}
			if checked, err := p.LockReferences(context.Background(), nil); err == nil || checked != nil {
				t.Fatal("failed resource reached SQL/new use")
			}
		})
	}
	for _, mode := range []string{"scope", "config", "zero_config", "nil_context", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			g, c, ctx := f.g, f.c, context.Background()
			switch mode {
			case "scope":
				g.InstallationID += "_other"
			case "config":
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
			if p, err := f.v.PrepareCandidateAttempt(ctx, g, c); err == nil || p != nil {
				t.Fatal("scope/ctx error incorrectly deferred")
			}
		})
	}
	f, p, s := candidateNoncePrepared(t)
	original := *p.DependencyDeadline()
	changed := p.DependencyDeadline()
	*changed = pd.Timestamp("9999-12-31T23:59:59.000000Z")
	if *p.DependencyDeadline() != original {
		t.Fatal("original dependency deadline extended")
	}
	for _, value := range []any{p, *p, &CandidateNonceCheck{state: p.state}, CandidateNonceCheck{state: p.state}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, f.v.binding.Keys[0].MaterialFile) || strings.Contains(out, f.v.binding.Keys[0].MaterialSHA256) {
				t.Fatal("material mapping formatted")
			}
		}
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("material mapping serialized")
		}
	}
	var prepared PreparedCandidateNonce
	var checked CandidateNonceCheck
	if json.Unmarshal([]byte(`{}`), &prepared) == nil || json.Unmarshal([]byte(`{}`), &checked) == nil {
		t.Fatal("JSON manufactured material state")
	}
	err := candidateNonceGuard(t, f, p, s, func(ctx context.Context, tx *pd.Transaction) error {
		before := len(s.queries)
		other := context.WithValue(ctx, struct{}{}, "other")
		if checked, err := p.LockReferences(other, tx); err == nil || checked != nil || len(s.queries) != before {
			t.Fatal("wrong ctx reached material/SQL work")
		}
		if _, err := p.LockReferences(ctx, tx); err == nil {
			t.Fatal("failed binding renewed once state")
		}
		return sec.ErrRegistrationUnavailable
	})
	if err == nil || s.commits != 0 {
		t.Fatal("invalid context committed")
	}
}
