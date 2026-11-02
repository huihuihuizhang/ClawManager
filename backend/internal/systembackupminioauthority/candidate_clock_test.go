package systembackupminioauthority

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Controlled-clock protocol fixture, not a replacement for the real D guard.
// Integration supplies its actual BootstrapSQL/BootstrapReadSQL; this model
// makes ANY raw clock SQL fail, retaining floor/failure state across samples.
type candidateClockModel struct {
	model                              *sqlSourceModel
	ctx                                context.Context
	base, floor                        time.Time
	calls, identities, rawClockQueries int
	regressAt, failAt                  int
	failed                             bool
}
type candidateClockConnector struct{ c *candidateClockModel }
type candidateClockConn struct {
	*sqlSourceConn
	c *candidateClockModel
}
type candidateClockView struct {
	*sql.Tx
	c *candidateClockModel
}

func (c candidateClockConnector) Driver() driver.Driver { return sqlSourceDriver{} }
func (c candidateClockConnector) Connect(context.Context) (driver.Conn, error) {
	return &candidateClockConn{sqlSourceConn: &sqlSourceConn{m: c.c.model}, c: c.c}, nil
}
func (c *candidateClockConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "UTC_TIMESTAMP") {
		c.c.rawClockQueries++
		return nil, errors.New("candidate raw clock SQL prohibited")
	}
	if q == `SELECT CURRENT_USER(),@@server_uuid,DATABASE()` {
		if ctx != c.c.ctx || c.c.failed || c.c.model.open != 1 {
			return nil, errors.New("wrong original guarded read")
		}
		c.c.identities++
		f := c.c.model.f
		return sqlSourceRow(f.pin.Target.ConsumerDatabaseAccount, f.pin.Target.ServerUUID, f.pin.Target.Database), nil
	}
	return c.sqlSourceConn.QueryContext(ctx, q, args)
}
func (v *candidateClockView) SampleTime(ctx context.Context) (time.Time, error) {
	c := v.c
	if c.failed || ctx != c.ctx || ctx.Err() != nil || c.model.open != 1 {
		c.failed = true
		return time.Time{}, errors.New("original clock failure latched")
	}
	c.calls++
	now := c.base.Add(time.Duration(c.calls) * time.Microsecond)
	if c.calls == c.regressAt {
		now = c.floor.Add(-time.Microsecond)
	}
	if c.calls == c.failAt || !c.floor.IsZero() && now.Before(c.floor) {
		c.failed = true
		return time.Time{}, errors.New("original clock failure latched")
	}
	c.floor = now
	return now, nil
}

func openCandidateClock(t *testing.T, regressAt, failAt int) (*candidateClockModel, *candidateClockView) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	c := &candidateClockModel{model: &sqlSourceModel{f: newSQLRecordFixture(t)}, ctx: ctx, base: time.Now().UTC().Truncate(time.Microsecond), regressAt: regressAt, failAt: failAt}
	db := sql.OpenDB(candidateClockConnector{c})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var username, role, provider string
	var active bool
	if e = tx.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, c.model.f.grant.Actor.LocalAdminUserID).Scan(&username, &role, &active, &provider); e != nil {
		t.Fatal(e)
	}
	return c, &candidateClockView{Tx: tx, c: c}
}

func TestMinIOSQLCandidateUsesOriginalControlledSampleTimeOnly(t *testing.T) {
	c, view := openCandidateClock(t, 0, 0)
	s, e := ReadSQLCurrentCandidate(c.ctx, view, c.model.f.pin)
	if e != nil {
		t.Fatal(e)
	}
	_, checked, e := s.Comparison()
	if e != nil || !checked.Equal(c.floor) || c.calls != 4 || c.identities != 2 || c.rawClockQueries != 0 || c.model.exclusiveLocks != 0 || c.model.writes != 0 || c.model.open != 1 {
		t.Fatal("candidate escaped original shared clock/read-only tx", e, c.calls, c.rawClockQueries)
	}
	// The ordinary entry also detects an actual controlled view; accidentally
	// selecting it must not reintroduce the old raw-clock query in candidates.
	if _, e = ReadSQLCurrent(c.ctx, view, c.model.f.pin); e != nil || c.rawClockQueries != 0 || c.calls != 8 {
		t.Fatal("controlled view fell back to raw UTC clock", e)
	}
}

func TestMinIOSQLCandidateClockRegressionAndFailureRemainLatched(t *testing.T) {
	for _, scenario := range []string{"regression-before-rows", "failure-before-rows", "failure-after-rows"} {
		t.Run(scenario, func(t *testing.T) {
			regressAt, failAt := 0, 0
			switch scenario {
			case "regression-before-rows":
				regressAt = 2
			case "failure-before-rows":
				failAt = 2
			case "failure-after-rows":
				failAt = 4
			}
			c, view := openCandidateClock(t, regressAt, failAt)
			if s, e := ReadSQLCurrentCandidate(c.ctx, view, c.model.f.pin); e == nil || s != nil || !c.failed || c.rawClockQueries != 0 || c.model.open != 1 {
				t.Fatal("controlled original clock failure became a valid source", e)
			}
			calls := c.calls
			if _, e := view.SampleTime(c.ctx); e == nil || c.calls != calls {
				t.Fatal("failed original clock was reset or renewed")
			}
			if _, e := ReadSQLCurrentCandidate(c.ctx, view, c.model.f.pin); e == nil || c.rawClockQueries != 0 {
				t.Fatal("failed source revived via raw fallback")
			}
		})
	}
}
