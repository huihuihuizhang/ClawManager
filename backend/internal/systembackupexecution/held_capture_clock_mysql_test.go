package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
	"database/sql/driver"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real SQL/current authority with delayed delivery of one actual fact row.
// Delays are transport observations, not fabricated time or authorization.
type dHeldClockDelay struct {
	armed, fired   atomic.Bool
	ownerFacts     bool
	initialFacts   bool
	heldOwnerFacts bool
	identityField  string
	duration       time.Duration
}
type dHeldClockConnector struct {
	driver.Connector
	delay *dHeldClockDelay
}

func (c dHeldClockConnector) Connect(ctx context.Context) (driver.Conn, error) {
	v, e := c.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return &dHeldClockConn{Conn: v, delay: c.delay}, nil
}

type dHeldClockConn struct {
	driver.Conn
	delay *dHeldClockDelay
}

func (c *dHeldClockConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *dHeldClockConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	r, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if e != nil {
		return nil, e
	}
	return c.wrap(q, r), nil
}
func (c *dHeldClockConn) Prepare(q string) (driver.Stmt, error) {
	s, e := c.Conn.Prepare(q)
	if e != nil {
		return nil, e
	}
	return dHeldClockStmt{Stmt: s, conn: c, query: q}, nil
}
func (c *dHeldClockConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *dHeldClockConn) wrap(q string, r driver.Rows) driver.Rows {
	if c.delay.identityField != "" {
		if strings.Contains(q, "CURRENT_USER()") && strings.Contains(q, "@@server_uuid") && strings.Contains(q, "DATABASE()") {
			return &dHeldIdentityRows{Rows: r, fault: c.delay}
		}
		return r
	}
	if c.delay.heldOwnerFacts {
		if strings.Contains(q, ",p.profile_json,p.profile_sha256,i.last_effective_enabled") && strings.Contains(q, "FROM system_backup_gate g") {
			return &dHeldClockRows{Rows: r, delay: c.delay}
		}
		return r
	}
	if c.delay.initialFacts {
		if strings.HasPrefix(q, "SELECT original.canonical_config_json,t.status,t.row_version,") {
			return &dHeldClockRows{Rows: r, delay: c.delay}
		}
		return r
	}
	if c.delay.ownerFacts {
		if strings.HasPrefix(q, "SELECT b.status,p.profile_json,p.profile_sha256,i.last_effective_enabled FROM") {
			return &dHeldClockRows{Rows: r, delay: c.delay}
		}
		return r
	}
	if strings.Contains(q, "FROM system_backup_gate g") || strings.HasPrefix(q, "SELECT schema_version,origin_installation_id,task_type,request_id,status,controller_owner,") {
		return &dHeldClockRows{Rows: r, delay: c.delay}
	}
	return r
}

func TestInitialHeldSnapshotRechecksClockAfterSharedFacts(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	delay := &dHeldClockDelay{initialFacts: true}
	owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{WrapControlConnector: func(conn driver.Connector) driver.Connector {
		return dHeldClockConnector{Connector: conn, delay: delay}
	}})
	refresh()
	ctx := context.Background()
	for _, bound := range []string{"claim", "task-deadline", "gate-lease", "hold"} {
		t.Run(bound, func(t *testing.T) {
			delay.armed.Store(false)
			delay.fired.Store(false)
			tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			expires := time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
			authority := a
			var query string
			switch bound {
			case "claim":
				query = "UPDATE system_backup_v2_backups SET controller_lease_expires_at=?"
			case "task-deadline":
				query = "UPDATE system_backup_v2_backups SET deadline_at=?"
				authority.DeadlineAt = expires
			case "gate-lease":
				query = "UPDATE system_backup_v2_maintenance_locks SET lease_expires_at=?"
			case "hold":
				query = "UPDATE system_backup_v2_maintenance_locks SET absolute_hold_deadline_at=?"
			}
			result, err := tx.ExecContext(ctx, query, expires)
			if err != nil {
				t.Fatal(err)
			}
			if count, e := result.RowsAffected(); e != nil || count != 1 {
				t.Fatal("original bound not actually set", count, e)
			}
			delay.armed.Store(true)
			_, err = owner.Gate.Authority.Bind(ctx, tx, authority)
			if !delay.fired.Load() || time.Now().Before(expires) {
				t.Fatal("initial shared facts did not actually cross the original bound")
			}
			if err == nil {
				t.Fatal("initial snapshot accepted expiry during actual shared facts delivery")
			}
		})
	}
}

type dHeldClockStmt struct {
	driver.Stmt
	conn  *dHeldClockConn
	query string
}

func (s dHeldClockStmt) Query(args []driver.Value) (driver.Rows, error) {
	r, e := s.Stmt.Query(args)
	if e != nil {
		return nil, e
	}
	return s.conn.wrap(s.query, r), nil
}

type dHeldClockRows struct {
	driver.Rows
	delay *dHeldClockDelay
}

func (r *dHeldClockRows) Next(v []driver.Value) error {
	e := r.Rows.Next(v)
	if e == nil && r.delay.armed.CompareAndSwap(true, false) {
		r.delay.fired.Store(true)
		pause := r.delay.duration
		if pause <= 0 {
			pause = 2500 * time.Millisecond
		}
		time.Sleep(pause)
	}
	return e
}

func TestDeploymentEffectiveGrantCannotExpireDuringCurrentFactsRead(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	delay := &dHeldClockDelay{ownerFacts: true, duration: 5500 * time.Millisecond}
	var expires time.Time
	owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{
		WrapControlConnector: func(conn driver.Connector) driver.Connector {
			return dHeldClockConnector{Connector: conn, delay: delay}
		},
		ConfigureGrant: func(grant *c.ExecutionGrant) {
			expires = time.Now().UTC().Add(5 * time.Second).Truncate(time.Microsecond)
			grant.ExpiresAt = expires
		},
	})
	refresh()
	ctx := context.Background()
	tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	delay.armed.Store(true)
	_, err = owner.Gate.Authority.Bind(ctx, tx, a)
	if !delay.fired.Load() || time.Now().Before(expires) {
		t.Fatal("current owner facts did not actually delay beyond the original signed grant")
	}
	if err == nil {
		t.Fatal("authorization accepted a signed grant that expired during current facts delivery")
	}
}

func TestHeldOwnerGrantCannotExpireDuringCombinedFactsRead(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	delay := &dHeldClockDelay{heldOwnerFacts: true, duration: 5500 * time.Millisecond}
	var expires time.Time
	owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{
		WrapControlConnector: func(conn driver.Connector) driver.Connector {
			return dHeldClockConnector{Connector: conn, delay: delay}
		},
		ConfigureGrant: func(grant *c.ExecutionGrant) {
			expires = time.Now().UTC().Add(5 * time.Second).Truncate(time.Microsecond)
			grant.ExpiresAt = expires
		},
	})
	refresh()
	ctx := context.Background()
	tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guard, err := owner.Gate.Authority.Bind(ctx, tx, a)
	if err != nil || guard.Recheck(ctx, tx) != nil || !time.Now().Before(expires) {
		t.Fatal("original current grant baseline", err)
	}
	delay.armed.Store(true)
	err = guard.Recheck(ctx, tx)
	if !delay.fired.Load() || time.Now().Before(expires) {
		t.Fatal("combined owner facts did not actually delay beyond original grant")
	}
	if err == nil || !guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil {
		t.Fatal("grant expired during current combined facts delivery but guard accepted/revived")
	}
}

func TestHeldCaptureRecheckCannotUseClockBeforeDelayedFacts(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	delay := &dHeldClockDelay{}
	owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{WrapControlConnector: func(c driver.Connector) driver.Connector { return dHeldClockConnector{Connector: c, delay: delay} }})
	refresh()
	ctx := context.Background()
	for _, bound := range []string{"claim", "task-deadline", "gate-lease", "hold"} {
		t.Run(bound, func(t *testing.T) {
			delay.armed.Store(false)
			delay.fired.Store(false)
			tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			expiredAt := time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
			authority := a
			var query string
			switch bound {
			case "claim":
				query = "UPDATE system_backup_v2_backups SET controller_lease_expires_at=?"
			case "task-deadline":
				query = "UPDATE system_backup_v2_backups SET deadline_at=?"
				authority.DeadlineAt = expiredAt
			case "gate-lease":
				query = "UPDATE system_backup_v2_maintenance_locks SET lease_expires_at=?"
			case "hold":
				query = "UPDATE system_backup_v2_maintenance_locks SET absolute_hold_deadline_at=?"
			}
			result, err := tx.ExecContext(ctx, query, expiredAt)
			if err != nil {
				t.Fatal(err)
			}
			if count, err := result.RowsAffected(); err != nil || count != 1 {
				t.Fatal("exact original bound not set", count, err)
			}
			guard, err := owner.Gate.Authority.Bind(ctx, tx, authority)
			if err != nil {
				t.Fatal("healthy original bind", err)
			}
			delay.armed.Store(true)
			err = guard.Recheck(ctx, tx)
			if !delay.fired.Load() || time.Now().Before(expiredAt) {
				t.Fatal("actual delayed fact read did not cross the original expiry")
			}
			if err == nil || !guard.ValidUntil().IsZero() {
				t.Fatal("recheck accepted an expired original bound using a clock sampled before delayed facts")
			}
		})
	}
}
