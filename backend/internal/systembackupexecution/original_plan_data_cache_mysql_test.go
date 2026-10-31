package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

type originalPlanReadProbe struct {
	reads      atomic.Int32
	armed      atomic.Bool
	beforeRead func() error
}
type originalPlanProbeConnector struct {
	driver.Connector
	probe *originalPlanReadProbe
}

func (c originalPlanProbeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	v, e := c.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return &originalPlanProbeConn{Conn: v, probe: c.probe}, nil
}

type originalPlanProbeConn struct {
	driver.Conn
	probe *originalPlanReadProbe
}

func (c *originalPlanProbeConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (p *originalPlanReadProbe) before(q string) error {
	if strings.HasPrefix(q, "SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records") && p.armed.CompareAndSwap(true, false) {
		return p.beforeRead()
	}
	return nil
}
func (p *originalPlanReadProbe) observed(q string) {
	if strings.HasPrefix(q, "SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records") {
		p.reads.Add(1)
	}
}
func (c *originalPlanProbeConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if e := c.probe.before(q); e != nil {
		return nil, e
	}
	r, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
	if e == nil {
		c.probe.observed(q)
	}
	return r, e
}
func (c *originalPlanProbeConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
}
func (c *originalPlanProbeConn) Prepare(q string) (driver.Stmt, error) {
	s, e := c.Conn.Prepare(q)
	if e != nil {
		return nil, e
	}
	return originalPlanProbeStmt{Stmt: s, probe: c.probe, query: q}, nil
}

type originalPlanProbeStmt struct {
	driver.Stmt
	probe *originalPlanReadProbe
	query string
}

func (s originalPlanProbeStmt) Query(a []driver.Value) (driver.Rows, error) {
	if e := s.probe.before(s.query); e != nil {
		return nil, e
	}
	r, e := s.Stmt.Query(a)
	if e == nil {
		s.probe.observed(s.query)
	}
	return r, e
}

func TestOriginalPlanDataCacheStillRequiresCurrentSQLKeyAndExactCipherMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	probe := &originalPlanReadProbe{}
	owner, service, admin, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{WrapControlConnector: func(c driver.Connector) driver.Connector {
		return originalPlanProbeConnector{Connector: c, probe: probe}
	}})
	refresh()
	ctx := context.Background()
	in, err := owner.executionInput(ctx, a, false)
	if err != nil {
		t.Fatal(err)
	}
	var originalCipher []byte
	if admin.QueryRow("SELECT sealed_payload FROM system_backup_v2_execution_records WHERE record_kind='plan'").Scan(&originalCipher) != nil {
		t.Fatal("original encrypted plan")
	}
	writeCipher := func(value []byte) error {
		result, e := admin.Exec("UPDATE system_backup_v2_execution_records SET sealed_payload=? WHERE record_kind='plan'", value)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return os.ErrInvalid
		}
		var actual []byte
		if e = admin.QueryRow("SELECT sealed_payload FROM system_backup_v2_execution_records WHERE record_kind='plan'").Scan(&actual); e != nil {
			return e
		}
		if !bytes.Equal(actual, value) {
			return os.ErrInvalid
		}
		return nil
	}
	bad := bytes.Clone(originalCipher)
	bad[len(bad)-1] ^= 1
	if err = writeCipher(bad); err != nil {
		t.Fatal(err)
	}
	probe.beforeRead = func() error { return writeCipher(originalCipher) }
	probe.armed.Store(true)
	if _, _, _, err = owner.Gate.Records.OpenOriginalCapturePlan(ctx, in); err == nil || probe.armed.Load() {
		t.Fatal("different actual authenticated ciphertext populated an earlier sampled identity", err)
	}
	if err = writeCipher(bad); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = owner.Gate.Records.OpenOriginalCapturePlan(ctx, in); err == nil {
		t.Fatal("corrupt earlier sample became a cached authenticated plan")
	}
	if err = writeCipher(originalCipher); err != nil {
		t.Fatal(err)
	}
	probe.reads.Store(0)
	plan, desc, first, err := owner.Gate.Records.OpenOriginalCapturePlan(ctx, in)
	if err != nil || probe.reads.Load() != 1 {
		t.Fatal("cold authenticated plan read", probe.reads.Load(), err)
	}
	defer clear(plan.CanonicalJSON)
	canonical := bytes.Clone(plan.CanonicalJSON)
	discovery, _ := json.Marshal(desc)
	plan.CanonicalJSON[0] = '!'
	desc.Source[0] = '!'
	desc.Parts[0].Intent.SpecJSON[0] = '!'
	desc.Parts[0].InvocationJSON[0] = '!'
	other, cancel := context.WithCancel(ctx)
	defer cancel()
	warm, warmDesc, second, err := owner.Gate.Records.OpenOriginalCapturePlan(other, in)
	if err != nil || probe.reads.Load() != 1 || first == second || !bytes.Equal(warm.CanonicalJSON, canonical) {
		t.Fatal("warm path did not use private immutable authenticated data", probe.reads.Load(), err)
	}
	defer clear(warm.CanonicalJSON)
	actualDesc, _ := json.Marshal(warmDesc)
	if !bytes.Equal(actualDesc, discovery) {
		t.Fatal("caller aliases polluted cached discovery")
	}
	tx, err := owner.Gate.Authority.DB.BeginTx(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.RecheckTx(other, tx, owner.Gate.Records, in) == nil {
		t.Fatal("old request historical object reused across contexts")
	}
	tx.Rollback()
	// This named local fixture colocates its pinned record key and config.
	keyFile := filepath.Join(filepath.Dir(service.ConfigPath), owner.Identity.DeploymentBinding().RecordKeys[0].Ref)
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	changed := bytes.Clone(key)
	changed[0] ^= 1
	if os.WriteFile(keyFile, changed, 0600) != nil {
		t.Fatal("change actual record key")
	}
	if _, _, _, err = owner.Gate.Records.OpenOriginalCapturePlan(ctx, in); err == nil {
		t.Fatal("cache bypassed current record key change")
	}
	tx, err = owner.Gate.Authority.DB.BeginTx(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Gate.Authority.Bind(other, tx, a); err != nil {
		t.Fatal("original current claim before key recheck", err)
	}
	if second.RecheckTx(other, tx, owner.Gate.Records, in) == nil {
		t.Fatal("request historical object ignored mid-request key change")
	}
	tx.Rollback()
	if os.WriteFile(keyFile, key, 0600) != nil {
		t.Fatal("restore record key")
	}
	clear(changed)
	if err = writeCipher(bad); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = owner.Gate.Records.OpenOriginalCapturePlan(ctx, in); err == nil {
		t.Fatal("cache bypassed actual ciphertext change")
	}
	if err = writeCipher(originalCipher); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ table, column string }{
		{"system_backup_v2_backups", "controller_owner"},
		{"system_backup_v2_backups", "config_snapshot_json"},
		{"system_backup_v2_execution_inputs", "profile_json"},
		{"system_backup_v2_backups", "runner"},
		{"system_backup_v2_execution_records", "key_ref"},
	} {
		var original []byte
		if admin.QueryRow("SELECT "+m.column+" FROM "+m.table).Scan(&original) != nil {
			t.Fatal("original cache scope field")
		}
		value := append(bytes.Clone(original), 'x')
		result, e := admin.Exec("UPDATE "+m.table+" SET "+m.column+"=?", value)
		if e != nil {
			t.Fatal(e)
		}
		count, e := result.RowsAffected()
		var actual []byte
		if e != nil || count != 1 || admin.QueryRow("SELECT "+m.column+" FROM "+m.table).Scan(&actual) != nil || !bytes.Equal(actual, value) {
			t.Fatal("scope mutation not independently observed")
		}
		_, _, _, err = owner.Gate.Records.OpenOriginalCapturePlan(ctx, in)
		if _, e = admin.Exec("UPDATE "+m.table+" SET "+m.column+"=?", original); e != nil {
			t.Fatal(e)
		}
		if err == nil {
			t.Fatal("warm data bypassed current scope mutation", m.column)
		}
	}
	final, finalDesc, _, err := owner.Gate.Records.OpenOriginalCapturePlan(ctx, in)
	if err != nil || !bytes.Equal(final.CanonicalJSON, canonical) {
		t.Fatal("original immutable data not reusable after actual original scope restored", err)
	}
	clear(final.CanonicalJSON)
	// The complete discovery remains independently loadable and unchanged.
	persisted, err := owner.Gate.Records.LoadPlan(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(persisted.CanonicalJSON)
	inner, err := d.UnwrapTaskPlan(in, persisted, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	independent, err := b.DescribePlan(in, inner)
	clear(inner.CanonicalJSON)
	if err != nil {
		t.Fatal(err)
	}
	actualFinal, _ := json.Marshal(finalDesc)
	actualIndependent, _ := json.Marshal(independent)
	if !bytes.Equal(actualFinal, actualIndependent) {
		t.Fatal("complete authenticated plan scope changed")
	}
}
