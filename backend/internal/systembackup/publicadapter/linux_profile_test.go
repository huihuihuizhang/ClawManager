package publicadapter

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// Isolated SQL-driver fixture exercises the real production SELECT path. It
// does not certify MySQL grants, physical snapshot isolation or live schema.
type sourceFixture struct {
	queries, writes, rollbacks int
	wrongOwner, windows        bool
}
type sourceConnector struct{ f *sourceFixture }

func (c sourceConnector) Connect(context.Context) (driver.Conn, error) { return &sourceConn{c.f}, nil }
func (c sourceConnector) Driver() driver.Driver                        { return sourceDriver{c.f} }

type sourceDriver struct{ f *sourceFixture }

func (d sourceDriver) Open(string) (driver.Conn, error) { return &sourceConn{d.f}, nil }

type sourceConn struct{ f *sourceFixture }

func (c *sourceConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared SQL")
}
func (c *sourceConn) Close() error { return nil }
func (c *sourceConn) Begin() (driver.Tx, error) {
	return nil, errors.New("missing readonly transaction")
}
func (c *sourceConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if !o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("source transaction not readonly RR")
	}
	return sourceTx{c.f}, nil
}

type sourceTx struct{ f *sourceFixture }

func (t sourceTx) Commit() error   { t.f.writes++; return errors.New("discovery must not commit") }
func (t sourceTx) Rollback() error { t.f.rollbacks++; return nil }
func (c *sourceConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.f.writes++
	return nil, errors.New("source write prohibited")
}
func (c *sourceConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.f.queries++
	var values [][]driver.Value
	switch q {
	case "SELECT DATABASE(), @@server_uuid":
		values = [][]driver.Value{{"synthetic_source", "source-uuid"}}
	case "SELECT id FROM users ORDER BY id":
		values = [][]driver.Value{{int64(1)}, {int64(4)}}
	default:
		if !strings.HasPrefix(q, "SELECT id,user_id,instance_mode,type,runtime_type,") {
			return nil, errors.New("unreviewed source query")
		}
		owner := int64(4)
		os := "linux"
		if c.f.wrongOwner {
			owner = 99
		}
		if c.f.windows {
			os = "windows"
		}
		values = [][]driver.Value{{int64(7), owner, "lite", "openclaw", "gateway", "linux", os, "running", int64(7), "source-pod", "source-ns", "/workspace"}}
	}
	columns := make([]string, len(values[0]))
	for i := range columns {
		columns[i] = "value"
	}
	return &sourceRows{columns, values}, nil
}

type sourceRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *sourceRows) Columns() []string { return r.columns }
func (r *sourceRows) Close() error      { return nil }
func (r *sourceRows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}

func linuxFixture(t *testing.T, f *fixture, sqlf *sourceFixture) *LinuxProfile {
	t.Helper()
	db := sql.OpenDB(sourceConnector{sqlf})
	t.Cleanup(func() { db.Close() })
	p, err := NewLinuxProfile(LinuxProfileConfig{Source: db, Database: "synthetic_source", ServerUUID: "source-uuid", Supported: map[AgentKind]bool{{"openclaw", "lite", "linux", "linux"}: true}, HoldLimit: 30 * time.Second,
		BuildWriters: func(_ context.Context, _ d.Input, inv SourceInventory, _ []FrozenWriter) ([]flow.Writer, error) {
			if len(inv.Users) != 2 || len(inv.Instances) != 1 || inv.Instances[0].ID != 7 {
				return nil, errors.New("wrong frozen inventory")
			}
			return []flow.Writer{fixtureWriter{f}}, nil
		},
		BuildParts: func(in d.Input, _ SourceInventory, _ time.Time) ([]JobPart, error) {
			if in.Authority.TaskType == "preflight" {
				return []JobPart{{Part: "source_inventory", Category: "preflight"}}, nil
			}
			return f.x.Parts, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRealCompositionEntryConstructsSharedDispatcherWithoutControlSQL(t *testing.T) {
	f, _, _ := setup(t)
	sf := &sourceFixture{}
	profile := linuxFixture(t, f, sf)
	cfg := profile.cfg
	original := cfg.BuildParts
	cfg.BuildParts = func(in d.Input, source SourceInventory, hold time.Time) ([]JobPart, error) {
		parts, err := original(in, source, hold)
		if err != nil {
			return nil, err
		}
		parts = append([]JobPart(nil), parts...)
		for i := range parts {
			var inv worker.Invocation
			if json.Unmarshal(parts[i].InvocationJSON, &inv) != nil {
				return nil, d.ErrNotReady
			}
			inv.Request.Deadline = hold
			raw, _ := json.Marshal(inv)
			parts[i].InvocationJSON = raw
			parts[i].InvocationSHA256 = digest(raw)
		}
		return parts, nil
	}
	execution := Dependencies{Results: f, Recovery: f, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: fixtureInventory, RecoveryTimeout: time.Second}
	if _, err := NewLinuxDispatcher(ProfileKey{f.in.ProfileID, f.in.ProfileRevision}, cfg, execution, nil); err == nil || sf.queries != 0 {
		t.Fatal("missing Ports accepted or constructor queried source")
	}
	dispatcher, err := NewLinuxDispatcher(ProfileKey{f.in.ProfileID, f.in.ProfileRevision}, cfg, execution, f)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := dispatcher.Prepare(context.Background(), f.in)
	if err != nil || plan.SchemaVersion != PlanVersion || sf.queries != 3 || sf.writes != 0 || f.ensures != 0 {
		t.Fatal(plan, err, sf)
	}
	x, err := DescribePlan(f.in, plan)
	if err != nil || len(x.Parts) != 1 || len(x.Parts[0].InvocationJSON) == 0 {
		t.Fatal("persisted invocation unavailable to D", err)
	}
}

func TestConcreteLinuxDiscoveryUsesReadonlySQLAndBindNeverRediscovers(t *testing.T) {
	f, _, _ := setup(t)
	sqlf := &sourceFixture{}
	p := linuxFixture(t, f, sqlf)
	x, err := p.Discover(context.Background(), f.in)
	if err != nil {
		t.Fatal(err)
	}
	if sqlf.queries != 3 || sqlf.writes != 0 || sqlf.rollbacks != 1 || len(x.Writers) != 1 {
		t.Fatal(sqlf, x)
	}
	if _, err := p.BindWriters(context.Background(), f.in, x); err != nil || sqlf.queries != 3 || sqlf.writes != 0 {
		t.Fatal("Bind used source SQL", err, sqlf)
	}
}

func TestConcreteLinuxDiscoveryRejectsUnsupportedAndOrphanInventory(t *testing.T) {
	for _, which := range []string{"orphan", "windows"} {
		t.Run(which, func(t *testing.T) {
			f, _, _ := setup(t)
			sf := &sourceFixture{wrongOwner: which == "orphan", windows: which == "windows"}
			p := linuxFixture(t, f, sf)
			if _, err := p.Discover(context.Background(), f.in); err == nil || sf.writes != 0 {
				t.Fatal("unsafe inventory accepted", err, sf)
			}
		})
	}
}

func TestSourcePreflightPerformsNoWriterPauseOrJobDispatch(t *testing.T) {
	f, _, _ := setup(t)
	sf := &sourceFixture{}
	profile := linuxFixture(t, f, sf)
	f.in.Authority.TaskType = "preflight"
	f.in.Authority.TaskPublicID = "spf_11111111-1111-4111-8111-111111111111"
	f.in.Authority.Phase = "preflight"
	f.in.Authority.MaintenanceOwner = ""
	f.in.Authority.MaintenanceFencingToken = 0
	r, err := NewPublicRunner(Dependencies{Profiles: map[ProfileKey]Profile{{f.in.ProfileID, f.in.ProfileRevision}: profile}, Results: f, Recovery: f, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: fixtureInventory, RecoveryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Prepare(context.Background(), f.in, f)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Capture(context.Background(), f.in, p, f)
	if err != nil || len(out) != 1 || out[0].Part != "source_inventory" || sf.queries != 6 || sf.writes != 0 || f.ensures != 0 || contains(f.events, "pause") {
		t.Fatal(out, err, sf, f.events)
	}
}
