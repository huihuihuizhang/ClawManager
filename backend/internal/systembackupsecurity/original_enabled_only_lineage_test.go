package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// SQL row MODELS, not a native normal-enable/KEK-admission qualification.
type lineageConfigModel struct {
	config  ConfigValues
	mode    string
	queries []string
	now     time.Time
}
type lineageConfigConnector struct{ s *lineageConfigModel }

func (c lineageConfigConnector) Connect(context.Context) (driver.Conn, error) {
	return &lineageConfigConn{c.s}, nil
}
func (lineageConfigConnector) Driver() driver.Driver { return lineageConfigDriver{} }

type lineageConfigDriver struct{}

func (lineageConfigDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}

type lineageConfigConn struct{ s *lineageConfigModel }

func (*lineageConfigConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("no prepare/write")
}
func (*lineageConfigConn) Close() error              { return nil }
func (*lineageConfigConn) Begin() (driver.Tx, error) { return lineageReadTx{}, nil }
func (*lineageConfigConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return lineageReadTx{}, nil
}

type lineageReadTx struct{}

func (lineageReadTx) Commit() error   { return errors.New("read test rolls back") }
func (lineageReadTx) Rollback() error { return nil }

type lineageConfigRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *lineageConfigRows) Columns() []string { return r.columns }
func (*lineageConfigRows) Close() error        { return nil }
func (r *lineageConfigRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}
func (c *lineageConfigConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.s.queries = append(c.s.queries, q)
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return &lineageConfigRows{columns: []string{"now"}, values: []driver.Value{c.s.now}}, nil
	}
	if !strings.Contains(q, "FROM system_backup_v2_configs") {
		return nil, errors.New("unexpected model query")
	}
	if strings.Contains(q, "FOR UPDATE") {
		return nil, errors.New("read-only lineage acquired write lock")
	}
	columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ",")
	all, args, _ := c.s.config.sqlValues("installation_lineage", "unused", "unused", 1)
	facts := map[string]driver.Value{}
	for n, key := range all {
		value := args[n]
		switch v := value.(type) {
		case []byte:
			facts[key] = v
		case bool:
			facts[key] = v
		default:
			facts[key] = fmt.Sprint(value)
		}
	}
	facts["schema_version"], facts["row_version"] = "system-backup-config.v1", int64(1)
	if c.s.mode == "wrong-flat-ref" {
		facts["kek_identity_hash"] = strings.Repeat("0", 64)
	}
	if c.s.mode == "wrong-size" {
		facts["config_size_bytes"] = int64(1)
	}
	values := make([]driver.Value, len(columns))
	for n, key := range columns {
		v, ok := facts[key]
		if !ok {
			return nil, fmt.Errorf("unknown fixture column %s", key)
		}
		values[n] = v
	}
	return &lineageConfigRows{columns: columns, values: values}, nil
}

func TestOriginalEnabledOnlyLineageReadsCompleteCanonicalAndFlattenedConfig(t *testing.T) {
	old, e := DecodeConfigValues(bootstrapFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "wrong-flat-ref", "wrong-size"} {
		t.Run(mode, func(t *testing.T) {
			state := &lineageConfigModel{config: old, mode: mode, now: time.Now().UTC().Truncate(time.Microsecond)}
			db := sql.OpenDB(lineageConfigConnector{state})
			defer db.Close()
			tx, _ := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
			defer tx.Rollback()
			got, e := readEnabledLineageConfig(context.Background(), tx, "installation_lineage", 1)
			if mode == "valid" {
				if e != nil || got.SHA256() != old.SHA256() {
					t.Fatal("complete row read failed", e)
				}
				if len(state.queries) != 2 || !strings.Contains(state.queries[1], "kek_identity_hash") || !strings.Contains(state.queries[1], "nonce_hmac_identity_hash") {
					t.Fatal("flattened security references omitted")
				}
			} else if e == nil {
				t.Fatal("SQL/raw contradiction accepted")
			}
		})
	}
}

func TestOriginalEnabledOnlyLineageScopeAccessorCannotCrossContextOrTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := &lineageConfigModel{now: now}
	db := sql.OpenDB(lineageConfigConnector{state})
	defer db.Close()
	tx, _ := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	// Only this private accessor boundary is modeled. No source reader is
	// bypassed to produce native permission, a provider permit or a real proof.
	p := &OriginalEnabledOnlyLineage{ctx: ctx, view: tx, checkedAt: now, oldSHA: strings.Repeat("a", 64)}
	p.origin = p
	if _, e := p.AuthorizationConfigSHA256(ctx, tx); e != nil {
		t.Fatal(e)
	}
	other, _ := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	defer other.Rollback()
	if _, e := p.AuthorizationConfigSHA256(ctx, other); e == nil {
		t.Fatal("foreign tx accepted")
	}
	foreign, stop := context.WithCancel(ctx)
	defer stop()
	if _, e := p.AuthorizationConfigSHA256(foreign, tx); e == nil {
		t.Fatal("foreign ctx accepted")
	}
	copy := *p
	if _, e := copy.AuthorizationConfigSHA256(ctx, tx); e == nil {
		t.Fatal("copied opaque source accepted")
	}
	if _, e := json.Marshal(p); e == nil {
		t.Fatal("opaque source serialized")
	}
	tx.Rollback()
	if _, e := p.AuthorizationConfigSHA256(ctx, tx); e == nil {
		t.Fatal("closed SQL view accepted")
	}
}

func TestOriginalEnabledOnlyLineageRefusesMissingViewAndOtherVersion(t *testing.T) {
	for _, v := range []uint64{0, 1, 2, 3} {
		if p, e := ReadOriginalEnabledOnlyLineage(context.Background(), nil, "installation_lineage", strings.Repeat("a", 64), v, strings.Repeat("b", 64)); e == nil || p != nil {
			t.Fatal("missing actual SQL view authorized inheritance")
		}
	}
}
