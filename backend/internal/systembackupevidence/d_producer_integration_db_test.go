package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"reflect"
	"strconv"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// One in-memory SQL connection owns BOTH A and D rows. It interprets only the
// emitted parameterized statements, including CAS predicates; it is not MySQL.
// No test writes directly to the database to simulate a successful service step.
type dIntegrationDB struct {
	*systemPendingTestDB
	records      map[string][]map[string]driver.Value
	saved        map[string][]map[string]driver.Value
	reject       string
	advanceClock bool
}

func (d *dIntegrationDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func cloneDIntegrationRows(src map[string][]map[string]driver.Value) map[string][]map[string]driver.Value {
	dst := make(map[string][]map[string]driver.Value, len(src))
	for k, rows := range src {
		dst[k] = cloneSystemPendingChunks(rows)
	}
	return dst
}
func (d *dIntegrationDB) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if _, err := d.systemPendingTestDB.BeginTx(ctx, o); err != nil {
		return nil, err
	}
	d.saved = cloneDIntegrationRows(d.records)
	return d, nil
}
func (d *dIntegrationDB) Rollback() error {
	d.records = d.saved
	return d.systemPendingTestDB.Rollback()
}
func dSQLValue(v any) driver.Value {
	if n, ok := v.(uint64); ok {
		return strconv.FormatUint(n, 10)
	}
	out, err := driver.DefaultParameterConverter.ConvertValue(v)
	if err != nil {
		panic(err)
	}
	return out
}
func (d *dIntegrationDB) seed(record any) {
	row, err := pd.EncodeStoredRecord(record)
	if err != nil {
		d.t.Fatal(err)
	}
	cols := map[string]driver.Value{}
	for k, v := range row.Columns {
		cols[k] = dSQLValue(v)
	}
	d.records[row.Table] = append(d.records[row.Table], cols)
}
func (d *dIntegrationDB) check(records ...any) error {
	for _, record := range records {
		row, err := pd.EncodeStoredRecord(record)
		if err != nil {
			return err
		}
		found := false
		for _, stored := range d.records[row.Table] {
			same := true
			for k, v := range row.Columns {
				same = same && reflect.DeepEqual(stored[k], dSQLValue(v))
			}
			found = found || same
		}
		if !found {
			return pd.ErrConflict
		}
	}
	return nil
}
func (d *dIntegrationDB) load(table string, out any) {
	if len(d.records[table]) != 1 {
		d.t.Fatalf("expected one %s", table)
	}
	cols := map[string]any{}
	for k, v := range d.records[table][0] {
		cols[k] = v
	}
	if err := pd.DecodeStoredRecord(pd.StoredRecord{Table: table, Columns: cols}, d.scope, out); err != nil {
		d.t.Fatal(err)
	}
}
func (d *dIntegrationDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q == "SELECT @@server_uuid,DATABASE()" {
		return &systemPendingTestRows{cols: []string{"uuid", "db"}, rows: [][]driver.Value{{string(d.scope.ServerUUID), string(d.scope.Database)}}}, nil
	}
	if d.advanceClock && (q == "SELECT UTC_TIMESTAMP(6)" || strings.HasPrefix(q, "SELECT @@server_uuid,")) {
		d.now = d.now.Add(time.Millisecond)
	}
	if !strings.Contains(q, " FROM system_backup_producer_") {
		return d.systemPendingTestDB.QueryContext(ctx, q, args)
	}
	head, tail, ok := strings.Cut(q, " FROM ")
	if !ok {
		return nil, pd.ErrInvalid
	}
	table, where, ok := strings.Cut(tail, " WHERE ")
	if !ok || !strings.HasSuffix(where, " FOR UPDATE") {
		return nil, pd.ErrInvalid
	}
	cols := strings.Split(strings.TrimPrefix(head, "SELECT "), ", ")
	conditions := strings.Split(strings.TrimSuffix(where, " FOR UPDATE"), " AND ")
	if len(conditions) != len(args) {
		return nil, pd.ErrInvalid
	}
	rows := &systemPendingTestRows{cols: cols}
	d.events = append(d.events, "read:"+table)
	for _, row := range d.records[table] {
		match := true
		for i, c := range conditions {
			if !strings.HasSuffix(c, " = ?") {
				return nil, pd.ErrInvalid
			}
			match = match && reflect.DeepEqual(row[strings.TrimSuffix(c, " = ?")], args[i].Value)
		}
		if match {
			values := make([]driver.Value, len(cols))
			for i, c := range cols {
				values[i] = row[c]
			}
			rows.rows = append(rows.rows, values)
		}
	}
	return rows, nil
}
func (d *dIntegrationDB) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(q, "UPDATE system_backup_v2_evidence SET ") {
		return d.evidenceCAS(q, args)
	}
	if !strings.Contains(q, "system_backup_producer_") {
		return d.systemPendingTestDB.ExecContext(ctx, q, args)
	}
	d.writes++
	if strings.HasPrefix(q, "INSERT INTO ") {
		table, tail, ok := strings.Cut(strings.TrimPrefix(q, "INSERT INTO "), " (")
		if !ok {
			return nil, pd.ErrInvalid
		}
		columns, _, ok := strings.Cut(tail, ") VALUES")
		if !ok {
			return nil, pd.ErrInvalid
		}
		cols := strings.Split(columns, ", ")
		if len(cols) != len(args) {
			return nil, pd.ErrInvalid
		}
		if d.reject == "insert:"+table {
			return nil, pd.ErrUnavailable
		}
		row := map[string]driver.Value{}
		for i, c := range cols {
			row[c] = args[i].Value
		}
		d.records[table] = append(d.records[table], row)
		d.events = append(d.events, "insert:"+table)
		return driver.RowsAffected(1), nil
	}
	table, tail, ok := strings.Cut(strings.TrimPrefix(q, "UPDATE "), " SET ")
	if !ok {
		return nil, pd.ErrInvalid
	}
	sets, where, ok := strings.Cut(tail, " WHERE ")
	if !ok {
		return nil, pd.ErrInvalid
	}
	setCols, conditions := strings.Split(sets, ", "), strings.Split(where, " AND ")
	if len(args) != len(setCols)+len(conditions) {
		return nil, pd.ErrInvalid
	}
	if d.reject == "update:"+table {
		return driver.RowsAffected(0), nil
	}
	n := int64(0)
	for _, row := range d.records[table] {
		match := true
		for i, c := range conditions {
			if !strings.HasSuffix(c, " <=> ?") {
				return nil, pd.ErrInvalid
			}
			match = match && reflect.DeepEqual(row[strings.TrimSuffix(c, " <=> ?")], args[len(setCols)+i].Value)
		}
		if match {
			for i, c := range setCols {
				if !strings.HasSuffix(c, " = ?") {
					return nil, pd.ErrInvalid
				}
				row[strings.TrimSuffix(c, " = ?")] = args[i].Value
			}
			n++
		}
	}
	d.events = append(d.events, "update:"+table)
	return driver.RowsAffected(n), nil
}

// Evaluate every WHERE predicate on D's two evidence CAS statements. A's
// actual loaders subsequently verify the complete registry/chunk projection.
func (d *dIntegrationDB) evidenceCAS(q string, args []driver.NamedValue) (driver.Result, error) {
	const claim = "UPDATE system_backup_v2_evidence SET claim_owner=?,claim_expires_at=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner <=> ? AND claim_expires_at <=> ?"
	const finish = "UPDATE system_backup_v2_evidence SET storage_state=?,evidence_failure_code=?,storage_immutable_version=?,claim_owner=NULL,claim_expires_at=NULL,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner=? AND claim_expires_at=? AND storage_immutable_version IS NULL"
	d.writes++
	r := d.row
	if r == nil || r["owner_target_type"] != "system" || r["evidence_type"] != "capability_snapshot" {
		return driver.RowsAffected(0), nil
	}
	var cols []string
	var values []driver.NamedValue
	switch q {
	case claim:
		if len(args) != 8 {
			return nil, pd.ErrInvalid
		}
		cols = []string{"public_id", "row_version", "owner_target_public_id", "storage_state", "claim_owner", "claim_expires_at"}
		values = args[2:]
	case finish:
		if len(args) != 9 || r["storage_immutable_version"] != nil {
			return driver.RowsAffected(0), nil
		}
		cols = []string{"public_id", "row_version", "owner_target_public_id", "storage_state", "claim_owner", "claim_expires_at"}
		values = args[3:]
	default:
		return nil, pd.ErrInvalid
	}
	for i, col := range cols {
		if !reflect.DeepEqual(r[col], values[i].Value) {
			return driver.RowsAffected(0), nil
		}
	}
	if d.reject == "evidence_cas" {
		return driver.RowsAffected(0), nil
	}
	if q == claim {
		r["claim_owner"], r["claim_expires_at"] = args[0].Value, args[1].Value
	} else {
		r["storage_state"], r["evidence_failure_code"], r["storage_immutable_version"] = args[0].Value, args[1].Value, args[2].Value
		r["claim_owner"], r["claim_expires_at"] = nil, nil
	}
	r["row_version"] = r["row_version"].(int64) + 1
	r["updated_at"] = d.now
	d.events = append(d.events, "evidence:cas")
	return driver.RowsAffected(1), nil
}
