package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Scripted SQL transport only. It independently checks the actual INSERT and
// exposes row mutation/driver failures; it does not prove MySQL locks or FK.
type downloadAuditDB struct {
	t                                   *testing.T
	now                                 time.Time
	user, resource                      driver.Value
	action, kind                        string
	body                                []byte
	created                             time.Time
	id, affected                        int64
	fail                                string
	mutate                              func(*downloadAuditDB)
	extraQuery                          func(string, []driver.NamedValue) (driver.Rows, error)
	extraExec                           func(string, []driver.NamedValue) (driver.Result, error)
	queries, inserts, begins, rollbacks int
	commits                             int
}

func (d *downloadAuditDB) Driver() driver.Driver                        { return authorityDriver{} }
func (d *downloadAuditDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *downloadAuditDB) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("no prepare") }
func (d *downloadAuditDB) Close() error                                 { return nil }
func (d *downloadAuditDB) Begin() (driver.Tx, error)                    { return nil, errors.New("explicit tx required") }
func (d *downloadAuditDB) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		d.t.Fatal("wrong isolation")
	}
	d.begins++
	return d, nil
}
func (d *downloadAuditDB) Commit() error   { d.commits++; return nil }
func (d *downloadAuditDB) Rollback() error { d.rollbacks++; return nil }
func (d *downloadAuditDB) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d.queries++
	if q == downloadIntentClockSQL {
		if len(args) != 0 {
			d.t.Fatal("clock args")
		}
		if d.fail == "clock" {
			return nil, errors.New("private clock failure")
		}
		offset := int64(0)
		if d.fail == "non_utc" {
			offset = 3600000000
		}
		return &authorityRows{values: []driver.Value{d.now, offset}}, nil
	}
	if d.extraQuery != nil && q != downloadIntentReadSQL {
		return d.extraQuery(q, args)
	}
	if !strings.Contains(q, "FROM audit_logs WHERE id=? FOR UPDATE") || len(args) != 1 || args[0].Value != d.id {
		d.t.Fatal("audit lookup must use exact INSERT ID and row lock", q)
	}
	if d.fail == "read" {
		return nil, errors.New("private read failure")
	}
	if d.fail == "missing" {
		return &authorityRows{}, nil
	}
	if d.mutate != nil {
		d.mutate(d)
	}
	return &authorityRows{values: []driver.Value{d.user, d.action, d.kind, d.resource, d.body, d.created}}, nil
}
func (d *downloadAuditDB) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if d.extraExec != nil && q != downloadIntentInsertSQL {
		return d.extraExec(q, args)
	}
	if q != "INSERT INTO audit_logs (user_id,action,resource_type,resource_id,details,created_at) VALUES (?,'system_backup.evidence_download.intent','system_backup',NULL,?,?)" || len(args) != 3 {
		d.t.Fatal("unexpected write", q)
	}
	d.inserts++
	if d.fail == "insert" {
		return nil, errors.New("private insert failure")
	}
	d.user, d.action, d.kind = args[0].Value, "system_backup.evidence_download.intent", "system_backup"
	d.body = append([]byte(nil), args[1].Value.([]byte)...)
	d.created = args[2].Value.(time.Time)
	return downloadAuditResult{d}, nil
}

type downloadAuditResult struct{ d *downloadAuditDB }

func (r downloadAuditResult) LastInsertId() (int64, error) {
	if r.d.fail == "id" {
		return 0, errors.New("private id failure")
	}
	return r.d.id, nil
}
func (r downloadAuditResult) RowsAffected() (int64, error) {
	if r.d.fail == "affected" {
		return 0, errors.New("private affected failure")
	}
	return r.d.affected, nil
}

func downloadAuditFixture(t *testing.T) (*downloadAuditDB, *sql.DB, *sql.Tx, DownloadAdmissionIntent) {
	t.Helper()
	d := &downloadAuditDB{t: t, id: 1729, affected: 1, now: time.Date(2026, 10, 16, 6, 30, 0, 876543000, time.UTC)}
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	f := DownloadAdmissionIntent{Installation: "installation_audit", OperationID: "sop_11111111-1111-4111-8111-111111111111",
		EvidenceID: "sev_22222222-2222-4222-8222-222222222222", RequestHash: strings.Repeat("a", 64),
		ManifestSHA256: strings.Repeat("b", 64), Claim: "aev_" + strings.Repeat("c", 32), ActorID: 42,
		EvidenceRowVersion: 7, Start: 1, End: 9, RangePresent: true}
	return d, db, tx, f
}

func TestDownloadAdmissionAuditActualIDAndPrivateClaim(t *testing.T) {
	d, _, tx, f := downloadAuditFixture(t)
	store := SQLDownloadAdmissionAudits{}
	a, err := store.StageIntent(context.Background(), tx, f)
	if err != nil {
		t.Fatal(err)
	}
	if a.id != 1729 || a.tx != tx || d.inserts != 1 || d.begins != 1 || d.commits != 0 || d.rollbacks != 0 {
		t.Fatal("storage changed transaction ownership", a.id, d)
	}
	if d.created.Nanosecond() != 0 || !d.created.Equal(d.now.Truncate(time.Second)) {
		t.Fatal("TIMESTAMP(0) column was rounded", d.created)
	}
	if strings.Contains(string(d.body), f.Claim) {
		t.Fatal("raw claim leaked")
	}
	var body map[string]any
	if json.Unmarshal(d.body, &body) != nil || len(body) != 12 || body["claim_sha256"] != hash([]byte(f.Claim)) ||
		body["operation_public_id"] != f.OperationID || body["evidence_id"] != f.EvidenceID || body["origin_installation_id"] != f.Installation ||
		body["evidence_row_version"] != float64(7) || body["range_start"] != float64(1) || body["range_end"] != float64(9) ||
		body["intent_at"] != "2026-10-16T06:30:00.876543Z" {
		t.Fatal("audit omitted independent facts", string(d.body))
	}
	if _, err := json.Marshal(a); !errors.Is(err, ErrInvalid) {
		t.Fatal("anchor serialized", err)
	}
	if _, err := json.Marshal(f); !errors.Is(err, ErrInvalid) {
		t.Fatal("raw claim input serialized", err)
	}
	// JSON presentation changes from MySQL do not change semantic audit facts.
	d.mutate = func(d *downloadAuditDB) {
		var v map[string]any
		if json.Unmarshal(d.body, &v) != nil {
			t.Fatal("body")
		}
		d.body, _ = json.MarshalIndent(v, "", "  ")
	}
	d.now = d.now.Add(time.Microsecond)
	if id, err := store.RecheckIntent(context.Background(), tx, a); err != nil || id != 1729 {
		t.Fatal(id, err)
	}
	if d.inserts != 1 || d.commits != 0 {
		t.Fatal("recheck rewrote audit or committed")
	}
}

func TestDownloadAdmissionAuditIntegerIDAPI(t *testing.T) {
	d, _, tx, f := downloadAuditFixture(t)
	id, err := (SQLDownloadAdmissionAudits{}).AuditIntent(context.Background(), tx, f)
	if err != nil || id != 1729 || d.inserts != 1 || d.commits != 0 {
		t.Fatal(id, err)
	}
}

func TestDownloadAdmissionAuditFailuresReturnNoAnchor(t *testing.T) {
	for _, fail := range []string{"clock", "non_utc", "driver_time_zone", "insert", "affected", "id", "read", "missing", "zero_id", "large_id", "zero_rows", "many_rows", "zero_time", "nanosecond_time"} {
		t.Run(fail, func(t *testing.T) {
			d, _, tx, f := downloadAuditFixture(t)
			d.fail = fail
			switch fail {
			case "driver_time_zone":
				d.now = d.now.In(time.FixedZone("invalid-driver-location", 3600))
			case "zero_id":
				d.id = 0
			case "large_id":
				d.id = 2147483648
			case "zero_rows":
				d.affected = 0
			case "many_rows":
				d.affected = 2
			case "zero_time":
				d.now = time.Time{}
			case "nanosecond_time":
				d.now = d.now.Add(time.Nanosecond)
			}
			a, err := (SQLDownloadAdmissionAudits{}).StageIntent(context.Background(), tx, f)
			if !errors.Is(err, ErrAudit) || a != (DownloadIntentAuditAnchor{}) || strings.Contains(err.Error(), "private") || d.commits != 0 {
				t.Fatal("failed storage returned partial authority", err)
			}
			if err := tx.Rollback(); err != nil || d.rollbacks != 1 {
				t.Fatal("caller cannot roll back", err)
			}
		})
	}
}

func TestDownloadAdmissionAuditOriginalRowCannotBeRebound(t *testing.T) {
	for _, field := range []string{"actor", "null_actor", "resource", "action", "kind", "time", "installation", "operation", "evidence", "claim", "range", "extra", "invalid_json", "oversize", "clock_backwards"} {
		t.Run(field, func(t *testing.T) {
			d, _, tx, f := downloadAuditFixture(t)
			store := SQLDownloadAdmissionAudits{}
			a, err := store.StageIntent(context.Background(), tx, f)
			if err != nil {
				t.Fatal(err)
			}
			if field == "clock_backwards" {
				d.now = d.now.Add(-time.Microsecond)
			}
			d.mutate = func(d *downloadAuditDB) {
				var body map[string]any
				if json.Unmarshal(d.body, &body) != nil {
					t.Fatal("body")
				}
				switch field {
				case "actor":
					d.user = int64(43)
				case "null_actor":
					d.user = nil
				case "resource":
					d.resource = int64(42)
				case "action":
					d.action = "other"
				case "kind":
					d.kind = "other"
				case "time":
					d.created = d.created.Add(time.Second)
				case "installation":
					body["origin_installation_id"] = "installation_other"
				case "operation":
					body["operation_public_id"] = "sop_33333333-3333-4333-8333-333333333333"
				case "evidence":
					body["evidence_id"] = "sev_33333333-3333-4333-8333-333333333333"
				case "claim":
					body["claim_sha256"] = strings.Repeat("d", 64)
				case "range":
					body["range_end"] = float64(8)
				case "extra":
					body["proof"] = "forbidden"
				case "invalid_json":
					d.body = []byte("[]")
					return
				case "oversize":
					d.body = []byte(strings.Repeat("x", 8193))
					return
				}
				d.body, _ = json.Marshal(body)
			}
			id, err := store.RecheckIntent(context.Background(), tx, a)
			if !errors.Is(err, ErrAudit) || id != 0 || d.inserts != 1 || d.commits != 0 {
				t.Fatal("changed original audit accepted", id, err)
			}
		})
	}
}

func TestDownloadAdmissionAuditRejectsInvalidOrCrossTransactionInput(t *testing.T) {
	d, db, tx, f := downloadAuditFixture(t)
	store := SQLDownloadAdmissionAudits{}
	bad := f
	bad.Claim = "raw-client-claim"
	if a, err := store.StageIntent(context.Background(), tx, bad); !errors.Is(err, ErrInvalid) || a != (DownloadIntentAuditAnchor{}) || d.queries != 0 {
		t.Fatal("invalid data reached SQL")
	}
	if a, err := store.StageIntent(context.Background(), nil, f); !errors.Is(err, ErrAudit) || a != (DownloadIntentAuditAnchor{}) {
		t.Fatal("nil tx")
	}
	a, err := store.StageIntent(context.Background(), tx, f)
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Rollback()
	before := d.queries
	if id, err := store.RecheckIntent(context.Background(), other, a); !errors.Is(err, ErrAudit) || id != 0 || d.queries != before {
		t.Fatal("anchor crossed transactions")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if id, err := store.RecheckIntent(ctx, tx, a); !errors.Is(err, ErrAudit) || id != 0 {
		t.Fatal("cancelled recheck")
	}
	if id, err := store.RecheckIntent(context.Background(), tx, DownloadIntentAuditAnchor{}); !errors.Is(err, ErrAudit) || id != 0 {
		t.Fatal("zero anchor")
	}
}
