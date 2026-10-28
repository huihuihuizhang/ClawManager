package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

const maintenanceTestReceiptID = "12345678-1234-1234-1234-123456789abc"
const maintenanceTestRequestID = "maintenance-request-001"

// Transport/transaction model only: actual InnoDB constraints, locking and
// unknown COMMIT remain a separate remote acceptance requirement for 082.
type maintenanceReceiptSQLState struct {
	base     *backfillLockedSQLState
	receipt  map[string]driver.Value
	audits   map[int64][]driver.Value
	columns  []string
	mode     string
	callback func(string)
	inserts  int
}
type maintenanceReceiptConnector struct{ s *maintenanceReceiptSQLState }

func (maintenanceReceiptConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c maintenanceReceiptConnector) Connect(context.Context) (driver.Conn, error) {
	return &maintenanceReceiptConn{backfillLockedConn: backfillLockedConn{s: c.s.base}, s: c.s}, nil
}

type maintenanceReceiptConn struct {
	backfillLockedConn
	s              *maintenanceReceiptSQLState
	priorCanonical driver.Value
}

func (c *maintenanceReceiptConn) Begin() (driver.Tx, error) {
	c.priorCanonical = c.s.base.cells["canonical_config_json"]
	return c, nil
}
func (c *maintenanceReceiptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *maintenanceReceiptConn) Rollback() error {
	c.s.base.rollbacks++
	c.s.receipt = nil
	c.s.audits = map[int64][]driver.Value{}
	c.s.base.cells["canonical_config_json"] = c.priorCanonical
	return nil
}
func (c *maintenanceReceiptConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if q == configMaintenanceReceiptSelect {
		want := []driver.Value{s.base.facts.TargetServerUUID, s.base.facts.TargetDatabase, s.base.facts.InstallationID, strings.Repeat("a", 64), "maintenance-key-0001"}
		if len(args) != len(want) {
			return nil, errors.New("receipt scope length")
		}
		for i, v := range want {
			if args[i].Value != v {
				return nil, errors.New("receipt scope binding")
			}
		}
		if s.callback != nil {
			s.callback("receipt-query")
		}
		if s.mode == "query-error" {
			return nil, errors.New("receipt query error")
		}
		values := make([]driver.Value, len(s.columns))
		for i, name := range s.columns {
			values[i] = s.receipt[name]
		}
		count := 1
		if s.receipt == nil {
			count = 0
		}
		if s.mode == "duplicate-row" {
			count = 2
		}
		return &maintenanceReceiptRows{s: s, values: values, count: count}, nil
	}
	if q == "SELECT user_id,action,resource_type,resource_id,details,created_at FROM audit_logs WHERE id=? FOR UPDATE" {
		if len(args) != 1 {
			return nil, errors.New("audit scope")
		}
		id, ok := args[0].Value.(int64)
		if !ok {
			return nil, errors.New("audit ID")
		}
		if s.callback != nil {
			s.callback("audit-query")
		}
		if cells, found := s.audits[id]; found {
			return registrationRow(cells...), nil
		}
		return &maintenanceReceiptRows{s: s, count: 0}, nil
	}
	return c.backfillLockedConn.QueryContext(ctx, q, args)
}

type maintenanceReceiptResult struct{ mode string }

func (r maintenanceReceiptResult) LastInsertId() (int64, error) {
	if r.mode == "id-error" {
		return 0, errors.New("ID unavailable")
	}
	if r.mode == "zero-id" {
		return 0, nil
	}
	return 19, nil
}
func (r maintenanceReceiptResult) RowsAffected() (int64, error) {
	if r.mode == "affected-error" {
		return 0, errors.New("affected unavailable")
	}
	if r.mode == "zero-affected" {
		return 0, nil
	}
	return 1, nil
}
func (c *maintenanceReceiptConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	s.inserts++
	if q != configMaintenanceReceiptInsert {
		return nil, errors.New("unexpected canonical/audit write")
	}
	if s.mode == "duplicate-key" {
		return nil, &mysql.MySQLError{Number: 1062, Message: "private diagnostic"}
	}
	if s.mode == "insert-error" {
		return nil, errors.New("private diagnostic")
	}
	names := maintenanceReceiptInsertNames()
	if len(args) != len(names) {
		return nil, errors.New("INSERT required columns")
	}
	s.receipt = map[string]driver.Value{"id": int64(19)}
	for i, name := range names {
		v := args[i].Value
		if b, ok := v.([]byte); ok {
			v = append([]byte(nil), b...)
		}
		s.receipt[name] = v
	}
	if s.mode == "driver-buffer-mutation" {
		b := args[22].Value.([]byte)
		b[0] = '!'
	}
	if s.callback != nil {
		s.callback("insert")
	}
	return maintenanceReceiptResult{s.mode}, nil
}

type maintenanceReceiptRows struct {
	s      *maintenanceReceiptSQLState
	values []driver.Value
	count  int
	closed bool
}

func (r *maintenanceReceiptRows) Columns() []string { return r.s.columns }
func (r *maintenanceReceiptRows) Close() error {
	if !r.closed {
		r.closed = true
		if r.s.callback != nil {
			r.s.callback("receipt-close")
		}
	}
	if r.s.mode == "close-error" {
		return errors.New("close error")
	}
	return nil
}
func (r *maintenanceReceiptRows) Next(dest []driver.Value) error {
	if r.s.callback != nil {
		r.s.callback("receipt-next")
	}
	if r.count == 0 {
		if r.s.mode == "rows-error" {
			return errors.New("rows error")
		}
		return io.EOF
	}
	r.count--
	copy(dest, r.values)
	return nil
}
func maintenanceReceiptInsertNames() []string {
	start := strings.Index(configMaintenanceReceiptInsert, " (") + 2
	end := strings.Index(configMaintenanceReceiptInsert, ") VALUES")
	return strings.Split(configMaintenanceReceiptInsert[start:end], ",")
}
func maintenanceReceiptFixture(t *testing.T) (*sql.DB, *sql.Tx, *maintenanceReceiptSQLState, configMaintenanceScope, []byte) {
	t.Helper()
	oldDB, oldTx, base, original, rowSHA := backfillLockedFixture(t)
	if err := oldTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := oldDB.Close(); err != nil {
		t.Fatal(err)
	}
	base.rollbacks = 0
	s := &maintenanceReceiptSQLState{base: base, audits: map[int64][]driver.Value{}}
	s.columns = append([]string{"id"}, maintenanceReceiptInsertNames()...)
	sort.Sort(sort.Reverse(sort.StringSlice(s.columns)))
	var request map[string]any
	if json.Unmarshal(maintenanceDigestVectors(t)[3].Input, &request) != nil {
		t.Fatal("A request fixture")
	}
	request["target_server_uuid"], request["target_database"], request["origin_installation_id"] = base.facts.TargetServerUUID, base.facts.TargetDatabase, base.facts.InstallationID
	request["maintenance_actor_sha256"], request["config_version"] = strings.Repeat("a", 64), base.facts.Version
	request["original_config_sha256"], request["original_config_size_bytes"], request["expected_row_sha256"] = base.facts.ConfigSHA256, base.facts.ConfigSizeBytes, rowSHA
	request["reason"] = "private-maintenance-reason-sentinel"
	raw, _ := json.Marshal(request)
	scope, err := newConfigMaintenanceScope(DatabaseIdentity{base.facts.TargetServerUUID, base.facts.TargetDatabase}, base.facts.InstallationID, strings.Repeat("a", 64), "maintenance-key-0001", raw)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(maintenanceReceiptConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return db, tx, s, scope, original
}
func maintenanceReceiptAudits(t *testing.T, s *maintenanceReceiptSQLState, scope configMaintenanceScope, wrote bool) {
	t.Helper()
	for i, phase := range []string{"intent", "result"} {
		raw, err := canonicalConfigMaintenanceAudit(scope, maintenanceTestReceiptID, maintenanceTestRequestID, phase, wrote)
		if err != nil {
			t.Fatal(err)
		}
		// Exercise MySQL JSON's non-canonical whitespace, without changing values.
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "", " ") != nil {
			t.Fatal("audit JSON")
		}
		s.audits[int64(i+11)] = []driver.Value{nil, "system_backup.config_canonical_backfill." + phase, "system_backup", nil, pretty.Bytes(), s.base.now.Add(time.Duration(i-2) * time.Microsecond)}
	}
}
func maintenanceReceiptStage(t *testing.T, tx *sql.Tx, s *maintenanceReceiptSQLState, scope configMaintenanceScope, original []byte, wrote bool) (configMaintenanceReceiptSnapshot, error) {
	t.Helper()
	if !wrote {
		s.base.cells["canonical_config_json"] = append([]byte(nil), original...)
	}
	before, err := backfillLockedRead(context.Background(), tx, s.base, original)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		s.base.cells["canonical_config_json"] = append([]byte(nil), original...)
	} // explicit caller fill, never performed by store
	maintenanceReceiptAudits(t, s, scope, wrote)
	return stageConfigMaintenanceReceipt(context.Background(), tx, scope, before, maintenanceTestReceiptID, maintenanceTestRequestID, 11, 12)
}
func maintenanceReceiptEmpty(t *testing.T, r configMaintenanceReceiptSnapshot, err error) {
	t.Helper()
	if err == nil || r.tx != nil || r.raw != nil || r.id != "" {
		t.Fatal("failed storage returned usable receipt", err)
	}
}

func TestConfigMaintenanceReceiptCallerFillNoChangeReplayAndRollback(t *testing.T) {
	for _, wrote := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-change", true: "caller-fill"}[wrote], func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			r, err := maintenanceReceiptStage(t, tx, s, scope, original, wrote)
			if err != nil {
				t.Fatal(err)
			}
			if r.policy.wrote != wrote || s.inserts != 1 || s.base.writes != 0 || s.base.commits != 0 || s.base.rollbacks != 0 {
				t.Fatal("store changed caller transaction/canonical ownership")
			}
			if err = r.recheck(context.Background(), tx); err != nil {
				t.Fatal(err)
			}
			replay, err := loadConfigMaintenanceReceipt(context.Background(), tx, scope, r.row)
			if err != nil || !bytes.Equal(replay.bytes(), r.bytes()) || s.inserts != 1 {
				t.Fatal("original byte replay", err)
			}
			copy := r.bytes()
			copy[0] = '!'
			if bytes.Equal(copy, r.bytes()) {
				t.Fatal("receipt getter aliases state")
			}
			if _, err = json.Marshal(r); err == nil {
				t.Fatal("private observation serializes")
			}
			if _, err = json.Marshal(scope); err == nil {
				t.Fatal("private reason serializes")
			}
			for _, body := range [][]byte{r.bytes(), s.audits[11][4].([]byte), s.audits[12][4].([]byte)} {
				for _, secret := range []string{"private-maintenance-reason-sentinel", string(original), "archive_locator", "proof", "token", "created_by", "change_reason"} {
					if bytes.Contains(body, []byte(secret)) {
						t.Fatal("private field leaked", secret)
					}
				}
			}
			var body map[string]any
			if json.Unmarshal(r.bytes(), &body) != nil || len(body) != 27 || body["request_profile"] != ConfigMaintenanceDigestProfile || body["row_identity_profile"] != ConfigBackfillRowProfile || body["source_provenance_profile"] != ConfigBackfillProvenanceProfile {
				t.Fatal("receipt closed profiles", len(body))
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if s.receipt != nil || len(s.audits) != 0 || s.base.cells["canonical_config_json"] != nil {
				t.Fatal("caller rollback failed in transaction model")
			}
		})
	}
}
func TestConfigMaintenanceReceiptDoesNotFillOrSelfAuthorize(t *testing.T) {
	_, tx, s, scope, original := maintenanceReceiptFixture(t)
	row, err := backfillLockedRead(context.Background(), tx, s.base, original)
	if err != nil {
		t.Fatal(err)
	}
	r, err := loadConfigMaintenanceReceipt(context.Background(), tx, scope, row)
	if !errors.Is(err, errConfigMaintenanceReceiptMissing) {
		t.Fatal("missing receipt conflated", err)
	}
	maintenanceReceiptEmpty(t, r, err)
	maintenanceReceiptAudits(t, s, scope, true)
	r, err = stageConfigMaintenanceReceipt(context.Background(), tx, scope, row, maintenanceTestReceiptID, maintenanceTestRequestID, 11, 12)
	maintenanceReceiptEmpty(t, r, err)
	if s.inserts != 0 || s.base.writes != 0 || s.base.cells["canonical_config_json"] != nil {
		t.Fatal("store filled canonical")
	}
	// A well-shaped client digest cannot change independently admitted bindings.
	for _, name := range []string{"server", "database", "installation", "actor", "key"} {
		t.Run(name, func(t *testing.T) {
			db, install, actor, key := scope.database, scope.identity.Installation, scope.identity.Actor, scope.key
			switch name {
			case "server":
				db.ServerUUID = "22345678-1234-1234-1234-123456789abc"
			case "database":
				db.Database += "_other"
			case "installation":
				install += "_other"
			case "actor":
				actor = strings.Repeat("b", 64)
			case "key":
				key = "short"
			}
			if _, err := newConfigMaintenanceScope(db, install, actor, key, scope.canonical); err == nil {
				t.Fatal("unbound scope admitted")
			}
		})
	}
}
func TestConfigMaintenanceReceiptEveryStoredSQLFact(t *testing.T) {
	for _, name := range append([]string{"id"}, maintenanceReceiptInsertNames()...) {
		t.Run(name, func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			r, err := maintenanceReceiptStage(t, tx, s, scope, original, true)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "id":
				s.receipt[name] = true
			case "config_version", "original_config_size_bytes", "intent_audit_id", "result_audit_id", "redacted_response_size_bytes":
				s.receipt[name] = int64(0)
			case "wrote":
				s.receipt[name] = int64(2)
			case "created_at":
				s.receipt[name] = s.base.now.Add(time.Microsecond)
			default:
				s.receipt[name] = "corrupt-private-value"
			}
			got, err := loadConfigMaintenanceReceipt(context.Background(), tx, scope, r.row)
			maintenanceReceiptEmpty(t, got, err)
		})
	}
}
func TestConfigMaintenanceReceiptPermanentKeyAndOriginalBody(t *testing.T) {
	for _, name := range []string{"grant-version", "reason", "body-unknown", "body-whitespace", "body-profile", "body-duplicate", "audit-correlation"} {
		t.Run(name, func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			r, err := maintenanceReceiptStage(t, tx, s, scope, original, false)
			if err != nil {
				t.Fatal(err)
			}
			wantConflict := false
			if name == "grant-version" || name == "reason" {
				var request map[string]any
				json.Unmarshal(scope.canonical, &request)
				if name == "grant-version" {
					request["grant_version"] = "next-grant-version"
				} else {
					request["reason"] = "changed reason"
				}
				raw, _ := json.Marshal(request)
				scope, err = newConfigMaintenanceScope(scope.database, scope.identity.Installation, scope.identity.Actor, scope.key, raw)
				if err != nil {
					t.Fatal(err)
				}
				wantConflict = true
			} else if name == "audit-correlation" {
				s.audits[12][4] = bytes.ReplaceAll(s.audits[12][4].([]byte), []byte(maintenanceTestRequestID), []byte("another-request-001"))
			} else {
				raw := string(r.raw)
				switch name {
				case "body-unknown":
					raw = strings.TrimSuffix(raw, "}") + `,"extra":true}`
				case "body-whitespace":
					raw = " " + raw
				case "body-profile":
					raw = strings.Replace(raw, ConfigBackfillRowProfile, "unaccepted-profile", 1)
				case "body-duplicate":
					raw = strings.TrimSuffix(raw, "}") + `,"wrote":false}`
				}
				s.receipt["redacted_response_canonical_json"] = []byte(raw)
				s.receipt["redacted_response_sha256"] = registrationHash(raw)
				s.receipt["redacted_response_size_bytes"] = int64(len(raw))
			}
			got, err := loadConfigMaintenanceReceipt(context.Background(), tx, scope, r.row)
			maintenanceReceiptEmpty(t, got, err)
			if wantConflict && !errors.Is(err, ErrRegistrationConflict) {
				t.Fatal("key reopened across new grant/reason", err)
			}
			if s.inserts != 1 {
				t.Fatal("observation wrote receipt")
			}
		})
	}
}
func TestConfigMaintenanceReceiptAuditsMustBeActualClosedAnchors(t *testing.T) {
	for _, name := range []string{"missing", "admin-user", "resource", "action", "type", "future", "submicrosecond", "order", "request", "actor", "unknown", "reason", "duplicate", "same-id", "bad-receipt-id", "bad-request-id"} {
		t.Run(name, func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			before, err := backfillLockedRead(context.Background(), tx, s.base, original)
			if err != nil {
				t.Fatal(err)
			}
			s.base.cells["canonical_config_json"] = original
			maintenanceReceiptAudits(t, s, scope, true)
			a := s.audits[11]
			receiptID, requestID, resultID := maintenanceTestReceiptID, maintenanceTestRequestID, int64(12)
			switch name {
			case "missing":
				delete(s.audits, 11)
			case "admin-user":
				a[0] = int64(3)
			case "resource":
				a[3] = int64(3)
			case "action":
				a[1] = "system_backup.config_update.intent"
			case "type":
				a[2] = "config"
			case "future":
				a[5] = s.base.now.Add(time.Hour)
			case "submicrosecond":
				a[5] = s.base.now.Add(-time.Nanosecond)
			case "order":
				a[5] = s.base.now
			case "request":
				requestID = "different-request-001"
			case "actor":
				a[4] = bytes.ReplaceAll(a[4].([]byte), []byte(scope.identity.Actor), []byte(strings.Repeat("b", 64)))
			case "unknown", "reason", "duplicate":
				raw, _ := canonicalConfigMaintenanceAudit(scope, receiptID, requestID, "intent", true)
				extra := `,"extra":true}`
				if name == "reason" {
					extra = `,"reason":"private"}`
				}
				if name == "duplicate" {
					extra = `,"wrote":true}`
				}
				a[4] = []byte(strings.TrimSuffix(string(raw), "}") + extra)
			case "same-id":
				resultID = 11
			case "bad-receipt-id":
				receiptID = "not-uuid"
			case "bad-request-id":
				requestID = "bad/request"
			}
			got, err := stageConfigMaintenanceReceipt(context.Background(), tx, scope, before, receiptID, requestID, 11, resultID)
			maintenanceReceiptEmpty(t, got, err)
			if s.inserts != 0 {
				t.Fatal("invalid audit reached INSERT")
			}
		})
	}
}
func TestConfigMaintenanceReceiptTransportFailuresAndFinalGuard(t *testing.T) {
	for _, name := range []string{"column-extra", "column-missing", "column-duplicate", "duplicate-row", "query-error", "rows-error", "close-error", "row-drift", "target-drift-after-audit", "cancel-after-audit", "other-tx", "same-body-driver-mutation"} {
		t.Run(name, func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			r, err := maintenanceReceiptStage(t, tx, s, scope, original, true)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "column-extra":
				s.columns = append(s.columns, "extra")
			case "column-missing":
				s.columns = s.columns[1:]
			case "column-duplicate":
				s.columns[0] = s.columns[1]
			case "row-drift":
				s.base.cells["created_by"] = "drift"
			case "target-drift-after-audit":
				s.callback = func(stage string) {
					if stage == "audit-query" {
						s.base.wrongDatabase = true
					}
				}
			case "cancel-after-audit":
				s.callback = func(stage string) {
					if stage == "audit-query" {
						cancel()
					}
				}
			case "same-body-driver-mutation":
				s.callback = func(stage string) {
					if stage == "receipt-close" {
						b := s.receipt["redacted_response_canonical_json"].([]byte)
						b[0] = '!'
					}
				}
			case "other-tx":
				other := &sql.Tx{}
				if r.recheck(ctx, other) == nil {
					t.Fatal("another tx accepted")
				}
				return
			default:
				s.mode = name
			}
			err = r.recheck(ctx, tx)
			if name == "same-body-driver-mutation" {
				if err != nil {
					t.Fatal("driver buffer escaped copied SQL snapshot", err)
				}
				s.callback = nil
				if r.recheck(ctx, tx) == nil {
					t.Fatal("later corruption ignored")
				}
			} else if err == nil {
				t.Fatal("final guard accepted drift", name)
			}
		})
	}
}
func TestConfigMaintenanceReceiptInsertResultsAndBufferOwnership(t *testing.T) {
	for _, mode := range []string{"insert-error", "duplicate-key", "affected-error", "zero-affected", "id-error", "zero-id", "driver-buffer-mutation"} {
		t.Run(mode, func(t *testing.T) {
			_, tx, s, scope, original := maintenanceReceiptFixture(t)
			s.mode = mode
			r, err := maintenanceReceiptStage(t, tx, s, scope, original, true)
			if mode == "driver-buffer-mutation" {
				if err != nil || r.raw[0] != '{' {
					t.Fatal("driver argument aliases original response", err)
				}
				return
			}
			maintenanceReceiptEmpty(t, r, err)
			if mode == "duplicate-key" && !errors.Is(err, ErrRegistrationConflict) {
				t.Fatal("unique key was reopened", err)
			}
			if err != nil && strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("raw SQL diagnostic leaked")
			}
			if s.base.commits != 0 || s.base.rollbacks != 0 {
				t.Fatal("store finalized caller tx")
			}
		})
	}
}
func TestConfigMaintenanceReceiptDDLAndPermanentScope(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/system-backup-d-config-maintenance-082-proposal-20261015.sql")
	if err != nil {
		t.Fatal(err)
	}
	ddl := string(raw)
	columns := regexp.MustCompile(`(?m)^  ([a-z_0-9]+) (?:BIGINT|VARCHAR|CHAR|ENUM|INT|BOOLEAN|MEDIUMBLOB|DATETIME)`).FindAllStringSubmatch(ddl, -1)
	names := []string{}
	for _, m := range columns {
		names = append(names, m[1])
	}
	sort.Strings(names)
	if len(names) != 27 || registrationHash(strings.Join(names, "\n")) != configMaintenanceReceiptColumnsSHA256 {
		t.Fatal("082 closed column set drift")
	}
	insert := append([]string{"id"}, maintenanceReceiptInsertNames()...)
	sort.Strings(insert)
	if strings.Join(insert, ",") != strings.Join(names, ",") {
		t.Fatal("required non-default SQL column omitted")
	}
	if strings.Count(configMaintenanceReceiptInsert, "?") != 26 {
		t.Fatal("INSERT placeholders")
	}
	if !strings.Contains(ddl, "(target_server_uuid,target_database,origin_installation_id,maintenance_actor_sha256,action,idempotency_key)") {
		t.Fatal("permanent key scope changed")
	}
	if strings.Contains(configMaintenanceReceiptSelect, "grant_version") || strings.Contains(configMaintenanceReceiptSelect, "request_sha256") {
		t.Fatal("new grant/hash reopens key")
	}
}

func TestConfigMaintenanceReceiptCodecBoundsAndOwnedRequest(t *testing.T) {
	_, _, s, scope, _ := maintenanceReceiptFixture(t)
	raw := append([]byte(nil), scope.canonical...)
	copy, err := newConfigMaintenanceScope(scope.database, scope.identity.Installation, scope.identity.Actor, scope.key, raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = '!'
	if !copy.valid() {
		t.Fatal("scope retained caller buffer")
	}
	base := configMaintenanceReceiptPolicy{scope: copy, receiptID: maintenanceTestReceiptID, requestID: maintenanceTestRequestID, intentID: 11, resultID: 12, createdAt: s.base.now}
	for _, name := range []string{"id-zero", "id-overflow", "same-id", "zero-time", "year", "offset", "fraction", "scope-hash", "scope-identity", "scope-bytes"} {
		t.Run(name, func(t *testing.T) {
			p := base
			switch name {
			case "id-zero":
				p.intentID = 0
			case "id-overflow":
				p.resultID = 2147483648
			case "same-id":
				p.resultID = p.intentID
			case "zero-time":
				p.createdAt = time.Time{}
			case "year":
				p.createdAt = time.Date(999, 1, 1, 0, 0, 0, 0, time.UTC)
			case "offset":
				p.createdAt = p.createdAt.In(time.FixedZone("shift", 3600))
			case "fraction":
				p.createdAt = p.createdAt.Add(time.Nanosecond)
			case "scope-hash":
				p.scope.hash = strings.Repeat("f", 64)
			case "scope-identity":
				p.scope.identity.ProvenanceSHA = strings.Repeat("f", 64)
			case "scope-bytes":
				p.scope.canonical = append([]byte(" "), p.scope.canonical...)
			}
			if body, err := canonicalConfigMaintenanceReceipt(p); err == nil || body != nil {
				t.Fatal("invalid receipt policy admitted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`null`), []byte(`[]`), []byte(`{"x":true,"x":false}`), []byte(`{"x":"\ud800"}`), []byte("{\"x\":\"\xff\"}"), []byte(`{"x":1} {}`)} {
		if body, err := canonicalMaintenanceStoredJSON(raw); err == nil || body != nil {
			t.Fatal("ambiguous stored audit JSON admitted")
		}
	}
}
