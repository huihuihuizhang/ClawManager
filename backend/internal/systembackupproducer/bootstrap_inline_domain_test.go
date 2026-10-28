package systembackupproducer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

type inlineFenceSQLState struct {
	tables        [][]driver.Value
	domain        *DomainRecord
	tamper        bool
	metadataError bool
	probeExisting bool
	probeError    error
}

func inlineFenceTables() [][]driver.Value {
	var rows [][]driver.Value
	for _, name := range bootstrapInlineTables() {
		rows = append(rows, []driver.Value{name, "BASE TABLE", "InnoDB"})
	}
	return rows
}

func inlineFenceFixture(t *testing.T) (*sql.DB, *sql.Tx, *fakeDB, *inlineFenceSQLState, Scope, Hash) {
	t.Helper()
	runner, dbState, _ := setupTx(t)
	domain := recordFixture(t, "DomainRecord").(*DomainRecord)
	scope := domain.Scope
	dbState.server, dbState.database = string(scope.ServerUUID), string(scope.Database)
	state := &inlineFenceSQLState{tables: inlineFenceTables()}
	hash := Hash(strings.Repeat("a", 64))
	domain.Admission = detached(resultFixture(t, "disabled_artifact").Admission)
	domain.Admission.Configured.ConfigVersion, domain.Admission.Configured.ConfigHash = "1", hash
	state.domain = domain
	dbState.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		switch q {
		case "SELECT @@server_uuid,DATABASE()":
			return &fakeRows{values: []driver.Value{dbState.server, dbState.database}}, nil
		case bootstrapInlineSchemaSQL:
			if len(args) != 9 || args[0].Value != string(scope.Database) {
				t.Fatal("metadata scope not pinned", args)
			}
			for i, table := range bootstrapInlineTables() {
				if args[i+1].Value != table {
					t.Fatal("metadata table set changed")
				}
			}
			if state.metadataError {
				return nil, errors.New("PRIVATE metadata error")
			}
			return &storedRows{names: []string{"TABLE_NAME", "TABLE_TYPE", "ENGINE"}, data: state.tables}, nil
		default:
			if strings.HasPrefix(q, "SELECT 1 FROM ") && strings.HasSuffix(q, " LIMIT 0") {
				valid := false
				for _, name := range bootstrapInlineTables() {
					if q == "SELECT 1 FROM "+name+" LIMIT 0" {
						valid = true
					}
				}
				if !valid || len(args) != 0 {
					t.Fatal("unbounded table probe", q, args)
				}
				if state.probeError != nil {
					return nil, state.probeError
				}
				if state.probeExisting {
					return &storedRows{names: []string{"1"}}, nil
				}
				return nil, &mysqldriver.MySQLError{Number: 1146, Message: "owned table does not exist"}
			}
			definition, _ := storageFor(&DomainRecord{})
			keys, _ := recordKeyValues(definition, scope, RecordKey{})
			want := "SELECT " + strings.Join(recordColumns(definition), ",") + " FROM system_backup_producer_domains WHERE scope_key = ? FOR UPDATE"
			if q != want || len(args) != 1 || !reflect.DeepEqual(args[0].Value, keys[0]) {
				t.Fatal("not exact locked domain read", q, args)
			}
			if state.domain == nil {
				return &storedRows{names: recordColumns(definition)}, nil
			}
			rows := rowsForRecord(t, state.domain, true)
			if state.tamper {
				for i, column := range rows.names {
					if column == "record_sha256" {
						rows.data[0][i] = make([]byte, 32)
					}
				}
			}
			return rows, nil
		}
	}
	tx, err := runner.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return runner.db, tx, dbState, state, scope, hash
}

func TestBootstrapInlineDomainFenceLegacyAndHistoricalBranches(t *testing.T) {
	for _, mode := range []string{"schema_absent", "domain_absent", "configured_open", "configured_closed", "configured_revoked", "unconfigured_open", "unconfigured_closed", "unconfigured_revoked", "wrong_hash", "wrong_version", "wrong_scope", "corrupt_record"} {
		t.Run(mode, func(t *testing.T) {
			_, tx, db, state, scope, hash := inlineFenceFixture(t)
			switch mode {
			case "schema_absent":
				state.tables = nil
			case "domain_absent":
				state.domain = nil
			case "wrong_hash":
				state.domain.Admission.Configured.ConfigHash = Hash(strings.Repeat("b", 64))
			case "wrong_version":
				state.domain.Admission.Configured.ConfigVersion = "2"
			case "wrong_scope":
				state.domain.Scope.Installation = "installation_other"
			case "corrupt_record":
				state.tamper = true
			default:
				if strings.HasPrefix(mode, "unconfigured_") {
					state.domain.Admission = detached(resultFixture(t, "unconfigured_artifact").Admission)
				}
				state.domain.State = mode[strings.LastIndex(mode, "_")+1:]
			}
			ctx := context.Background()
			fence, err := LockBootstrapInlineDomain(ctx, tx, scope)
			if mode == "wrong_scope" || mode == "corrupt_record" {
				if err == nil || fence != nil {
					t.Fatal("untrusted domain admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			newErr := fence.CheckLegacyBranch(ctx, tx, hash, false)
			if (mode == "schema_absent") != (newErr == nil) {
				t.Fatal("C1 first initialization bypassed required candidates", mode, newErr)
			}
			historyErr := fence.CheckLegacyBranch(ctx, tx, hash, true)
			allowed := mode == "schema_absent" || mode == "domain_absent" || strings.HasPrefix(mode, "configured_")
			if allowed != (historyErr == nil) {
				t.Fatal("historical branch mismatch", mode, historyErr)
			}
			if err = fence.Recheck(ctx, tx); err != nil {
				t.Fatal("unchanged locked facts rejected", err)
			}
			if db.commits != 0 {
				t.Fatal("fence completed caller transaction")
			}
		})
	}
}

func TestBootstrapInlineDomainFenceRejectsPartialUnknownAndDrift(t *testing.T) {
	for _, mode := range []string{"partial", "duplicate", "unknown", "view", "engine", "null_engine", "metadata_error", "hidden_table", "hidden_denied", "absence_unknown_error", "late_schema", "late_partial", "late_domain", "late_epoch", "late_record", "late_database"} {
		t.Run(mode, func(t *testing.T) {
			_, tx, database, state, scope, _ := inlineFenceFixture(t)
			switch mode {
			case "partial":
				state.tables = state.tables[:7]
			case "duplicate":
				state.tables = append(state.tables, append([]driver.Value(nil), state.tables[0]...))
			case "unknown":
				state.tables[0][0] = "unreviewed_table"
			case "view":
				state.tables[0][1] = "VIEW"
			case "engine":
				state.tables[0][2] = "MyISAM"
			case "null_engine":
				state.tables[0][2] = nil
			case "metadata_error":
				state.metadataError = true
			case "hidden_table":
				state.tables, state.probeExisting = nil, true
			case "hidden_denied":
				state.tables, state.probeError = nil, &mysqldriver.MySQLError{Number: 1142, Message: "PRIVATE permission denied"}
			case "absence_unknown_error":
				state.tables, state.probeError = nil, errors.New("PRIVATE unknown SQL failure")
			case "late_schema":
				state.tables = nil
			case "late_domain":
				state.domain = nil
			}
			ctx := context.Background()
			fence, err := LockBootstrapInlineDomain(ctx, tx, scope)
			if !strings.HasPrefix(mode, "late_") {
				if err == nil || fence != nil || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("invalid storage accepted or leaked", mode, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "late_schema":
				state.tables = inlineFenceTables()
			case "late_partial":
				state.tables = state.tables[:7]
			case "late_domain":
				state.domain = recordFixture(t, "DomainRecord").(*DomainRecord)
			case "late_epoch":
				state.domain.Epoch, state.domain.RowVersion = "2", "2"
			case "late_record":
				state.tamper = true
			case "late_database":
				database.database = "different_database"
			}
			if fence.Recheck(ctx, tx) == nil {
				t.Fatal("late storage/domain drift ignored", mode)
			}
		})
	}
}

func TestBootstrapInlineDomainFenceBindingAndRedaction(t *testing.T) {
	db, tx, driverState, _, scope, hash := inlineFenceFixture(t)
	ctx := context.Background()
	fence, err := LockBootstrapInlineDomain(ctx, tx, scope)
	if err != nil {
		t.Fatal(err)
	}
	copy := *fence
	for _, value := range []any{fence, *fence, &copy} {
		if fmt.Sprintf("%v %#v", value, value) != "BootstrapInlineDomainFence BootstrapInlineDomainFence" {
			t.Fatal("captured facts leaked")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatal("captured facts serialized", err)
		}
	}
	var zero BootstrapInlineDomainFence
	if json.Unmarshal([]byte(`{}`), &zero) == nil || zero.CheckLegacyBranch(ctx, tx, hash, true) == nil {
		t.Fatal("zero/JSON minted fence")
	}
	other, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Rollback()
	wrong, cancel := context.WithCancel(ctx)
	defer cancel()
	before := len(driverState.events)
	for _, check := range []func() error{
		func() error { return fence.Recheck(wrong, tx) },
		func() error { return fence.Recheck(ctx, other) },
		func() error { return fence.CheckLegacyBranch(wrong, tx, hash, true) },
		func() error { return copy.CheckLegacyBranch(ctx, other, hash, true) },
	} {
		if !errors.Is(check(), ErrGuardRequired) {
			t.Fatal("rebound fence accepted")
		}
	}
	if len(driverState.events) != before {
		t.Fatal("rebound fence dispatched SQL")
	}
	cancel()
	if _, err := LockBootstrapInlineDomain(wrong, tx, scope); err == nil {
		t.Fatal("canceled preparation accepted")
	}
}
