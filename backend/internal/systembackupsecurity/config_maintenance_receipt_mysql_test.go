//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupcontroller"
	"github.com/go-sql-driver/mysql"
)

const configMaintenanceCandidateSHA256 = "e1a95c7863065580819e28353fa984fa8a98701ca2eeae57aff7ba5159a43b87"

//go:embed testdata/config_maintenance_candidate_082.sql
var configMaintenanceCandidateFixture string

var errMaintenanceProbeResultAudit = errors.New("maintenance_probe_result_audit")
var errMaintenanceProbeReceipt = errors.New("maintenance_probe_receipt")

type configMaintenanceProbeInputs struct {
	Kind              string          `json:"kind"`
	WriterInputs      json.RawMessage `json:"writer_inputs"`
	MaintenanceDDL    string          `json:"maintenance_ddl"`
	MaintenanceSHA256 string          `json:"maintenance_sha256"`
}

func decodeConfigMaintenanceProbeInputs(raw []byte, digest string) (configMaintenanceProbeInputs, configWriterProbeInputs, configProofProbeInputs, error) {
	var input configMaintenanceProbeInputs
	var fields map[string]json.RawMessage
	if len(raw) > 65536 || registrationHash(string(raw)) != digest || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) || json.Unmarshal(raw, &fields) != nil || !providerFieldSet(fields, "kind", "writer_inputs", "maintenance_ddl", "maintenance_sha256") || json.Unmarshal(raw, &input) != nil || input.Kind != "d_config_maintenance_receipt_probe_inputs.v1" || input.MaintenanceSHA256 != configMaintenanceCandidateSHA256 || registrationHash(input.MaintenanceDDL) != input.MaintenanceSHA256 {
		return input, configWriterProbeInputs{}, configProofProbeInputs{}, ErrConfigMutation
	}
	w, base, err := decodeConfigWriterProbeInputs(input.WriterInputs, registrationHash(string(input.WriterInputs)))
	return input, w, base, err
}
func maintenanceProbeUUID() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	// Random v4 UUID for probe ownership/correlation, never a runtime grant.
	entropy[6] = (entropy[6] & 15) | 64
	entropy[8] = (entropy[8] & 63) | 128
	s := hex.EncodeToString(entropy[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

// Synthetic request pins exercise representation/storage only. In particular,
// these shapes and digests authenticate no maintenance actor, grant or archive.
func maintenanceProbeScope(identity DatabaseIdentity, installation, key string, original []byte, rowSHA string) (configMaintenanceScope, error) {
	actor, err := ConfigMaintenanceActorSHA256("https://synthetic-maintenance.invalid", "probe-subject")
	if err != nil {
		return configMaintenanceScope{}, err
	}
	grant, err := ConfigMaintenanceGrantIdentitySHA256("https://synthetic-maintenance.invalid", "probe-grant")
	if err != nil {
		return configMaintenanceScope{}, err
	}
	_, sourceSHA, err := CanonicalConfigBackfillProvenance(ConfigBackfillProvenanceFacts{TargetServerUUID: identity.ServerUUID, TargetDatabase: identity.Database, InstallationID: installation, Version: 1, ConfigSizeBytes: int64(len(original)), ConfigSHA256: registrationHash(string(original)), SourceIssuer: "synthetic-maintenance-probe", SourceID: "generated-fixture", SourceVersion: "v1", AttestationSHA256: registrationHash("synthetic-no-source-authentication")})
	if err != nil {
		return configMaintenanceScope{}, err
	}
	raw, err := json.Marshal(map[string]any{"domain": "clawmanager.system-backup.config-canonical-backfill-request.v1", "action": "config_canonical_backfill", "target_server_uuid": identity.ServerUUID, "target_database": identity.Database, "origin_installation_id": installation, "maintenance_actor_sha256": actor, "grant_identity_sha256": grant, "grant_version": "synthetic-v1", "config_version": 1, "original_config_sha256": registrationHash(string(original)), "original_config_size_bytes": len(original), "expected_row_sha256": rowSHA, "source_provenance_sha256": sourceSHA, "schema_sha256": registrationHash(configWriterCandidateFixture + configMaintenanceCandidateFixture), "catalog_sha256": systembackupcontroller.ContractMigrationCatalogHash, "migration_sha256": configMaintenanceCandidateSHA256, "reason": "synthetic maintenance storage probe"})
	if err != nil {
		return configMaintenanceScope{}, err
	}
	return newConfigMaintenanceScope(identity, installation, actor, key, raw)
}

type maintenanceMySQLFixture struct {
	db           *sql.DB
	identity     DatabaseIdentity
	installation string
	original     []byte
	scope        configMaintenanceScope
}

func newMaintenanceMySQLFixture(t *testing.T, ctx context.Context, db *sql.DB, identity DatabaseIdentity) *maintenanceMySQLFixture {
	t.Helper()
	id, err := maintenanceProbeUUID()
	mysqlMust(t, err)
	f := &maintenanceMySQLFixture{db: db, identity: identity, installation: "installation_maintenance_probe_" + strings.ReplaceAll(id, "-", "")}
	config, err := DecodeBootstrapConfig(bootstrapFixture(t))
	mysqlMust(t, err)
	f.original = config.CanonicalJSON()
	// Insert the complete generated legacy row without a canonical value. Never
	// discover/modify an existing installation or reconstruct historical bytes.
	columns, args := config.sqlValues(f.installation, "synthetic-maintenance-probe", "synthetic original row")
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	mysqlMust(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		tx, e := db.BeginTx(cleanup, nil)
		if e != nil {
			t.Error("CLEANUP_PENDING maintenance connection")
			return
		}
		defer tx.Rollback()
		if identity.check(cleanup, tx) != nil {
			t.Error("CLEANUP_PENDING maintenance identity")
			return
		}
		for _, q := range []string{"DELETE FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?", "DELETE FROM audit_logs WHERE action IN ('system_backup.config_canonical_backfill.intent','system_backup.config_canonical_backfill.result') AND JSON_UNQUOTE(JSON_EXTRACT(details,'$.origin_installation_id'))=?", "DELETE FROM system_backup_v2_configs WHERE origin_installation_id=?"} {
			if _, e = tx.ExecContext(cleanup, q, f.installation); e != nil {
				t.Error("CLEANUP_PENDING maintenance owned rows")
				return
			}
		}
		if e = tx.Commit(); e != nil {
			t.Error("CLEANUP_PENDING maintenance cleanup commit")
			return
		}
		var n int
		if db.QueryRowContext(cleanup, "SELECT (SELECT COUNT(*) FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?)+(SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=?)+(SELECT COUNT(*) FROM audit_logs WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'$.origin_installation_id'))=?)", f.installation, f.installation, f.installation).Scan(&n) != nil || n != 0 {
			t.Error("CLEANUP_PENDING maintenance row absence")
			return
		}
		t.Log("CLEANED maintenance owned receipts/audits/config rows")
	})
	tx, err := db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	defer tx.Rollback()
	row, err := f.read(ctx, tx)
	mysqlMust(t, err)
	f.scope, err = maintenanceProbeScope(identity, f.installation, "maintenance_mysql_key_012345", f.original, row.rowSHA256)
	mysqlMust(t, err)
	mysqlMust(t, tx.Rollback())
	return f
}
func (f *maintenanceMySQLFixture) read(ctx context.Context, tx *sql.Tx) (lockedConfigBackfillRow, error) {
	return readLockedConfigBackfillRow(ctx, tx, f.identity, f.installation, 1, f.original)
}

// Test-only orchestration with synthetic admission. This is not the production
// maintenance writer: no grant/source/capacity or public success is issued.
func (f *maintenanceMySQLFixture) prepare(ctx context.Context, tx *sql.Tx) (configMaintenanceReceiptSnapshot, error) {
	zero := configMaintenanceReceiptSnapshot{}
	row, err := f.read(ctx, tx)
	if err != nil {
		return zero, err
	}
	existing, err := loadConfigMaintenanceReceipt(ctx, tx, f.scope, row)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, errConfigMaintenanceReceiptMissing) {
		return zero, err
	}
	receiptID, err := maintenanceProbeUUID()
	if err != nil {
		return zero, err
	}
	wrote := row.canonical == configBackfillCanonicalNull
	audit := func(phase string) (int64, error) {
		raw, e := canonicalConfigMaintenanceAudit(f.scope, receiptID, receiptID, phase, wrote)
		if e != nil {
			return 0, e
		}
		result, e := tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,resource_id,details,created_at) VALUES(NULL,?,'system_backup',NULL,?,UTC_TIMESTAMP())", "system_backup.config_canonical_backfill."+phase, string(raw))
		if e != nil {
			return 0, e
		}
		return result.LastInsertId()
	}
	intent, err := audit("intent")
	if err != nil {
		return zero, err
	}
	if wrote {
		result, e := tx.ExecContext(ctx, "UPDATE system_backup_v2_configs SET canonical_config_json=? WHERE id=? AND origin_installation_id=? AND version=1 AND canonical_config_json IS NULL AND config_sha256=?", append([]byte(nil), f.original...), row.rowID, f.installation, f.scope.identity.ConfigSHA)
		if !configMutationOne(result, e) {
			return zero, ErrConfigMutation
		}
	}
	resultID, err := audit("result")
	if err != nil {
		return zero, errors.Join(errMaintenanceProbeResultAudit, err)
	}
	r, err := stageConfigMaintenanceReceipt(ctx, tx, f.scope, row, receiptID, receiptID, intent, resultID)
	if err != nil {
		return zero, errors.Join(errMaintenanceProbeReceipt, err)
	}
	if err = r.recheck(ctx, tx); err != nil {
		return zero, err
	}
	return r, nil
}
func (f *maintenanceMySQLFixture) begin(ctx context.Context, db *sql.DB) (*sql.Tx, configMaintenanceReceiptSnapshot, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, configMaintenanceReceiptSnapshot{}, err
	}
	r, err := f.prepare(ctx, tx)
	if err != nil {
		_ = tx.Rollback()
		return nil, configMaintenanceReceiptSnapshot{}, err
	}
	return tx, r, nil
}
func (f *maintenanceMySQLFixture) assert(t *testing.T, ctx context.Context, receipts, audits int, filled bool) {
	t.Helper()
	var r, a int
	mysqlMust(t, f.db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?),(SELECT COUNT(*) FROM audit_logs WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'$.origin_installation_id'))=?)", f.installation, f.installation).Scan(&r, &a))
	if r != receipts || a != audits {
		t.Fatal("maintenance atomic row counts differ", r, a)
	}
	tx, err := f.db.BeginTx(ctx, nil)
	mysqlMust(t, err)
	defer tx.Rollback()
	row, err := f.read(ctx, tx)
	mysqlMust(t, err)
	if row.rowSHA256 != f.scope.identity.RowSHA || (row.canonical == configBackfillCanonicalOriginal) != filled {
		t.Fatal("original row fingerprint/canonical state changed")
	}
}
func maintenanceProbeError(t *testing.T, err error, code uint16) {
	t.Helper()
	var actual *mysql.MySQLError
	if !errors.As(err, &actual) || actual.Number != code {
		t.Fatalf("required MySQL rejection missing (expected_code=%d)", code)
	}
}

func maintenanceProbeDatabase(t *testing.T) (context.Context, *sql.DB, *mysql.Config, DatabaseIdentity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(8)
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("fresh run-owned database required")
	}
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	input, writer, base, err := decodeConfigMaintenanceProbeInputs(raw, os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256"))
	mysqlMust(t, err)
	rows, err := db.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	mysqlMust(t, err)
	var names []string
	for rows.Next() {
		var name string
		mysqlMust(t, rows.Scan(&name))
		names = append(names, name)
	}
	mysqlMust(t, rows.Err())
	mysqlMust(t, rows.Close())
	if !reflect.DeepEqual(names, base.Filenames) {
		t.Fatal("full migration ledger differs")
	}
	var present int
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' AND COLUMN_NAME='canonical_config_json')+(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_config_maintenance_receipts')").Scan(&present))
	if present != 0 {
		t.Fatal("candidate schema unexpectedly preinstalled")
	}
	_, err = db.ExecContext(ctx, writer.CandidateDDL)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, input.MaintenanceDDL)
	mysqlMust(t, err)
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_config_maintenance_receipts", "audit_logs"} {
		var engine string
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&engine))
		if engine != "InnoDB" {
			t.Fatal("InnoDB required")
		}
	}
	identity := DatabaseIdentity{actualUUID, cfg.DBName}
	return ctx, db, cfg, identity
}

func TestDConfigMaintenanceReceiptMySQL(t *testing.T) {
	ctx, db, cfg, identity := maintenanceProbeDatabase(t)
	for _, name := range []string{"fill_commit_replay_nochange", "caller_rollback", "receipt_failure_atomic_rollback", "result_audit_failure_atomic_rollback", "constraints_and_retention", "lost_commit_reply_observation", "observed_config_lock_replay"} {
		if !t.Run(name, func(t *testing.T) {
			f := newMaintenanceMySQLFixture(t, ctx, db, identity)
			switch name {
			case "receipt_failure_atomic_rollback", "result_audit_failure_atomic_rollback":
				trigger := "dmr_" + strings.TrimPrefix(f.installation, "installation_maintenance_probe_")
				table, predicate := "system_backup_v2_config_maintenance_receipts", "NEW.origin_installation_id='"+f.installation+"'"
				if name == "result_audit_failure_atomic_rollback" {
					table = "audit_logs"
					predicate = "NEW.action='system_backup.config_canonical_backfill.result' AND JSON_UNQUOTE(JSON_EXTRACT(NEW.details,'$.origin_installation_id'))='" + f.installation + "'"
				}
				_, err := db.ExecContext(ctx, "CREATE TRIGGER "+trigger+" BEFORE INSERT ON "+table+" FOR EACH ROW BEGIN IF "+predicate+" THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic maintenance rejection'; END IF; END")
				mysqlMust(t, err)
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
					defer stop()
					if _, e := db.ExecContext(cleanup, "DROP TRIGGER IF EXISTS "+trigger); e != nil {
						t.Error("CLEANUP_PENDING maintenance trigger")
					}
				})
				_, failed, failure := f.begin(ctx, db)
				if failure == nil || failed.tx != nil {
					t.Fatal("failed INSERT returned usable result")
				}
				if name == "result_audit_failure_atomic_rollback" {
					if !errors.Is(failure, errMaintenanceProbeResultAudit) {
						t.Fatal("failure did not reach result audit insertion")
					}
					maintenanceProbeError(t, failure, 1644)
				} else if !errors.Is(failure, errMaintenanceProbeReceipt) || !errors.Is(failure, ErrProviderEvidenceStorage) {
					t.Fatal("failure did not reach receipt insertion")
				}
				f.assert(t, ctx, 0, 0, false)
				_, err = db.ExecContext(ctx, "DROP TRIGGER "+trigger)
				mysqlMust(t, err)
				tx, _, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				mysqlMust(t, tx.Commit())
				f.assert(t, ctx, 1, 2, true)
			case "caller_rollback":
				tx, r, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				if !r.policy.wrote {
					t.Fatal("caller fill not recorded")
				}
				mysqlMust(t, tx.Rollback())
				f.assert(t, ctx, 0, 0, false)
			case "fill_commit_replay_nochange":
				tx, r, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				mysqlMust(t, tx.Commit())
				if !r.policy.wrote {
					t.Fatal("fill not recorded")
				}
				f.assert(t, ctx, 1, 2, true)
				tx, replay, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				mysqlMust(t, tx.Commit())
				if !bytes.Equal(replay.bytes(), r.bytes()) {
					t.Fatal("committed original response changed")
				}
				f.assert(t, ctx, 1, 2, true)
				originalScope := f.scope
				var request map[string]any
				mysqlMust(t, json.Unmarshal(f.scope.canonical, &request))
				request["grant_version"] = "synthetic-v2"
				changed, e := json.Marshal(request)
				mysqlMust(t, e)
				f.scope, e = newConfigMaintenanceScope(identity, f.installation, f.scope.identity.Actor, f.scope.key, changed)
				mysqlMust(t, e)
				if _, _, e = f.begin(ctx, db); !errors.Is(e, ErrRegistrationConflict) {
					t.Fatal("same key reopened after grant version change")
				}
				f.scope = originalScope
				f.assert(t, ctx, 1, 2, true)
				f.scope, e = newConfigMaintenanceScope(identity, f.installation, f.scope.identity.Actor, "maintenance_nochange_key_012345", f.scope.canonical)
				mysqlMust(t, e)
				tx, nochange, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				mysqlMust(t, tx.Commit())
				if nochange.policy.wrote {
					t.Fatal("same bytes reported write")
				}
				f.assert(t, ctx, 2, 4, true)
			case "constraints_and_retention":
				tx, r, e := f.begin(ctx, db)
				mysqlMust(t, e)
				defer tx.Rollback()
				mysqlMust(t, tx.Commit())
				for _, fault := range []string{"permanent-key", "receipt-uuid", "config-fk", "intent-fk", "wrote", "same-audit", "size", "json", "digest"} {
					t.Run(fault, func(t *testing.T) {
						columns := maintenanceReceiptInsertNames()
						expressions := append([]string(nil), columns...)
						values := []any{}
						code := uint16(3819)
						id, e := maintenanceProbeUUID()
						mysqlMust(t, e)
						for i, col := range columns {
							switch col {
							case "receipt_id":
								if fault != "receipt-uuid" {
									expressions[i] = "?"
									values = append(values, id)
								}
							case "idempotency_key":
								if fault != "permanent-key" {
									expressions[i] = "?"
									values = append(values, "constraint_key_"+strings.ReplaceAll(id, "-", ""))
								}
							case "grant_version":
								if fault == "permanent-key" {
									expressions[i] = "'synthetic-v2'"
								}
							case "config_version":
								if fault == "config-fk" {
									expressions[i] = "9007199254740991"
								}
							case "intent_audit_id":
								if fault == "intent-fk" {
									expressions[i] = "2147483647"
								}
							case "result_audit_id":
								if fault == "same-audit" {
									expressions[i] = "intent_audit_id"
								}
							case "wrote":
								if fault == "wrote" {
									expressions[i] = "2"
								}
							case "redacted_response_size_bytes":
								if fault == "size" || fault == "json" {
									expressions[i] = "2"
								}
							case "redacted_response_canonical_json":
								if fault == "json" {
									expressions[i] = "'[]'"
								}
							case "redacted_response_sha256":
								if fault == "digest" {
									expressions[i] = "REPEAT('z',64)"
								}
							}
						}
						if fault == "permanent-key" || fault == "receipt-uuid" {
							code = 1062
						}
						if fault == "config-fk" || fault == "intent-fk" {
							code = 1452
						}
						values = append(values, f.installation)
						_, e = db.ExecContext(ctx, "INSERT INTO system_backup_v2_config_maintenance_receipts("+strings.Join(columns, ",")+") SELECT "+strings.Join(expressions, ",")+" FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?", values...)
						maintenanceProbeError(t, e, code)
					})
				}
				_, e = db.ExecContext(ctx, "DELETE FROM audit_logs WHERE id=?", r.policy.intentID)
				maintenanceProbeError(t, e, 1451)
				_, e = db.ExecContext(ctx, "DELETE FROM system_backup_v2_configs WHERE origin_installation_id=?", f.installation)
				maintenanceProbeError(t, e, 1451)
				f.assert(t, ctx, 1, 2, true)
			case "lost_commit_reply_observation":
				connector, e := mysql.NewConnector(cfg)
				mysqlMust(t, e)
				lost := &configProofLostCommitConnector{base: connector}
				faultDB := sql.OpenDB(lost)
				defer faultDB.Close()
				tx, r, e := f.begin(ctx, faultDB)
				mysqlMust(t, e)
				defer tx.Rollback()
				if tx.Commit() == nil || !lost.lost.Load() {
					t.Fatal("real COMMIT reply was not lost")
				}
				if r.recheck(ctx, tx) == nil {
					t.Fatal("ended transaction observation was reused")
				}
				observe, e := db.BeginTx(ctx, nil)
				mysqlMust(t, e)
				defer observe.Rollback()
				row, e := f.read(ctx, observe)
				mysqlMust(t, e)
				saved, e := loadConfigMaintenanceReceipt(ctx, observe, f.scope, row)
				mysqlMust(t, e)
				mysqlMust(t, observe.Rollback())
				if !bytes.Equal(saved.bytes(), r.bytes()) {
					t.Fatal("independent committed observation changed response")
				}
				f.assert(t, ctx, 1, 2, true)
			case "observed_config_lock_replay":
				first, e := db.BeginTx(ctx, nil)
				mysqlMust(t, e)
				defer first.Rollback()
				_, e = f.read(ctx, first)
				mysqlMust(t, e)
				workerDB, e := sql.Open("mysql", cfg.FormatDSN())
				mysqlMust(t, e)
				workerDB.SetMaxOpenConns(1)
				defer workerDB.Close()
				var connectionID int64
				mysqlMust(t, workerDB.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&connectionID))
				work, stop := context.WithCancel(ctx)
				defer stop()
				done := make(chan error, 1)
				body := make(chan []byte, 1)
				drained := make(chan struct{})
				go func() {
					defer close(drained)
					tx, r, e := f.begin(work, workerDB)
					if e == nil {
						body <- r.bytes()
						e = tx.Commit()
						_ = tx.Rollback()
					}
					done <- e
				}()
				defer func() {
					stop()
					_ = first.Rollback()
					select {
					case <-drained:
					case <-time.After(5 * time.Second):
						t.Error("maintenance worker did not drain")
					}
				}()
				(sessionMySQLProbe{db: db, identity: identity}).waiting(t, ctx, sessionProbeWorker{id: connectionID, result: done}, "system_backup_v2_configs")
				r, e := f.prepare(ctx, first)
				mysqlMust(t, e)
				mysqlMust(t, first.Commit())
				mysqlMust(t, sessionWorkerResult(t, ctx, sessionProbeWorker{result: done}))
				if !bytes.Equal(<-body, r.bytes()) {
					t.Fatal("waiting writer failed original replay")
				}
				f.assert(t, ctx, 1, 2, true)
			}
		}) {
			return
		}
	}
	t.Log("PASS real MySQL maintenance receipt storage candidate: commit/replay/nochange, actual audit anchors, atomic rollback, unique/FK/CHECK/retention, lost reply observation and observed config-lock replay; synthetic_admission=yes production_approval=no")
}

func TestDConfigMaintenanceReceiptMySQLSeed(t *testing.T) {
	base := configProofProbeInputs{Kind: "a_config_proof_probe_inputs.v1", Catalog: systembackupcontroller.ContractMigrationCatalogHash}
	for n := 1; n <= systembackupcontroller.ContractMigrationCatalogFileCount; n++ {
		base.Filenames = append(base.Filenames, fmt.Sprintf("%03d_synthetic.sql", n))
	}
	b, err := json.Marshal(base)
	mysqlMust(t, err)
	w, err := json.Marshal(configWriterProbeInputs{Kind: "d_config_writer_probe_inputs.v1", MigrationInputs: b, CandidateDDL: configWriterCandidateFixture, CandidateSHA256: configWriterCandidateSHA256})
	mysqlMust(t, err)
	raw, err := json.Marshal(configMaintenanceProbeInputs{Kind: "d_config_maintenance_receipt_probe_inputs.v1", WriterInputs: w, MaintenanceDDL: configMaintenanceCandidateFixture, MaintenanceSHA256: configMaintenanceCandidateSHA256})
	mysqlMust(t, err)
	if _, _, _, err = decodeConfigMaintenanceProbeInputs(raw, registrationHash(string(raw))); err != nil {
		t.Fatal("detached maintenance capsule", err)
	}
	for _, name := range []string{"kind", "ddl", "pin", "writer", "unknown", "digest", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			mysqlMust(t, json.Unmarshal(raw, &fields))
			switch name {
			case "kind":
				fields["kind"] = "production"
			case "ddl":
				fields["maintenance_ddl"] = configMaintenanceCandidateFixture + "\n"
			case "pin":
				fields["maintenance_sha256"] = registrationHash("other")
			case "writer":
				fields["writer_inputs"] = map[string]any{}
			case "unknown":
				fields["grant"] = "not-authorization"
			}
			bad, e := json.Marshal(fields)
			mysqlMust(t, e)
			if name == "duplicate" {
				bad = append([]byte(`{"kind":"d_config_maintenance_receipt_probe_inputs.v1",`), bad[1:]...)
			}
			digest := registrationHash(string(bad))
			if name == "digest" {
				digest = registrationHash("other")
			}
			if _, _, _, e = decodeConfigMaintenanceProbeInputs(bad, digest); e == nil {
				t.Fatal("unsafe maintenance capsule admitted")
			}
		})
	}
	config, err := DecodeBootstrapConfig(bootstrapFixture(t))
	mysqlMust(t, err)
	scope, err := maintenanceProbeScope(DatabaseIdentity{"12345678-1234-1234-1234-123456789abc", "clawmanager"}, "installation_maintenance_seed", "maintenance_seed_key_012345", config.CanonicalJSON(), registrationHash("synthetic-row"))
	mysqlMust(t, err)
	id, err := maintenanceProbeUUID()
	mysqlMust(t, err)
	_, err = canonicalConfigMaintenanceReceipt(configMaintenanceReceiptPolicy{scope: scope, receiptID: id, requestID: id, intentID: 11, resultID: 12, createdAt: time.Date(2026, 10, 15, 0, 0, 0, 123456000, time.UTC)})
	mysqlMust(t, err)
	// An extra detached pass validates the actual PowerShell-built capsule,
	// including its complete formal ledger, before any SSH is possible.
	if path, digest := os.Getenv("D_MAINTENANCE_SEED_INPUTS"), os.Getenv("D_MAINTENANCE_SEED_INPUTS_SHA256"); path != "" || digest != "" {
		actual, e := os.ReadFile(path)
		mysqlMust(t, e)
		if _, _, _, e = decodeConfigMaintenanceProbeInputs(actual, digest); e != nil {
			t.Fatal("actual runner maintenance capsule rejected", e)
		}
		t.Log("PASS actual frozen runner maintenance capsule; MySQL not executed")
	}
}
