//go:build systembackup_mysql

package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// Installation/offline/metadata authority is explicitly a TEST MODEL. All SQL,
// records, account privileges, original consumer, final guard, domain CAS and
// caller transaction completion below are REAL native MySQL, never a model
// driver. Each model metadata mutation uses the SAME original business tx.
type bootstrapBusinessMetadataModel struct {
	t               *testing.T
	owner, business *sql.DB
	records         *bootstrapNativeRecords
	principal       string
	ctx             context.Context
	write           BootstrapSQL
	raw             *sql.Tx
	mode            string
	writerBlocked   bool
	stages          []string
	driftInjected   bool
}

func (e *bootstrapBusinessMetadataModel) stage(name string) {
	e.stages = append(e.stages, name)
	e.t.Logf("metadata enter=%s mode=%s", name, e.mode)
}

func (e *bootstrapBusinessMetadataModel) PrepareBootstrapConsumption(ctx context.Context, r BootstrapConsumptionRequest) (PreparedBootstrapAuthority, error) {
	e.stage("PrepareBootstrapConsumption")
	if !reflect.DeepEqual(r, e.records.request) {
		return PreparedBootstrapAuthority{}, ErrGuardRequired
	}
	var now time.Time
	if e.business.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return PreparedBootstrapAuthority{}, ErrUnavailable
	}
	e.ctx = ctx
	return PreparedBootstrapAuthority{Session: e, OperationPublicID: "sop_native_business_bootstrap", CapacityObservedAt: &now}, nil
}
func (e *bootstrapBusinessMetadataModel) LockInstallation(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest) error {
	e.stage("LockInstallation")
	e.write = tx
	var principal string
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&principal) != nil || principal != e.principal {
		return ErrGuardRequired
	}
	for _, q := range []string{bootstrapConfigSnapshotSQL, bootstrapInstallationSnapshotSQL} {
		rows, err := tx.QueryContext(ctx, q, string(r.Scope.Installation))
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		if rows.Err() != nil || rows.Close() != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func (e *bootstrapBusinessMetadataModel) Authorize(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, _ DomainRecord, now time.Time) (BootstrapConsumptionAdmission, error) {
	e.stage("Authorize")
	var name, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=1 FOR SHARE").Scan(&name, &role, &active, &provider) != nil || name != r.Username || role != "admin" || !active || provider != "local" {
		return BootstrapConsumptionAdmission{}, ErrGuardRequired
	}
	h, err := BootstrapConsumptionHash(r)
	if err != nil {
		return BootstrapConsumptionAdmission{}, err
	}
	return BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: bootstrapNativeStamp(now.Add(time.Minute)), DependencyExpiresAt: bootstrapNativeStamp(now.Add(time.Minute))}, nil
}
func (e *bootstrapBusinessMetadataModel) LockOperation(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, _ Hash, _ string) (BootstrapOperation, error) {
	e.stage("LockOperation")
	var op BootstrapOperation
	err := tx.QueryRowContext(ctx, "SELECT public_id,request_hash,status,result_config_version,http_status FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE", string(r.Scope.Installation), string(r.ActorID), r.Endpoint, r.IdempotencyKey).Scan(&op.PublicID, &op.RequestHash, &op.Status, &op.Version, &op.HTTPStatus)
	if errors.Is(err, sql.ErrNoRows) {
		var existing string
		if probe := tx.QueryRowContext(ctx, "SELECT public_id FROM system_backup_v2_operations WHERE public_id=? FOR UPDATE", "sop_native_business_bootstrap").Scan(&existing); !errors.Is(probe, sql.ErrNoRows) {
			return BootstrapOperation{}, ErrConflict
		}
		// Both fixed audit destinations are reserved before child/source reads.
		rows, probe := tx.QueryContext(ctx, "SELECT id FROM audit_logs WHERE id IN (11,12) ORDER BY id FOR SHARE")
		if probe != nil {
			return BootstrapOperation{}, probe
		}
		found := rows.Next()
		if rows.Err() != nil || rows.Close() != nil || found {
			return BootstrapOperation{}, ErrConflict
		}
		return BootstrapOperation{}, nil
	}
	op.Found = err == nil
	return op, err
}
func (e *bootstrapBusinessMetadataModel) LockHosts(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	e.stage("LockHosts")
	return nil
}
func (e *bootstrapBusinessMetadataModel) LockReferences(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	e.stage("LockReferences")
	return nil
}
func (e *bootstrapBusinessMetadataModel) Reserve(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	e.stage("Reserve")
	return nil
}
func (e *bootstrapBusinessMetadataModel) audit(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, id int64, action string, now time.Time) error {
	h, err := BootstrapConsumptionHash(r)
	if err != nil {
		return err
	}
	details, err := json.Marshal(map[string]any{"operation_public_id": "sop_native_business_bootstrap", "installation_id": string(r.Scope.Installation), "config_sha256": string(r.ConfigHash), "request_hash": string(h), "authorization": "offline_bootstrap", "config_version": 1})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(id,user_id,action,resource_type,resource_id,details,created_at) VALUES (?,1,?,'system_backup',NULL,?,?)", id, action, details, now)
	return err
}
func (e *bootstrapBusinessMetadataModel) AuditIntent(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, _ BootstrapConsumptionFacts) error {
	e.stage("AuditIntent")
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return err
	}
	return e.audit(ctx, tx, r, 11, "system_backup.config_bootstrap.intent", now)
}
func (e *bootstrapBusinessMetadataModel) LockEvidence(_ context.Context, _ BootstrapSQL, _ BootstrapConsumptionRequest, _ BootstrapConsumptionFacts) ([]ResultEvidence, error) {
	e.stage("LockEvidence")
	return []ResultEvidence{detached(e.records.evidence)}, nil
}
func (e *bootstrapBusinessMetadataModel) WriteBootstrap(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, _ BootstrapConsumptionFacts, id string, h Hash, now time.Time) (BootstrapWriteResult, error) {
	e.stage("WriteBootstrap")
	if _, err := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_configs(origin_installation_id,version,enabled,config_sha256,config_canonical_json) VALUES (?,1,FALSE,?,?)", string(r.Scope.Installation), string(r.ConfigHash), []byte(`{"native_metadata_model":true}`)); err != nil {
		return BootstrapWriteResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,matrix_key) VALUES (?,1,?)", string(r.Scope.Installation), r.MatrixKey); err != nil {
		return BootstrapWriteResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_operations(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,status,external_action_public_ids_canonical_json,external_action_public_ids_sha256,result_config_version,http_status,external_action_public_ids_size_bytes) VALUES (?,?,'config_update','system',?,'admin',?,?,?,?,'succeeded','[]','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',1,201,2)", id, string(r.Scope.Installation), string(r.Scope.Installation), string(r.ActorID), r.Endpoint, r.IdempotencyKey, string(h)); err != nil {
		return BootstrapWriteResult{}, err
	}
	if err := e.audit(ctx, tx, r, 12, "system_backup.config_bootstrap.result", now); err != nil {
		return BootstrapWriteResult{}, err
	}
	return BootstrapWriteResult{IntentAuditID: 11, ResultAuditID: 12}, nil
}
func (e *bootstrapBusinessMetadataModel) Recheck(ctx context.Context, read BootstrapReadSQL, _ BootstrapConsumptionRequest, _ BootstrapConsumptionFacts, _ time.Time) error {
	e.stage("Recheck")
	if ctx != e.ctx || !SameBootstrapTransaction(e.write, read) {
		return ErrGuardRequired
	}
	if e.mode == "metadata-drift" {
		_, err := e.raw.ExecContext(ctx, "UPDATE system_backup_v2_configs SET config_canonical_json=? WHERE origin_installation_id=? AND version=1", []byte(`{"native_metadata_model":"changed"}`), string(e.records.request.Scope.Installation))
		e.driftInjected = err == nil
		return err
	}
	if e.mode == "block-child-writer" {
		writer, err := e.owner.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return err
		}
		defer writer.Rollback()
		def, _ := storageFor(&GrantRecord{})
		key, err := recordKeyValues(def, e.records.request.Scope, RecordKey{ID: e.records.grant.GrantID})
		if err != nil {
			return err
		}
		_, err = writer.ExecContext(ctx, "UPDATE system_backup_producer_grants SET row_version=row_version+1 WHERE scope_key=? AND grant_id=?", key...)
		var denied *mysql.MySQLError
		if !errors.As(err, &denied) || denied.Number != 1205 {
			return ErrConflict
		}
		e.writerBlocked = true
	}
	return nil
}

func bootstrapBusinessAssertRows(t *testing.T, ctx context.Context, owner *sql.DB, f *bootstrapNativeRecords, committed bool) {
	t.Helper()
	after := bootstrapNativeRecordBytes(t, ctx, owner)
	for table, before := range f.before {
		if table != "system_backup_producer_domains" && !reflect.DeepEqual(after[table], before) {
			t.Fatal("business changed original immutable child", table)
		}
	}
	var domain DomainRecord
	found, err := ReadOriginalSharedRecord(ctx, owner, f.request.Scope, RecordKey{}, &domain)
	if err != nil || !found {
		t.Fatal("independent connection domain readback", err)
	}
	if !committed {
		if !reflect.DeepEqual(domain, f.domain) {
			t.Fatal("original domain close persisted after rollback")
		}
	} else {
		expected := f.domain
		expected.Epoch, _ = nextCounter(expected.Epoch)
		expected.RowVersion, _ = nextCounter(expected.RowVersion)
		expected.State = "closed"
		expected.UpdatedAt = domain.UpdatedAt
		if !reflect.DeepEqual(domain, expected) {
			t.Fatal("domain CAS close mismatch", domain.State, domain.Epoch, domain.RowVersion)
		}
	}
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "audit_logs"} {
		var count int
		want := 0
		if committed {
			want = 1
			if table == "audit_logs" {
				want = 2
			}
		}
		if err := owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != want {
			t.Fatal("independent metadata commit/rollback readback", table, count, want, err)
		}
	}
}

func TestBootstrapBusinessSelectOnlyOriginalConsumerNativeMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	owner, business, scope, principal := bootstrapBusinessNativeDB(t, ctx)
	f := bootstrapSeedNativeRecords(t, ctx, owner, scope)
	t.Run("exact-principal-shared-positive-exclusive-denied", func(t *testing.T) {
		tx, err := business.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, record := range []any{&f.domain, &f.grant, &f.run, &f.target, &f.history, &f.receipt, &f.refs[0]} {
			out := reflect.New(reflect.TypeOf(record).Elem()).Interface()
			found, err := ReadOriginalSharedRecord(ctx, tx, scope, keyForRecord(record), out)
			if err != nil || !found || !reflect.DeepEqual(out, record) {
				t.Fatal("actual SELECT-only FOR SHARE", reflect.TypeOf(record), err)
			}
			definition, _ := storageFor(record)
			values, _ := recordKeyValues(definition, scope, keyForRecord(record))
			keys := recordPrimary(definition)
			where := []string{}
			for _, key := range keys {
				where = append(where, key+"=?")
			}
			rows, err := tx.QueryContext(ctx, "SELECT scope_key FROM "+definition.table+" WHERE "+strings.Join(where, " AND ")+" FOR UPDATE", values...)
			if rows != nil {
				for rows.Next() {
				}
				rows.Close()
			}
			if definition.table == "system_backup_producer_domains" {
				if err != nil {
					t.Fatal("original domain UPDATE lock", err)
				}
			} else {
				var denied *mysql.MySQLError
				if !errors.As(err, &denied) || denied.Number != 1142 {
					t.Fatal("child FOR UPDATE should be denied1142", definition.table, err)
				}
			}
		}
		rows, err := tx.QueryContext(ctx, "SELECT scope_key FROM system_backup_producer_command_receipts")
		if rows != nil {
			rows.Close()
		}
		var denied *mysql.MySQLError
		if !errors.As(err, &denied) || denied.Number != 1142 {
			t.Fatal("business read ungranted command receipts", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	})
	for _, mode := range []string{"rollback", "metadata-drift", "block-child-writer", "replay"} {
		t.Run(mode, func(t *testing.T) {
			env := &bootstrapBusinessMetadataModel{t: t, owner: owner, business: business, records: f, principal: principal, mode: mode}
			consumer, err := NewBootstrapCandidateConsumer(business, scope, env)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := consumer.PrepareBootstrapConsumption(ctx, f.request)
			if err != nil {
				t.Fatal("actual original prepare", err)
			}
			tx, err := business.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			env.raw = tx
			out, consumeErr := consumer.ConsumeBootstrapInTx(ctx, tx, prepared)
			t.Logf("metadata stages=%v drift_injected=%t writer_blocked=%t", env.stages, env.driftInjected, env.writerBlocked)
			bootstrapNativeTraceEvent(t, "ConsumeBootstrapInTx", "", consumeErr)
			if mode == "metadata-drift" {
				if !env.driftInjected {
					t.Fatal("metadata drift was not injected; earlier failure cannot cover final drift guard")
				}
				if consumeErr == nil {
					t.Fatal("native fixed final guard missed metadata drift")
				}
			} else if consumeErr != nil || out.Replayed != (mode == "replay") {
				t.Fatal("actual business SDK consumption", mode, out, consumeErr)
			}
			commit := mode == "block-child-writer" || mode == "replay"
			if commit {
				if err := tx.Commit(); err != nil {
					t.Fatal("native commit", err)
				}
			} else {
				if err := tx.Rollback(); err != nil {
					t.Fatal("native rollback", err)
				}
			}
			if mode == "block-child-writer" && !env.writerBlocked {
				t.Fatal("original shared rows did not block competing native writer")
			}
			bootstrapBusinessAssertRows(t, ctx, owner, f, commit)
		})
	}
}
