package systembackupapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// SQL-shape/admission model. This exercises the persistence core and final
// guards; it is not MySQL or an owner request/provider implementation.
type writerTestRequest []byte

func (r writerTestRequest) CanonicalJSON() []byte { return append([]byte(nil), r...) }

type writerTestContract struct{ reject bool }

func (c writerTestContract) Decode(_ context.Context, _ read.TaskKind, _ string, raw json.RawMessage) (NormalizedTaskRequest, error) {
	if c.reject || string(raw) != `{"test_request":true}` {
		return nil, &Error{"validation_failed"}
	}
	return writerTestRequest(raw), nil
}

type writerTestAdmission struct {
	q      *writerTestSQL
	mode   string
	called int
}

func (a *writerTestAdmission) Admit(_ TaskWriteSQL, _ TaskSubmissionIdentity, c TaskConfigSnapshot, _ read.TaskKind, _ []byte) (TaskCreation, TaskAdmissionGuard, error) {
	a.called++
	if a.mode == "capacity" {
		return TaskCreation{}, nil, &Error{"capacity_exceeded"}
	}
	// Admission receives a private config copy, never the bytes inserted below.
	if a.mode == "mutate_input" {
		c.CanonicalJSON[0] = 'x'
	}
	return TaskCreation{Preflight: &PreflightCreation{SourceType: "backup", SourcePublicID: "sbk_00000000-0000-4000-8000-000000000001", Mode: "production_readonly", TargetProfile: "cluster", TargetConfigRef: "target_v1", TargetConfigHash: strings.Repeat("a", 64), Compatibility: "supported"}}, a, nil
}
func (a *writerTestAdmission) ValidUntil() time.Time { return a.q.now.Add(5 * time.Second) }
func (a *writerTestAdmission) Recheck(TaskWriteSQL) error {
	a.q.order = append(a.q.order, "owner_recheck")
	switch a.mode {
	case "expire":
		a.q.clock = a.q.now.Add(5 * time.Second)
	case "clock_regress":
		a.q.clock = a.q.now.Add(-time.Microsecond)
	case "kill_switch":
		a.q.enabled = false
	case "schedule_drift":
		a.q.schedule = a.q.now.Add(time.Second)
	case "snapshot_drift":
		a.q.snapshot = []byte(`{}`)
	case "revoke":
		return &Error{"permission_denied"}
	}
	return nil
}

type writerTestRow struct {
	values []any
	err    error
}

func (r writerTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("wrong scan shape")
	}
	for i, v := range r.values {
		if scanner, ok := dest[i].(sql.Scanner); ok {
			if err := scanner.Scan(v); err != nil {
				return err
			}
			continue
		}
		d := reflect.ValueOf(dest[i]).Elem()
		if v == nil {
			d.SetZero()
			continue
		}
		s := reflect.ValueOf(v)
		if s.Type().AssignableTo(d.Type()) {
			d.Set(s)
		} else if s.Type().ConvertibleTo(d.Type()) {
			d.Set(s.Convert(d.Type()))
		} else {
			return errors.New("scan type")
		}
	}
	return nil
}

type writerTestSQL struct {
	now, clock, schedule                time.Time
	config, snapshot                    []byte
	configHash                          string
	enabled                             bool
	task                                *read.TaskHeader
	retiredHash                         string
	order                               []string
	writeFail                           string
	insertCount, eventCount, auditCount int
}

func newWriterTestSQL(t *testing.T) *writerTestSQL {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Request struct {
			Config json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("fixture")
	}
	var config map[string]any
	if json.Unmarshal(doc.Request.Config, &config) != nil {
		t.Fatal("config fixture")
	}
	config["enabled"] = true
	raw, _ = json.Marshal(config)
	values, err := security.DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 28, 1, 2, 3, 0, time.UTC)
	return &writerTestSQL{now: now, clock: now, config: values.CanonicalJSON(), configHash: values.SHA256(), enabled: true}
}
func (q *writerTestSQL) QueryRow(query string, args ...any) TaskRow {
	q.order = append(q.order, query)
	switch {
	case strings.HasPrefix(query, "SELECT engine FROM system_backup_v2_engine_bindings"):
		return writerTestRow{values: []any{"v2"}}
	case strings.HasPrefix(query, "SELECT active_config_version"):
		return writerTestRow{values: []any{uint64(3), uint64(4), q.enabled, "k8s-cluster"}}
	case strings.HasPrefix(query, "SELECT canonical_config_json"):
		return writerTestRow{values: []any{q.config, q.configHash, uint64(len(q.config)), true, uint64(3600)}}
	case strings.HasPrefix(query, "SELECT UTC_TIMESTAMP"):
		return writerTestRow{values: []any{q.clock, int64(0)}}
	case strings.HasPrefix(query, "SELECT request_hash,source_type"):
		if q.retiredHash != "" {
			return writerTestRow{values: []any{q.retiredHash, "preflight", "spf_00000000-0000-4000-8000-000000000001", "succeeded", "none"}}
		}
		return writerTestRow{err: sql.ErrNoRows}
	case strings.HasPrefix(query, "SELECT next_reconcile_at"):
		return writerTestRow{values: []any{q.schedule, q.snapshot, q.configHash, uint64(len(q.config))}}
	case strings.HasPrefix(query, "SELECT "+writerHeaderColumns):
		if q.task == nil {
			return writerTestRow{err: sql.ErrNoRows}
		}
		h := q.task
		return writerTestRow{values: []any{h.ID, h.PublicID, h.InstallationID, h.ActorType, h.ActorID, h.Endpoint, h.IdempotencyKey, h.RequestHash, h.RequestID, nil, h.Status, h.PendingReason, h.AttentionReason, h.CanCancel, h.ConfigVersion, h.Retryable, h.FailureCategory, h.RowVersion, h.DeadlineAt, h.CreatedAt, h.UpdatedAt}}
	default:
		return writerTestRow{err: errors.New("unexpected query")}
	}
}
func (q *writerTestSQL) Exec(query string, args ...any) (sql.Result, error) {
	q.order = append(q.order, query)
	if q.writeFail != "" && strings.Contains(query, q.writeFail) {
		return nil, errors.New("model write failure")
	}
	switch {
	case strings.HasPrefix(query, "INSERT INTO system_backup_v2_preflights"):
		q.insertCount++
		q.snapshot = append([]byte(nil), args[9].([]byte)...)
		q.schedule = args[12].(time.Time)
		q.task = &read.TaskHeader{ID: 1, PublicID: args[0].(string), InstallationID: args[1].(string), Kind: read.PreflightTask, ActorType: "admin", ActorID: args[3].(string), Endpoint: args[4].(string), IdempotencyKey: args[5].(string), RequestHash: args[6].(string), RequestID: args[7].(string), Status: "pending", PendingReason: "none", AttentionReason: "none", CanCancel: true, ConfigVersion: 3, FailureCategory: "none", RowVersion: 1, DeadlineAt: args[13].(time.Time), CreatedAt: q.now, UpdatedAt: q.now}
	case strings.Contains(query, "system_backup_v2_events"):
		q.eventCount++
	case strings.Contains(query, "audit_logs"):
		q.auditCount++
	default:
		return nil, errors.New("unexpected write")
	}
	return driver.RowsAffected(1), nil
}
func writerTestIdentity() TaskSubmissionIdentity {
	return TaskSubmissionIdentity{"installation_model", "7", "createSystemBackupPreflight", "model-key-123456789"}
}
func writerTestPlan(t *testing.T, q *writerTestSQL, mode string) (PreparedTaskWrite, *writerTestAdmission) {
	t.Helper()
	a := &writerTestAdmission{q: q, mode: mode}
	w, err := NewPublicSQLTaskWriter(writerTestContract{}, a, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := w.Prepare(context.WithValue(context.Background(), taskRequestIDKey{}, "request_test_1"), read.PreflightTask, "createSystemBackupPreflight", []byte(`{"test_request":true}`))
	if err != nil {
		t.Fatal(err)
	}
	return p, a
}
func TestSQLWriterCreatesOnceAndReplaysOriginal(t *testing.T) {
	q := newWriterTestSQL(t)
	p, a := writerTestPlan(t, q, "mutate_input")
	first, err := p.Stage(q, writerTestIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != "request_test_1" || q.insertCount != 1 || q.eventCount != 1 || q.auditCount != 1 || a.called != 1 || !reflect.DeepEqual(q.config, q.snapshot) {
		t.Fatal("non-atomic submission or mutated snapshot")
	}
	if _, err = p.Stage(q, writerTestIdentity()); err == nil {
		t.Fatal("prepared write reused")
	}
	q.enabled = false // original plan: disabled blocks new work, not exact replay.
	p, a = writerTestPlan(t, q, "")
	replay, err := p.Stage(q, writerTestIdentity())
	if err != nil || !reflect.DeepEqual(first, replay) || a.called != 0 || q.insertCount != 1 || q.eventCount != 1 || q.auditCount != 1 {
		t.Fatalf("replay changed original: %v", err)
	}
}
func TestSQLWriterRejectsAuditCapacityClockAndFinalDrift(t *testing.T) {
	for _, mode := range []string{"capacity", "expire", "clock_regress", "kill_switch", "schedule_drift", "snapshot_drift", "revoke", "audit_failure", "event_failure", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			q := newWriterTestSQL(t)
			p, _ := writerTestPlan(t, q, mode)
			if mode == "audit_failure" {
				q.writeFail = "audit_logs"
			}
			if mode == "event_failure" {
				q.writeFail = "system_backup_v2_events"
			}
			if mode == "disabled" {
				q.enabled = false
			}
			got, err := p.Stage(q, writerTestIdentity())
			if err == nil || got.PublicID != "" {
				t.Fatal("unsafe staged result")
			}
			if (mode == "capacity" || mode == "disabled") && q.insertCount != 0 {
				t.Fatal("admission failure wrote task")
			}
		})
	}
}
func TestSQLWriterConflictAndTombstoneNeverReenqueue(t *testing.T) {
	for _, mode := range []string{"existing_conflict", "expired", "retired_conflict"} {
		t.Run(mode, func(t *testing.T) {
			q := newWriterTestSQL(t)
			p, _ := writerTestPlan(t, q, "")
			if mode == "existing_conflict" {
				if _, err := p.Stage(q, writerTestIdentity()); err != nil {
					t.Fatal(err)
				}
				q.task.RequestHash = strings.Repeat("a", 64)
				q.insertCount = 0
				p, _ = writerTestPlan(t, q, "")
			} else {
				h := sha256.Sum256([]byte(`{"test_request":true}`))
				q.retiredHash = hex.EncodeToString(h[:])
				if mode == "retired_conflict" {
					q.retiredHash = strings.Repeat("b", 64)
				}
			}
			_, err := p.Stage(q, writerTestIdentity())
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != map[string]string{"existing_conflict": "idempotency_conflict", "expired": "idempotency_expired", "retired_conflict": "idempotency_conflict"}[mode] || q.insertCount != 0 {
				t.Fatalf("bad replay rejection %v", err)
			}
		})
	}
}
func TestSQLWriterRequiresOwnerContractAndRejectsEmptyObject(t *testing.T) {
	if _, err := NewPublicSQLTaskWriter(nil, nil, true); err == nil {
		t.Fatal("missing owners accepted")
	}
	q := newWriterTestSQL(t)
	w, _ := NewPublicSQLTaskWriter(writerTestContract{}, &writerTestAdmission{q: q}, true)
	for _, body := range []string{`{}`, `null`, `{"test_request":true,"extra":1}`, `{"test_request":null}`} {
		if _, err := w.Prepare(context.Background(), read.PreflightTask, "createSystemBackupPreflight", []byte(body)); err == nil {
			t.Fatal("owner rejection bypassed")
		}
	}
}
