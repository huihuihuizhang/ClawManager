package systembackupproducer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func independentBootstrapRequest(r ResultRequest) BootstrapConsumptionRequest {
	a := r.Admission.Unconfigured
	return BootstrapConsumptionRequest{
		Scope: r.Scope, OfflineGrantHash: Hash(strings.Repeat("a", 64)),
		ConfigHash: a.CandidateHash, RegistrySetHash: a.RegistrySetHash, RefSetHash: a.RefSetHash,
		ActorID: "1", Username: "bootstrap-admin", MatrixKey: "k8s-cluster",
		Endpoint: "/api/admin/system-backups/config/bootstrap", IdempotencyKey: "bootstrap-independent-20261026",
		Candidates: []BootstrapCandidateSelection{{Purpose: "artifact", ReferenceIdentityHash: Hash(strings.Repeat("b", 64)), ReferenceVersion: "1", MappingHash: Hash(strings.Repeat("c", 64)), Request: r, ResultVersion: "1"}},
	}
}

// This is a synthetic trusted A adapter. It exercises the actual D consumer
// and record codecs, not deployment authority, InnoDB range locks or providers.
type independentBootstrapSession struct {
	db            *fakeDB
	m             *commandMemory
	request       BootstrapConsumptionRequest
	evidence      ResultEvidence
	operation     BootstrapOperation
	configured    bool
	audits        bool
	fail          string
	reserves      int
	retained      BootstrapSQL
	readRetained  BootstrapReadSQL
	beforeRecheck func()
	snapshots     map[string]map[string]driver.Value
}

func (e *independentBootstrapSession) phase(name string) error {
	e.m.events = append(e.m.events, "bootstrap:"+name)
	if e.fail == name {
		return ErrUnavailable
	}
	return nil
}
func (e *independentBootstrapSession) PrepareBootstrapConsumption(_ context.Context, r BootstrapConsumptionRequest) (PreparedBootstrapAuthority, error) {
	if !reflect.DeepEqual(r, e.request) {
		return PreparedBootstrapAuthority{}, ErrGuardRequired
	}
	now := e.db.now
	return PreparedBootstrapAuthority{Session: e, OperationPublicID: "sop_bootstrap_independent", CapacityObservedAt: &now}, e.phase("prepare")
}
func (e *independentBootstrapSession) LockInstallation(_ context.Context, tx BootstrapSQL, _ BootstrapConsumptionRequest) error {
	e.retained = tx
	return e.phase("installation")
}
func (e *independentBootstrapSession) Authorize(_ context.Context, _ BootstrapSQL, r BootstrapConsumptionRequest, _ DomainRecord, now time.Time) (BootstrapConsumptionAdmission, error) {
	h, err := BootstrapConsumptionHash(r)
	if err != nil {
		return BootstrapConsumptionAdmission{}, err
	}
	return BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: Timestamp(now.Add(time.Hour).Format(timeLayout)), DependencyExpiresAt: Timestamp(now.Add(time.Hour).Format(timeLayout))}, e.phase("authorize")
}
func (e *independentBootstrapSession) LockOperation(context.Context, BootstrapSQL, BootstrapConsumptionRequest, Hash, string) (BootstrapOperation, error) {
	return e.operation, e.phase("operation")
}
func (e *independentBootstrapSession) LockHosts(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	return e.phase("hosts")
}
func (e *independentBootstrapSession) LockReferences(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	return e.phase("refs")
}
func (e *independentBootstrapSession) Reserve(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	e.reserves++
	return e.phase("reserve")
}
func (e *independentBootstrapSession) AuditIntent(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error {
	return e.phase("intent")
}
func (e *independentBootstrapSession) LockEvidence(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) ([]ResultEvidence, error) {
	return []ResultEvidence{e.evidence}, e.phase("evidence")
}
func (e *independentBootstrapSession) WriteBootstrap(_ context.Context, _ BootstrapSQL, _ BootstrapConsumptionRequest, _ BootstrapConsumptionFacts, id string, h Hash, _ time.Time) (BootstrapWriteResult, error) {
	e.configured, e.audits = true, true
	e.operation = BootstrapOperation{Found: true, PublicID: id, RequestHash: h, Status: "succeeded", Version: 1, HTTPStatus: 201}
	e.snapshots[bootstrapOperationSnapshotSQL] = map[string]driver.Value{"public_id": id, "origin_installation_id": string(e.request.Scope.Installation), "operation_type": "config_update", "target_type": "system", "target_public_id": string(e.request.Scope.Installation), "actor_type": "admin", "actor_id": string(e.request.ActorID), "endpoint": e.request.Endpoint, "idempotency_key": e.request.IdempotencyKey, "request_hash": string(h), "status": "succeeded", "external_action_public_ids_canonical_json": []byte("[]"), "external_action_public_ids_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", "result_config_version": int64(1), "http_status": int64(201), "external_action_public_ids_size_bytes": int64(2)}
	return BootstrapWriteResult{IntentAuditID: 11, ResultAuditID: 12}, e.phase("write")
}
func (e *independentBootstrapSession) Recheck(_ context.Context, tx BootstrapReadSQL, _ BootstrapConsumptionRequest, _ BootstrapConsumptionFacts, _ time.Time) error {
	e.readRetained = tx
	if e.beforeRecheck != nil {
		e.beforeRecheck()
	}
	return e.phase("recheck")
}
func (e *independentBootstrapSession) query(q string, args []driver.NamedValue) (driver.Rows, error) {
	if snapshot, ok := e.snapshots[q]; ok {
		if q == bootstrapAuditSnapshotSQL {
			copy := map[string]driver.Value{}
			for column, value := range snapshot {
				copy[column] = value
			}
			snapshot = copy
			snapshot["id"] = args[0].Value
			snapshot["action"] = "system_backup.config_bootstrap.intent"
			if args[0].Value == int64(12) {
				snapshot["action"] = "system_backup.config_bootstrap.result"
			}
		}
		columns := make([]string, 0, len(snapshot))
		for column := range snapshot {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		values := make([]driver.Value, len(columns))
		for i, column := range columns {
			values[i] = snapshot[column]
		}
		return &storedRows{names: columns, data: [][]driver.Value{values}}, nil
	}
	switch {
	case strings.Contains(q, "SELECT c.config_sha256,s.active_config_version"):
		if !e.configured {
			return &storedRows{names: []string{"hash", "version", "enabled", "matrix"}}, nil
		}
		return &fakeRows{values: []driver.Value{string(e.request.ConfigHash), int64(1), false, e.request.MatrixKey}}, nil
	case strings.HasPrefix(q, "SELECT public_id,result_config_version,request_hash,status,http_status"):
		op := e.operation
		return &fakeRows{values: []driver.Value{op.PublicID, op.Version, string(op.RequestHash), op.Status, int64(op.HTTPStatus)}}, nil
	case strings.HasPrefix(q, "SELECT username,role,is_active,auth_provider"):
		return &fakeRows{values: []driver.Value{e.request.Username, "admin", true, "local"}}, nil
	case strings.HasPrefix(q, "SELECT user_id,action,resource_type,details"):
		if !e.audits {
			return nil, ErrUnavailable
		}
		action := "system_backup.config_bootstrap.intent"
		if args[0].Value == int64(12) {
			action = "system_backup.config_bootstrap.result"
		}
		raw, _ := json.Marshal(map[string]any{"operation_public_id": e.operation.PublicID, "installation_id": string(e.request.Scope.Installation), "config_sha256": string(e.request.ConfigHash), "request_hash": string(e.operation.RequestHash), "authorization": "offline_bootstrap", "config_version": 1})
		return &fakeRows{values: []driver.Value{int64(1), action, "system_backup", raw}}, nil
	default:
		q = strings.ReplaceAll(strings.ReplaceAll(q, ", ", ","), ",", ", ")
		return e.m.query(q, args)
	}
}
func setupIndependentBootstrap(t *testing.T) (*BootstrapCandidateConsumer, BootstrapConsumptionRequest, *independentBootstrapSession) {
	t.Helper()
	s, h, result, db, resultEnv, m := setupResult(t, "unconfigured", "candidate")
	if _, err := s.CommitResult(context.Background(), h, result); err != nil {
		t.Fatal(err)
	}
	r := independentBootstrapRequest(result)
	e := &independentBootstrapSession{db: db, m: m, request: detached(r), evidence: detached(resultEnv.evidence)}
	var history HistoricalBindingRecord
	loadMemoryRecord(t, m, &history, 0)
	b := result.Evidence
	retention, _ := e.evidence.RetentionExpiresAt.Time()
	protection, _ := e.evidence.ProtectedUntil.Time()
	rowVersion, _ := e.evidence.RowVersion.SQLInt64()
	contentSize, _ := b.ContentBytes.SQLInt64()
	objectSize, _ := b.ObjectBytes.SQLInt64()
	e.snapshots = map[string]map[string]driver.Value{
		bootstrapEvidenceSnapshotSQL:     {"id": int64(101), "schema_version": "system-backup-evidence.v1", "public_id": string(b.EvidenceID), "owner_target_type": b.OwnerType, "owner_target_public_id": string(b.OwnerID), "evidence_type": b.EvidenceType, "storage_state": "ready", "evidence_failure_code": "none", "storage_provider_role": "evidence", "storage_identity_hash": string(b.StoreIdentityHash), "storage_ref_version": string(b.StoreRefVersion), "storage_relative_key_hash": string(b.RelativeKeyHash), "storage_relative_key": string(history.RelativeKey), "storage_immutable_version": string(*b.ImmutableVersion), "content_checksum": string(b.ContentHash), "content_size_bytes": contentSize, "object_checksum": string(b.ObjectHash), "object_size_bytes": objectSize, "redaction_classification": b.Classification, "encryption": "envelope_v1", "envelope_framing_version": "system-backup-evidence-envelope.v1", "kek_identity_hash": string(b.KEKIdentityHash), "kek_version": string(b.KEKVersion), "row_version": rowVersion, "expires_at": retention, "protected_until": protection, "claim_owner": nil, "claim_expires_at": nil, "inline_payload": nil, "chunk_count": int64(1), "plaintext_chunk_size_bytes": int64(1048576), "chunk_list_root": strings.Repeat("a", 64), "envelope_hash": strings.Repeat("b", 64)},
		bootstrapChunksSnapshotSQL:       {"evidence_id": int64(101), "chunk_index": int64(0), "content_checksum": string(b.ContentHash), "object_checksum": string(b.ObjectHash), "content_size_bytes": contentSize, "object_size_bytes": objectSize},
		bootstrapConfigSnapshotSQL:       {"origin_installation_id": string(r.Scope.Installation), "version": int64(1), "enabled": false, "config_sha256": string(r.ConfigHash), "config_canonical_json": []byte(`{"synthetic":true}`)},
		bootstrapInstallationSnapshotSQL: {"origin_installation_id": string(r.Scope.Installation), "active_config_version": int64(1), "matrix_key": r.MatrixKey},
	}
	e.snapshots[bootstrapEvidenceSnapshotSQL]["media_type"] = "application/json"
	e.snapshots[bootstrapEvidenceSnapshotSQL]["created_at"] = db.now
	e.snapshots[bootstrapAuditSnapshotSQL] = map[string]driver.Value{"user_id": int64(1), "resource_type": "system_backup", "resource_id": nil, "created_at": db.now}
	for column, value := range map[string]driver.Value{"plaintext_offset": int64(0), "plaintext_length": contentSize, "plaintext_sha256": string(b.ContentHash), "object_frame_offset": int64(0), "object_frame_length": objectSize, "ciphertext_sha256": string(b.ObjectHash), "gcm_nonce": []byte("synthetic-nonce"), "gcm_tag": []byte("synthetic-tag")} {
		e.snapshots[bootstrapChunksSnapshotSQL][column] = value
	}
	db.queryRecord = e.query
	previousBegin, previousRollback := db.beginRecord, db.rollbackRecord
	db.beginRecord = func() {
		previousBegin()
		oldConfig, oldAudits, oldOp := e.configured, e.audits, e.operation
		oldSnapshots := map[string]map[string]driver.Value{}
		for query, row := range e.snapshots {
			copy := map[string]driver.Value{}
			for column, value := range row {
				copy[column] = value
			}
			oldSnapshots[query] = copy
		}
		db.rollbackRecord = func() {
			previousRollback()
			e.configured, e.audits, e.operation = oldConfig, oldAudits, oldOp
			e.snapshots = oldSnapshots
		}
	}
	consumer, err := NewBootstrapCandidateConsumer(s.execution.lifecycle.db, result.Scope, e)
	if err != nil {
		t.Fatal(err)
	}
	m.events = nil
	return consumer, r, e
}
func consumeIndependentBootstrap(ctx context.Context, s *BootstrapCandidateConsumer, r BootstrapConsumptionRequest) (BootstrapConsumptionResult, error) {
	p, err := s.PrepareBootstrapConsumption(ctx, r)
	if err != nil {
		return BootstrapConsumptionResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return BootstrapConsumptionResult{}, err
	}
	defer tx.Rollback()
	out, err := s.ConsumeBootstrapInTx(ctx, tx, p)
	if err != nil {
		return BootstrapConsumptionResult{}, err
	}
	if ctx.Err() != nil {
		return BootstrapConsumptionResult{}, ctx.Err()
	}
	return out, tx.Commit()
}

func TestBootstrapIndependentAssociationIdentity(t *testing.T) {
	r := independentBootstrapRequest(resultFixture(t, "unconfigured_artifact"))
	second := detached(r.Candidates[0])
	second.Purpose = "catalog"
	second.Request.InputHash = Hash(strings.Repeat("d", 64))
	second.MappingHash = Hash(strings.Repeat("e", 64))
	r.Candidates = append(r.Candidates, second)
	want, err := BootstrapConsumptionHash(r)
	if err != nil {
		t.Fatal(err)
	}
	reordered := detached(r)
	reordered.Candidates[0], reordered.Candidates[1] = reordered.Candidates[1], reordered.Candidates[0]
	if got, err := BootstrapConsumptionHash(reordered); err != nil || got != want {
		t.Fatal("order changed identity", got, err)
	}
	swapped := detached(r)
	swapped.Candidates[0].Request, swapped.Candidates[1].Request = swapped.Candidates[1].Request, swapped.Candidates[0].Request
	if got, err := BootstrapConsumptionHash(swapped); err != nil || got == want {
		t.Fatal("purpose reassignment lost", got, err)
	}
	duplicate := detached(r)
	duplicate.Candidates[1].Purpose = duplicate.Candidates[0].Purpose
	if _, err := BootstrapConsumptionHash(duplicate); err == nil {
		t.Fatal("duplicate purpose accepted")
	}
	for _, mutate := range []func(*BootstrapConsumptionRequest){
		func(v *BootstrapConsumptionRequest) { v.OfflineGrantHash = Hash(strings.Repeat("f", 64)) },
		func(v *BootstrapConsumptionRequest) { v.Candidates[0].MappingHash = Hash(strings.Repeat("f", 64)) },
		func(v *BootstrapConsumptionRequest) { v.Candidates[0].ReferenceVersion = "2" },
	} {
		v := detached(r)
		mutate(&v)
		if got, err := BootstrapConsumptionHash(v); err != nil || got == want {
			t.Fatal("association input not bound", got, err)
		}
	}
}

func TestBootstrapIndependentCommitReplayAndPreservedReferences(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	before := cloneMemory(e.m.rows)
	commits := e.db.commits
	out, err := consumeIndependentBootstrap(context.Background(), s, r)
	if err != nil || out.Replayed || e.db.commits != commits+1 || e.reserves != 1 {
		t.Fatal(out, err, e.db.events)
	}
	var d DomainRecord
	loadMemoryRecord(t, e.m, &d, 0)
	if d.State != "closed" {
		t.Fatal(d)
	}
	for table, rows := range before {
		if table != "system_backup_producer_domains" && !reflect.DeepEqual(rows, e.m.rows[table]) {
			t.Fatal("candidate history mutated", table)
		}
	}
	// Success replay is a current-authorized historical read after observation
	// expiry, even though the original epoch is already atomically closed.
	e.db.now = e.db.now.Add(24 * time.Hour)
	e.m.events = nil
	stable := cloneMemory(e.m.rows)
	replayed, err := consumeIndependentBootstrap(context.Background(), s, r)
	if err != nil || !replayed.Replayed || replayed.OperationPublicID != out.OperationPublicID || e.reserves != 1 || !reflect.DeepEqual(stable, e.m.rows) {
		t.Fatal(replayed, err)
	}
	for _, event := range e.m.events {
		if in(event, "bootstrap:reserve", "bootstrap:evidence", "bootstrap:write", "lock:system_backup_producer_grants") {
			t.Fatal("replay reconsumed", event)
		}
	}
	e.fail = "authorize"
	if denied, err := consumeIndependentBootstrap(context.Background(), s, r); err == nil || denied != (BootstrapConsumptionResult{}) || !reflect.DeepEqual(stable, e.m.rows) {
		t.Fatal("historical success bypassed current authority", denied, err)
	}
	if _, err := e.retained.SampleTime(context.Background()); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("retained write clock escaped", err)
	}
	if _, err := e.readRetained.SampleTime(context.Background()); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("retained read clock escaped", err)
	}
}

func TestBootstrapIndependentSharedCandidateUsesOnePrefix(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	alias := detached(r.Candidates[0])
	alias.Purpose = "catalog"
	alias.MappingHash = Hash(strings.Repeat("e", 64))
	r.Candidates = append(r.Candidates, alias)
	// The synthetic trusted adapter explicitly authenticates this complete
	// association. D must retain it in the hash while deduplicating SQL keys.
	e.request = detached(r)
	if _, err := consumeIndependentBootstrap(context.Background(), s, r); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, event := range e.m.events {
		if event == "bootstrap:hosts" {
			break
		}
		counts[event]++
	}
	for _, event := range []string{"bootstrap:installation", "bootstrap:authorize", "bootstrap:operation", "lock:system_backup_producer_result_receipts", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "lock:system_backup_producer_evidence_bindings"} {
		if counts[event] != 1 {
			t.Fatal("repeated full prefix for shared candidate", event, counts[event])
		}
	}
	if e.reserves != 1 {
		t.Fatal("shared candidate charged twice")
	}
}

func TestBootstrapIndependentFailuresRollback(t *testing.T) {
	for _, name := range []string{"installation", "authorize", "operation", "hosts", "refs", "reserve", "intent", "evidence", "write", "recheck", "revoked", "run_published", "target_replaced", "missing_hold", "observation_equal", "missing_claim_column", "missing_chunk_column", "chunk_index_gap", "late_receipt", "late_grant", "late_reference", "late_domain", "late_manifest", "late_chunk", "late_config", "late_operation", "late_operation_http_status", "late_audit", "late_clock"} {
		t.Run(name, func(t *testing.T) {
			s, r, e := setupIndependentBootstrap(t)
			e.fail = name
			switch name {
			case "revoked":
				var g GrantRecord
				loadMemoryRecord(t, e.m, &g, 0)
				g.State = "revoked"
				replaceMemory(t, e.m, &g)
			case "run_published":
				var run RunRecord
				loadMemoryRecord(t, e.m, &run, 0)
				run.State = "published"
				replaceMemory(t, e.m, &run)
			case "target_replaced":
				var target TargetRecord
				loadMemoryRecord(t, e.m, &target, 0)
				target.Generation = "2"
				replaceMemory(t, e.m, &target)
			case "missing_hold":
				rs := e.m.rows["system_backup_producer_evidence_refs"]
				kept := []StoredRecord{}
				for _, row := range rs {
					if row.Columns["reference_kind"] != "hold" {
						kept = append(kept, row)
					}
				}
				e.m.rows["system_backup_producer_evidence_refs"] = kept
			case "observation_equal":
				until, _ := r.Candidates[0].Request.ObservationExpiresAt.Time()
				e.db.now = until
			case "missing_claim_column":
				delete(e.snapshots[bootstrapEvidenceSnapshotSQL], "claim_owner")
			case "missing_chunk_column":
				delete(e.snapshots[bootstrapChunksSnapshotSQL], "gcm_tag")
			case "chunk_index_gap":
				e.snapshots[bootstrapChunksSnapshotSQL]["chunk_index"] = int64(1)
			case "late_receipt":
				e.beforeRecheck = func() {
					var receipt ReceiptRecord
					loadMemoryRecord(t, e.m, &receipt, 0)
					receipt.ChargedBytes = "1"
					replaceMemory(t, e.m, &receipt)
				}
			case "late_grant":
				e.beforeRecheck = func() {
					var grant GrantRecord
					loadMemoryRecord(t, e.m, &grant, 0)
					grant.State = "revoked"
					replaceMemory(t, e.m, &grant)
				}
			case "late_reference":
				e.beforeRecheck = func() {
					var ref ReferenceRecord
					loadMemoryRecord(t, e.m, &ref, 0)
					until, _ := ref.ProtectedUntil.Time()
					ref.ProtectedUntil = Timestamp(until.Add(time.Microsecond).Format(timeLayout))
					replaceMemory(t, e.m, &ref)
				}
			case "late_domain":
				e.beforeRecheck = func() {
					var domain DomainRecord
					loadMemoryRecord(t, e.m, &domain, 0)
					domain.Epoch = "3"
					domain.RowVersion = "3"
					replaceMemory(t, e.m, &domain)
				}
			case "late_manifest":
				e.beforeRecheck = func() { e.snapshots[bootstrapEvidenceSnapshotSQL]["envelope_hash"] = strings.Repeat("f", 64) }
			case "late_chunk":
				e.beforeRecheck = func() { e.snapshots[bootstrapChunksSnapshotSQL]["object_checksum"] = strings.Repeat("f", 64) }
			case "late_config":
				e.beforeRecheck = func() {
					e.snapshots[bootstrapConfigSnapshotSQL]["config_canonical_json"] = []byte(`{"synthetic":"changed"}`)
				}
			case "late_clock":
				e.beforeRecheck = func() {
					e.db.now = e.db.now.Add(2 * time.Second)
					if _, err := e.readRetained.SampleTime(context.Background()); err != nil {
						t.Fatal(err)
					}
					e.db.now = e.db.now.Add(-time.Second)
				}
			case "late_operation":
				e.beforeRecheck = func() { e.snapshots[bootstrapOperationSnapshotSQL]["target_public_id"] = "installation_other" }
			case "late_operation_http_status":
				e.beforeRecheck = func() { e.snapshots[bootstrapOperationSnapshotSQL]["http_status"] = int64(202) }
			case "late_audit":
				e.beforeRecheck = func() { e.snapshots[bootstrapAuditSnapshotSQL]["resource_id"] = int64(999) }
			}
			before := cloneMemory(e.m.rows)
			commits := e.db.commits
			out, err := consumeIndependentBootstrap(context.Background(), s, r)
			if err == nil || out != (BootstrapConsumptionResult{}) || e.db.commits != commits || !reflect.DeepEqual(before, e.m.rows) || e.configured {
				t.Fatal("failed consumption escaped rollback", out, err)
			}
			if strings.HasPrefix(name, "late_") {
				reached := false
				for _, event := range e.m.events {
					if event == "bootstrap:recheck" {
						reached = true
					}
				}
				if !reached {
					t.Fatal("late mutation test failed before its callback", err)
				}
			}
		})
	}
}

func TestBootstrapIndependentPreparedBindingAndRedaction(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	ctx := context.Background()
	p, err := s.PrepareBootstrapConsumption(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	copy := *p
	if fmt.Sprintf("%v %#v", p, p) != "PreparedBootstrapConsumption PreparedBootstrapConsumption" {
		t.Fatal("prepared exposed bindings")
	}
	if _, err := json.Marshal(p); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	for _, value := range []any{s, *s} {
		if fmt.Sprintf("%v %#v", value, value) != "BootstrapCandidateConsumer BootstrapCandidateConsumer" {
			t.Fatal("consumer exposed authority")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatal("consumer became JSON credential", err)
		}
	}
	authority := p.state.authority
	for _, value := range []any{authority, &authority} {
		if fmt.Sprintf("%v %#v", value, value) != "PreparedBootstrapAuthority PreparedBootstrapAuthority" {
			t.Fatal("prepared authority exposed adapter")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatal("prepared authority became JSON credential", err)
		}
	}
	wrong, cancel := context.WithCancel(ctx)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := s.ConsumeBootstrapInTx(wrong, tx, p); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("wrong context accepted", err)
	}
	if _, err := s.ConsumeBootstrapInTx(ctx, tx, &copy); !errors.Is(err, ErrGuardRequired) {
		t.Fatal("failed prepared reusable", err)
	}
	if e.configured {
		t.Fatal("failed binding wrote config")
	}
}

func TestBootstrapIndependentConcurrentCopiesConsumeOnce(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	ctx := context.Background()
	p, err := s.PrepareBootstrapConsumption(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	copy := *p
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	results := make(chan error, 2)
	for _, prepared := range []*PreparedBootstrapConsumption{p, &copy} {
		go func(value *PreparedBootstrapConsumption) {
			_, err := s.ConsumeBootstrapInTx(ctx, tx, value)
			results <- err
		}(prepared)
	}
	succeeded, rejected := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrGuardRequired) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || rejected != 1 || e.reserves != 1 {
		t.Fatal("prepared copies raced into multiple consumption", succeeded, rejected, e.reserves)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapIndependentExpiredExecutionBudgetPositive(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	var g GrantRecord
	loadMemoryRecord(t, e.m, &g, 0)
	var run RunRecord
	loadMemoryRecord(t, e.m, &run, 0)
	var history HistoricalBindingRecord
	loadMemoryRecord(t, e.m, &history, 0)
	// Construct the synthetic original persisted budgets after the legitimate
	// commit time and before the existing original observation expiry. The test
	// does not claim that the SQL fake authenticates deployment provenance.
	cutoff := Timestamp(e.db.now.Add(time.Microsecond).Format(timeLayout))
	g.LeaseExpiresAt, g.AuthorizationExpiresAt = cutoff, cutoff
	run.OwnerWriteExpiresAt, history.OwnerWriteExpiresAt = cutoff, cutoff
	replaceMemory(t, e.m, &g)
	replaceMemory(t, e.m, &run)
	replaceMemory(t, e.m, &history)
	lease, _ := g.LeaseExpiresAt.Time()
	auth, _ := g.AuthorizationExpiresAt.Time()
	write, _ := run.OwnerWriteExpiresAt.Time()
	// Advance SQL time beyond all three original execution budgets without
	// changing their persisted values or renewing the observation.
	now := lease
	if auth.After(now) {
		now = auth
	}
	if write.After(now) {
		now = write
	}
	now = now.Add(time.Microsecond)
	observation, _ := r.Candidates[0].Request.ObservationExpiresAt.Time()
	if !now.Before(observation) {
		t.Fatal("fixture must distinguish execution and observation deadlines", now, observation)
	}
	e.db.now = now
	if out, err := consumeIndependentBootstrap(context.Background(), s, r); err != nil || out.Replayed {
		t.Fatal("committed result inherited execution deadline", out, err)
	}
}

type independentClockPolicy struct {
	base          Policy
	db            *fakeDB
	retained      *Transaction
	ignoreFailure bool
}

type independentNilContext struct{ context.Context }

func TestBootstrapIndependentTypedNilContextRejectedBeforeAuthority(t *testing.T) {
	s, r, e := setupIndependentBootstrap(t)
	var nilContext *independentNilContext
	if prepared, err := s.PrepareBootstrapConsumption(nilContext, r); !errors.Is(err, ErrGuardRequired) || prepared != nil {
		t.Fatal("typed nil context accepted", prepared, err)
	}
	for _, event := range e.m.events {
		if strings.HasPrefix(event, "bootstrap:") {
			t.Fatal("invalid context reached authority", event)
		}
	}
}

func (p *independentClockPolicy) LockAndAuthorize(ctx context.Context, sqltx SQL, scope Scope) (GuardPlan, error) {
	tx := sqltx.(*Transaction)
	p.retained = tx
	plan, err := p.base.LockAndAuthorize(ctx, tx, scope)
	if err != nil {
		return plan, err
	}
	// The last successful sample is later than entry. A rollback still above
	// entry must fail, including when trusted integration ignores the error.
	p.db.now = p.db.now.Add(2 * time.Second)
	if _, err = tx.SampleTime(ctx); err != nil {
		return plan, err
	}
	p.db.now = p.db.now.Add(-time.Second)
	if p.ignoreFailure {
		_, _ = tx.SampleTime(ctx)
	}
	return plan, nil
}
func (p *independentClockPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	return p.base.Recheck(ctx, tx, scope, plan, now)
}
func TestBootstrapIndependentSharedClockRejectsIntermediateRollback(t *testing.T) {
	for _, ignored := range []bool{false, true} {
		t.Run(fmt.Sprint(ignored), func(t *testing.T) {
			r, db, base := setupTx(t)
			p := &independentClockPolicy{base: base, db: db, ignoreFailure: ignored}
			r.policy = p
			ctx := context.Background()
			tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = r.GuardInTx(ctx, tx, func(context.Context, *Transaction) error { t.Fatal("clock rollback reached work"); return nil })
			if !errors.Is(err, ErrExpired) || db.commits != 0 {
				t.Fatal("intermediate clock rollback accepted", err)
			}
		})
	}
}
