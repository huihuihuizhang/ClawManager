//go:build systembackup_mysql

package systembackupproducer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type bootstrapNativeRecords struct {
	request  BootstrapConsumptionRequest
	domain   DomainRecord
	grant    GrantRecord
	run      RunRecord
	target   TargetRecord
	history  HistoricalBindingRecord
	receipt  ReceiptRecord
	command  CommandReceiptRecord
	refs     []ReferenceRecord
	evidence ResultEvidence
	before   map[string][][]byte
}

func bootstrapNativeStamp(t time.Time) Timestamp {
	return Timestamp(t.UTC().Truncate(time.Microsecond).Format(timeLayout))
}
func bootstrapNativeHash(b []byte) Hash { h := sha256.Sum256(b); return Hash(hex.EncodeToString(h[:])) }

// Shift only declared protocol Timestamp values in a contract FIXTURE. This
// does not renew/rewrite an existing original source or a production record.
func bootstrapNativeShift(v reflect.Value, delta time.Duration) {
	if v.Kind() == reflect.Pointer {
		if !v.IsNil() {
			bootstrapNativeShift(v.Elem(), delta)
		}
		return
	}
	if v.Type() == reflect.TypeOf(Timestamp("")) {
		stamp, err := Timestamp(v.String()).Time()
		if err == nil {
			v.SetString(string(bootstrapNativeStamp(stamp.Add(delta))))
		}
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			bootstrapNativeShift(v.Field(i), delta)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			bootstrapNativeShift(v.Index(i), delta)
		}
	}
}

// Complete contract-derived original rows, encoded by the REAL original C1
// codec and inserted into actual migration137 tables. No fake database driver
// is created or used. These are declared fixture sources, not B/C field proof.
func bootstrapSeedNativeRecords(t *testing.T, ctx context.Context, db *sql.DB, scope Scope) *bootstrapNativeRecords {
	t.Helper()
	var now time.Time
	if err := db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		t.Fatal(err)
	}
	r := resultFixture(t, "unconfigured_artifact")
	old, err := r.ObservedAt.Time()
	if err != nil {
		t.Fatal(err)
	}
	bootstrapNativeShift(reflect.ValueOf(&r), now.Add(-30*time.Second).Sub(old))
	r.Scope = scope
	r.Evidence.OwnerID = scope.Installation
	r.ExpectedResultVersion = "0"
	r.ExpectedEvidenceVersion = "3"
	r.ObservedAt = bootstrapNativeStamp(now.Add(-30 * time.Second))
	r.ObservationExpiresAt = bootstrapNativeStamp(now.Add(2 * time.Minute))
	key := "evidence/" + string(scope.Installation) + "/system/" + string(scope.Installation) + "/" + string(r.Evidence.EvidenceID) + "/" + string(r.Evidence.ContentHash) + ".bin"
	r.Evidence.RelativeKeyHash = bootstrapNativeHash([]byte(key))
	f := &bootstrapNativeRecords{}
	f.domain = *recordFixture(t, "DomainRecord").(*DomainRecord)
	f.domain.Scope = scope
	f.domain.Epoch = r.DomainEpoch
	f.domain.RowVersion = "1"
	f.domain.State = "open"
	f.domain.Admission = detached(r.Admission)
	f.domain.AdmissionExpiresAt = bootstrapNativeStamp(now.Add(2 * time.Minute))
	f.domain.CreatedAt = bootstrapNativeStamp(now.Add(-time.Minute))
	f.domain.UpdatedAt = f.domain.CreatedAt
	f.grant = *recordFixture(t, "GrantRecord").(*GrantRecord)
	f.grant.Scope = scope
	f.grant.GrantID = r.GrantID
	f.grant.Generation = r.GrantGeneration
	f.grant.DomainEpoch = r.DomainEpoch
	f.grant.RowVersion = "2"
	f.grant.State = "active"
	f.grant.IssuerIdentityHash = f.domain.IssuerIdentityHash
	f.grant.Admission = detached(r.Admission)
	f.grant.Target = detached(r.Target)
	f.grant.Purpose = r.Purpose
	f.grant.LeaseExpiresAt = bootstrapNativeStamp(now.Add(2 * time.Minute))
	f.grant.AuthorizationExpiresAt = f.grant.LeaseExpiresAt
	f.grant.CreatedAt = f.domain.CreatedAt
	digests, err := ResultHashes(r)
	if err != nil {
		t.Fatal("native result contract fixture", err)
	}
	f.run = RunRecord{Scope: scope, RunID: r.RunID, GrantID: r.GrantID, GrantGeneration: r.GrantGeneration, TargetHash: digests.Target, TargetGeneration: r.TargetGeneration, InputHash: r.InputHash, EvidenceID: r.Evidence.EvidenceID, OwnerWriteExpiresAt: bootstrapNativeStamp(now.Add(time.Minute)), ObservedAt: &r.ObservedAt, ObservationExpiresAt: &r.ObservationExpiresAt, State: "committed", RowVersion: "5"}
	f.target = TargetRecord{Scope: scope, TargetHash: digests.Target, Target: detached(r.Target), Generation: r.TargetGeneration, CurrentRunID: r.RunID, ResultVersion: "1", RowVersion: "2"}
	pending := r.Evidence
	pending.ImmutableVersion = nil
	f.history = HistoricalBindingRecord{Scope: scope, RunID: r.RunID, GrantID: r.GrantID, GrantGeneration: r.GrantGeneration, DomainEpoch: r.DomainEpoch, Admission: detached(r.Admission), TargetHash: digests.Target, InputHash: r.InputHash, Evidence: pending, RelativeKey: RelativeKey(key), OwnerWriteExpiresAt: f.run.OwnerWriteExpiresAt, ObservedAt: r.ObservedAt, ObservationExpiresAt: r.ObservationExpiresAt, RetentionExpiresAt: bootstrapNativeStamp(now.Add(time.Hour)), RetentionPolicyHash: bootstrapNativeHash([]byte("native-fixture-retention")), CreatedAt: r.ObservedAt}
	f.receipt = ReceiptRecord{Scope: scope, ReceiptKeyHash: digests.Key, RequestHash: digests.Request, Request: detached(r), ResultVersion: "1", CommittedAt: bootstrapNativeStamp(now.Add(-5 * time.Second)), RetentionExpiresAt: f.history.RetentionExpiresAt, ChargedBytes: "1"}
	f.command = *recordFixture(t, "CommandReceiptRecord").(*CommandReceiptRecord)
	commandOld, err := f.command.CommittedAt.Time()
	if err != nil {
		t.Fatal(err)
	}
	bootstrapNativeShift(reflect.ValueOf(&f.command), now.Add(-10*time.Second).Sub(commandOld))
	f.command.Scope = scope
	f.command.Request.Scope = scope
	f.command.Request.Command = "acquire"
	f.command.Request.Expected = nil
	f.command.Request.Target = detached(r.Target)
	f.command.Request.ActorIdentityHash = f.grant.SubjectIdentityHash
	f.command.Request.ExpectedDomainEpoch = r.DomainEpoch
	targetGeneration, err := r.TargetGeneration.Uint64()
	if err != nil || targetGeneration == 0 {
		t.Fatal("native target generation")
	}
	f.command.Request.ExpectedTargetGeneration = ZeroCounter(strconv.FormatUint(targetGeneration-1, 10))
	f.command.Request.Next = &CommandNext{GrantID: r.GrantID, GrantGeneration: r.GrantGeneration, RunID: r.RunID, EvidenceID: r.Evidence.EvidenceID, SubjectIdentityHash: f.grant.SubjectIdentityHash, IssuerIdentityHash: f.domain.IssuerIdentityHash, Host: detached(f.grant.Host), Admission: detached(r.Admission), Purpose: r.Purpose, InputHash: r.InputHash, AuthorizationExpiresAt: f.grant.AuthorizationExpiresAt, OwnerWriteExpiresAt: f.run.OwnerWriteExpiresAt}
	f.command.Request.LeaseExpiresAt = &f.grant.LeaseExpiresAt
	f.command.Request.TerminationDecisionHash = nil
	f.command.Outcome = CommandExpected{GrantID: r.GrantID, GrantGeneration: r.GrantGeneration, GrantRowVersion: "1", RunID: r.RunID, TargetGeneration: r.TargetGeneration}
	f.command.CommittedAt = f.grant.CreatedAt
	f.command.RetentionExpiresAt = f.history.RetentionExpiresAt
	cd, err := CommandHashes(f.command.Request)
	if err != nil {
		t.Fatal("native command fixture", err)
	}
	f.command.ReceiptKeyHash, f.command.RequestHash = cd.Key, cd.Request
	hold, err := pendingReferenceHash(f.history)
	if err != nil {
		t.Fatal(err)
	}
	f.refs = []ReferenceRecord{{Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: "bootstrap_candidate", ReferenceKeyHash: digests.Key, ProtectedUntil: f.history.RetentionExpiresAt, CreatedAt: f.receipt.CommittedAt}, {Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: "producer_receipt", ReferenceKeyHash: digests.Key, ProtectedUntil: f.receipt.RetentionExpiresAt, CreatedAt: f.receipt.CommittedAt}, {Scope: scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: hold, ProtectedUntil: f.history.RetentionExpiresAt, CreatedAt: f.history.CreatedAt}}
	f.request = independentBootstrapRequest(r)
	f.request.ActorID = "1"
	f.request.Username = "native-bootstrap-admin"
	f.evidence = ResultEvidence{Evidence: detached(r.Evidence), RowVersion: r.ExpectedEvidenceVersion, State: "ready", Failure: "none", RetentionExpiresAt: f.history.RetentionExpiresAt, ProtectedUntil: f.history.RetentionExpiresAt}
	for _, record := range []any{&f.domain, &f.grant, &f.run, &f.target, &f.history, &f.receipt, &f.command, &f.refs[0], &f.refs[1], &f.refs[2]} {
		row, err := EncodeStoredRecord(record)
		if err != nil {
			t.Fatal("real original record codec", reflect.TypeOf(record), err)
		}
		bootstrapNativeInsert(t, ctx, db, row.Table, row.Columns)
	}
	// Evidence/metadata is explicit SQL fixture DATA for the declared model
	// authority below; it is not a native object/ciphertext validation claim.
	b := r.Evidence
	content, _ := b.ContentBytes.SQLInt64()
	object, _ := b.ObjectBytes.SQLInt64()
	retained, _ := f.history.RetentionExpiresAt.Time()
	bootstrapNativeInsert(t, ctx, db, "users", map[string]any{"id": int64(1), "username": f.request.Username, "role": "admin", "is_active": true, "auth_provider": "local"})
	bootstrapNativeInsert(t, ctx, db, "system_backup_v2_evidence", map[string]any{"id": int64(101), "schema_version": "system-backup-evidence.v1", "public_id": string(b.EvidenceID), "owner_target_type": b.OwnerType, "owner_target_public_id": string(b.OwnerID), "evidence_type": b.EvidenceType, "storage_state": "ready", "evidence_failure_code": "none", "storage_provider_role": "evidence", "storage_identity_hash": string(b.StoreIdentityHash), "storage_ref_version": string(b.StoreRefVersion), "storage_relative_key_hash": string(b.RelativeKeyHash), "storage_relative_key": key, "storage_immutable_version": string(*b.ImmutableVersion), "content_checksum": string(b.ContentHash), "content_size_bytes": content, "object_checksum": string(b.ObjectHash), "object_size_bytes": object, "redaction_classification": b.Classification, "encryption": "envelope_v1", "envelope_framing_version": "system-backup-evidence-envelope.v1", "kek_identity_hash": string(b.KEKIdentityHash), "kek_version": string(b.KEKVersion), "row_version": int64(3), "expires_at": retained, "protected_until": retained, "claim_owner": nil, "claim_expires_at": nil, "inline_payload": nil, "chunk_count": int64(1), "plaintext_chunk_size_bytes": int64(1048576), "chunk_list_root": string(bootstrapNativeHash([]byte("native-fixture-chunks"))), "envelope_hash": string(bootstrapNativeHash([]byte("native-fixture-envelope"))), "media_type": "application/json", "created_at": now})
	bootstrapNativeInsert(t, ctx, db, "system_backup_v2_evidence_chunks", map[string]any{"id": int64(1), "evidence_id": int64(101), "chunk_index": int64(0), "plaintext_offset": int64(0), "plaintext_length": content, "plaintext_sha256": string(b.ContentHash), "object_frame_offset": int64(0), "object_frame_length": object, "ciphertext_sha256": string(b.ObjectHash), "gcm_nonce": []byte("native-model-nonce"), "gcm_tag": []byte("native-model-tag")})
	f.before = bootstrapNativeRecordBytes(t, ctx, db)
	return f
}

func bootstrapNativeRecordBytes(t *testing.T, ctx context.Context, db *sql.DB) map[string][][]byte {
	t.Helper()
	out := map[string][][]byte{}
	for _, table := range bootstrapInlineTables() {
		definition, _ := storageFor(map[string]any{"system_backup_producer_domains": &DomainRecord{}, "system_backup_producer_grants": &GrantRecord{}, "system_backup_producer_runs": &RunRecord{}, "system_backup_producer_targets": &TargetRecord{}, "system_backup_producer_evidence_bindings": &HistoricalBindingRecord{}, "system_backup_producer_result_receipts": &ReceiptRecord{}, "system_backup_producer_command_receipts": &CommandReceiptRecord{}, "system_backup_producer_evidence_refs": &ReferenceRecord{}}[table])
		keys := recordPrimary(definition)
		query := "SELECT record_bytes FROM " + table + " ORDER BY "
		for i, key := range keys {
			if i > 0 {
				query += ","
			}
			query += key
		}
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			// record_bytes is the codec's C1 typed frame, not JSON.
			// Use the same bounded canonical frame parser as DecodeStoredRecord.
			tree, err := parseFrame(raw, definition.limit)
			if err != nil {
				rows.Close()
				t.Fatal("invalid C1 frame in actual original table", table, err)
			}
			if _, ok := tree.(map[string]any); !ok {
				rows.Close()
				t.Fatal("non-record C1 frame in actual original table", table)
			}
			out[table] = append(out[table], append([]byte(nil), raw...))
		}
		if rows.Err() != nil || rows.Close() != nil {
			t.Fatal("native original record EOF")
		}
	}
	return out
}
