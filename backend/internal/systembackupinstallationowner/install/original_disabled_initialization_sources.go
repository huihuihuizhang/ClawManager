package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

func originalDisabledRecoveredOwner(ctx context.Context, i *Installer, enrollment EnrollmentPin, s *PreparedOriginalWriterSet) bool {
	if s == nil || s.origin != s || !s.used || !s.recovering || s.owner == nil || s.owner.origin != s.owner || s.owner.operator == nil || s.owner.operator.installer != i || s.owner.enrollment != enrollment || !consumerSameContext(ctx, s.owner.ctx) || ctx.Err() != nil || s.application.unknown || s.owner.commitUnknown || s.application.phase != "idle" || s.owner.token.State != c.GateIdle {
		return false
	}
	s.owner.mu.Lock()
	poisoned := s.owner.failed
	s.owner.mu.Unlock()
	r := s.recoveryAuthorization
	h := s.actualHold
	return poisoned && r != nil && r.origin == r && r.set == s && r.providersStopped && r.enrollment == enrollment && r.journal == s.journal && h != nil && h.origin == h && h.set == s && h.closed && !h.adoptionUnknown
}

// The public journal DTO alone is never sufficient: the caller above already
// owns the genuine completed set, closed hold and actual recovery capability.
func originalDisabledJournal(ctx context.Context, s *PreparedOriginalWriterSet) (OriginalWriterJournalInspection, error) {
	var zero OriginalWriterJournalInspection
	j := s.journal
	if j == nil {
		return zero, ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || j.root == nil || j.checkDirectory() != nil {
		return zero, ErrInstall
	}
	out, e := j.inspect(ctx, s.owner.operation, s.inventorySHA)
	if e != nil || out.TailSHA256 != j.tail || uint64(len(out.Records)) != j.sequence {
		return zero, ErrInstall
	}
	found := false
	for _, r := range out.Records {
		if r.Action != "original_sources_released_readback" {
			continue
		}
		var proof struct {
			Gate        c.GateSnapshot
			ProofSHA256 string
		}
		if json.Unmarshal(r.Data, &proof) != nil || !digestPattern.MatchString(proof.ProofSHA256) || proof.Gate != s.owner.token.GateSnapshot {
			return zero, ErrInstall
		}
		found = true
	}
	if !found {
		return zero, ErrInstall
	}
	return out, nil
}

func originalDisabledAdoptedJournal(j OriginalWriterJournalInspection, snapshot reg.Snapshot, cfg a.SQLCoverageOwnerConfig) (originalAdoptionCommitExpected, error) {
	var out originalAdoptionCommitExpected
	found := false
	for _, row := range j.Records {
		if row.Action == "adoption_commit_readback" || row.Action == "adoption_commit_reconciled_committed_readback" {
			var current originalAdoptionCommitExpected
			if json.Unmarshal(row.Data, &current) != nil || found && originalObjectSHA(current) != originalObjectSHA(out) {
				return originalAdoptionCommitExpected{}, ErrInstall
			}
			out = current
			found = true
		}
	}
	if !found || out.Version != "original-adoption-commit-expectation.v1" || out.Operation != j.Operation || out.InventorySHA256 != j.InventorySHA256 || out.InstallationID != snapshot.InstallationID || out.ServerUUID != snapshot.Database.ServerUUID || out.Database != snapshot.Database.Database || out.NewEpoch != out.OldEpoch+1 || out.NewEpoch != snapshot.Epoch || len(out.ControlRows) != 17 || len(out.Sources) != 4 || !reflect.DeepEqual(out.Sources, snapshot.Coverage) || !reflect.DeepEqual(out.References, snapshot.References) || !reflect.DeepEqual(out.Bindings, snapshot.Bindings) {
		return originalAdoptionCommitExpected{}, ErrInstall
	}
	ids := map[string]bool{cfg.Adoption.Source.RecordID: true}
	for _, pin := range cfg.Witnesses {
		if ids[pin.Source.RecordID] {
			return originalAdoptionCommitExpected{}, ErrInstall
		}
		ids[pin.Source.RecordID] = true
	}
	if len(ids) != 17 {
		return originalAdoptionCommitExpected{}, ErrInstall
	}
	for id, digest := range out.ControlRows {
		if !ids[id] || !digestPattern.MatchString(digest) {
			return originalAdoptionCommitExpected{}, ErrInstall
		}
	}
	return out, nil
}

func originalDisabledLockReleasedGates(ctx context.Context, tx *sql.Tx, s *PreparedOriginalWriterSet) error {
	var owner sql.NullString
	if tx.QueryRowContext(ctx, "SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR SHARE", s.application.scope).Scan(&owner) != nil || owner.Valid {
		return ErrInstall
	}
	var phase, inventory string
	var generation, token uint64
	if tx.QueryRowContext(ctx, "SELECT phase,owner,generation,fencing_token,registry_hash FROM system_backup_gate WHERE scope=? FOR SHARE", s.application.scope).Scan(&phase, &owner, &generation, &token, &inventory) != nil || phase != "idle" || owner.Valid || generation != s.application.generation || token != s.application.token || inventory != s.inventorySHA {
		return ErrInstall
	}
	actual, e := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, s.owner.token.Key)
	if e != nil || actual != s.owner.token.GateSnapshot || actual.State != c.GateIdle {
		return ErrInstall
	}
	return nil
}

func originalDisabledSQLSession(ctx context.Context, tx *sql.Tx) error {
	var role string
	var connection uint64
	var offset int64
	if tx == nil || tx.QueryRowContext(ctx, "SELECT CURRENT_ROLE(),CONNECTION_ID(),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&role, &connection, &offset) != nil || role != "NONE" || connection == 0 || offset != 0 {
		return ErrInstall
	}
	return nil
}

// Compare the actual signed envelopes against the ORIGINAL committed journal,
// in addition to A's independent signatures/source pins/current-17 checks.
// Call only after LockOriginalEvidence, before F. Never trust a caller digest.
func originalDisabledLockCommittedControls(ctx context.Context, tx *sql.Tx, e originalAdoptionCommitExpected) error {
	if len(e.ControlRows) != 17 {
		return ErrInstall
	}
	ids := make([]string, 0, 17)
	for id := range e.ControlRows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var raw []byte
		var checksum string
		var size uint64
		if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='catalog_scan_receipt' AND storage_state='inline' AND encryption='none' AND observed_health='healthy' FOR SHARE`, id, e.InstallationID).Scan(&raw, &checksum, &size) != nil || uint64(len(raw)) != size || hash(raw) != checksum {
			return ErrInstall
		}
		var signed a.SignedCoverageOwnerRecord
		if json.Unmarshal(raw, &signed) != nil || originalObjectSHA(signed) != e.ControlRows[id] {
			return ErrInstall
		}
	}
	return nil
}

func originalDisabledLockConfigPrefix(ctx context.Context, tx *sql.Tx, installation string) error {
	return originalDisabledConfigPrefix(ctx, tx, installation, true)
}

func originalDisabledConfigPrefix(ctx context.Context, tx *sql.Tx, installation string, absent bool) error {
	suffix := " FOR SHARE"
	if absent {
		suffix = " FOR UPDATE"
	}
	for _, query := range []string{"SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id", "SELECT origin_installation_id FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version"} {
		rows, e := tx.QueryContext(ctx, query+suffix)
		if e != nil {
			return ErrInstall
		}
		count := 0
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil || absent && id == installation || count >= 10000 {
				rows.Close()
				return ErrInstall
			}
			count++
		}
		if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
			return ErrInstall
		}
	}
	return nil
}

func originalDisabledNoAdmission(ctx context.Context, tx *sql.Tx, installation string) error {
	rows, e := tx.QueryContext(ctx, "SELECT operation_id FROM system_backup_v2_kek_admissions WHERE installation_id=? ORDER BY operation_id FOR SHARE", installation)
	if e != nil {
		return ErrInstall
	}
	found := rows.Next()
	err := rows.Err()
	extra := rows.NextResultSet()
	closed := rows.Close()
	if found || err != nil || extra || closed != nil {
		return ErrInstall
	}
	return nil
}
