package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ErrPublicationFirstStage means original signing history exists or cannot be
// classified completely. It never permits another signing RPC or history reset.
var ErrPublicationFirstStage = errors.New("publication signing history exists or is inconclusive")

const maxPublicationFirstStageRows = 4096
const maxPublicationFirstStageBytes = 4 << 20

// StageFirst freezes a genuinely new original backup/attempt/purpose input,
// across all workloads. Unlike Stage it rejects an existing identical input.
// The original business owner must hold/use this SAME transaction, roll back
// on any error, and explicitly commit before its own unique-send protocol.
// This method performs no Kube/provider I/O, commit, or signing. It does not
// turn a successful Stage into a once-only provider-call authorization.
func (p *SQLPreparedPublicationRecord) StageFirst(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.task == nil || p.record == nil || p.task.factory == nil || p.task.factory.local() != nil {
		return ErrRegistrationUnavailable
	}
	return p.record.owner.stageFirstSigningInput(ctx, tx, p.record.binding.Purpose, p.record.input)
}

func (s *SQLInstallationArtifactSigners) stageFirstSigningInput(ctx context.Context, tx *sql.Tx, purpose string, input []byte) error {
	if s == nil || tx == nil || ctx == nil || ctx.Err() != nil || s.owners[purpose] == nil {
		return ErrRegistrationUnavailable
	}
	a := s.owners[purpose]
	if validateFrozenSigningInput(input, a.task, a.binding) != nil {
		return ErrRegistrationUnavailable
	}
	// All production Stage paths take a shared task lock in current(). Taking
	// the original task's exclusive lock FIRST serializes history plus insertion
	// with both legacy Stage and StageFirst, including another live workload.
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status IN ('validating','publishing') AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR UPDATE`, a.binding.InstallationID, a.task.BackupPublicID, a.claim.ControllerOwner, a.claim.RowVersion).Scan(&version) != nil || version != a.claim.RowVersion {
		return ErrRegistrationUnavailable
	}
	facts, until, err := a.current(ctx, tx, true)
	if err != nil {
		return err
	}
	if err = a.firstSigningHistoryAbsent(ctx, tx); err != nil {
		return errors.Join(ErrRegistrationUnavailable, ErrPublicationFirstStage, err)
	}
	if err = s.StageSigningInput(ctx, tx, purpose, input); err != nil {
		return err
	}
	again, end, err := a.current(ctx, tx, true)
	if err != nil || facts != again || !until.Equal(end) || ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

// A's private IDs hash the entire original task, including workload. Discover
// ALL backup-owned A evidence without expiry/health/purpose filters. A missing
// root, extra child, malformed input or unreadable history must not disappear
// from a first-use decision. Complete other purposes/attempts may be retained;
// their old expiry does not authorize use and is irrelevant to classification.
func (a *SQLArtifactSigningAuthority) firstSigningHistoryAbsent(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT public_id FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND LEFT(public_id,10)='sev_asign_' ORDER BY public_id LIMIT 4097 FOR SHARE`, a.task.BackupPublicID)
	if err != nil {
		return err
	}
	ids := make(map[string]bool)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		if len(ids) >= maxPublicationFirstStageRows || ids[id] || len(id) > 128 {
			err = ErrPublicationFirstStage
			break
		}
		ids[id] = true
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	used := make(map[string]bool)
	total := 0
	for id := range ids {
		if len(id) != len("sev_asign_")+64 || !strings.HasPrefix(id, "sev_asign_") || !signingDigest.MatchString(strings.TrimPrefix(id, "sev_asign_")) {
			continue // every child/unknown ID must be accounted for below
		}
		root, _, err := a.readFrozenEvidence(ctx, tx, true, id)
		if err != nil {
			return err
		}
		raw, _, err := a.readFrozenID(ctx, tx, true, id)
		if err != nil {
			return err
		}
		total += len(raw)
		if total > maxPublicationFirstStageBytes {
			return ErrPublicationFirstStage
		}
		var frozen frozenSQLSigningInput
		if !decodeFrozenSigningJSON(raw, &frozen) || firstStageFrozenScope(frozen, id, a) != nil {
			return ErrPublicationFirstStage
		}
		if frozen.Authorization.Task.AttemptNo == a.task.AttemptNo && frozen.Authorization.Signing.Binding.Purpose == a.binding.Purpose {
			return ErrPublicationFirstStage
		}
		used[id] = true
		var index frozenSigningChunkIndex
		if json.Unmarshal(root, &index) != nil {
			return ErrPublicationFirstStage
		}
		if index.Version == "system-backup-original-sql-signing-chunks.v1" {
			// readFrozenID has authenticated the exact descriptor, every chunk,
			// parent/index/count/size/hash and common retention bound.
			for n := 0; n < index.Count; n++ {
				child := signingChunkID(id, n)
				if !ids[child] {
					return ErrPublicationFirstStage
				}
				used[child] = true
			}
		}
	}
	if len(used) != len(ids) { // includes orphan and out-of-range children
		return ErrPublicationFirstStage
	}
	return nil
}

func firstStageFrozenScope(f frozenSQLSigningInput, id string, a *SQLArtifactSigningAuthority) error {
	t, b := f.Authorization.Task, f.Authorization.Signing.Binding
	digest := sha256.Sum256(f.Input)
	if f.Version != "system-backup-original-sql-signing-input.v1" || t.BackupPublicID != a.task.BackupPublicID || t.OperationID != a.task.OperationID || t.AttemptNo < 1 || b.InstallationID != a.binding.InstallationID || !artifactSigningPurpose(b.Purpose) || !signingDigest.MatchString(f.CaptureResultSHA256) || f.CaptureEpoch == 0 || f.Authorization.Signing.InputSHA256 != hex.EncodeToString(digest[:]) || signingInputEvidenceID(t, b.InstallationID, b.Purpose) != id || validateFrozenSigningInput(f.Input, t, b) != nil {
		return ErrPublicationFirstStage
	}
	for _, value := range []string{t.Workload.Namespace, t.Workload.PodUID, t.Workload.ServiceAccountUID} {
		if !providerBoundedString(value) {
			return ErrPublicationFirstStage
		}
	}
	return nil
}
