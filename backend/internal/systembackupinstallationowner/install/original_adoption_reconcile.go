package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"reflect"

	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
)

// ReconcileOriginalAdoptionCommit resolves ONLY the actual committed outcome
// of one genuine original held set. Expectations come from the private durable
// journal written BEFORE that exact COMMIT, never caller IDs/rows/hashes. This
// does not retry Stage/AdoptCoverage, renew capture or authorize an uncommitted
// result. A rolled-back/mixed/unknown outcome retains isolation for a distinct
// exact original-snapshot rollback reconciliation.
func (i *Installer) ReconcileOriginalAdoptionCommit(ctx context.Context, password []byte, enrollment EnrollmentPin, set *PreparedOriginalWriterSet) (OriginalAdoptionCommitInspection, error) {
	var zero OriginalAdoptionCommitInspection
	if i == nil || set == nil {
		return zero, ErrInstall
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.origin != set || set.owner == nil || set.owner.operator == nil || set.owner.operator.installer != i || set.owner.enrollment != enrollment || set.actualHold == nil || set.actualHold.origin != set.actualHold || set.actualHold.set != set || !set.actualHold.adoptionUnknown || set.owner.commitUnknown || set.application.unknown || set.journal == nil || consumerSameContext(ctx, set.owner.ctx) {
		return zero, ErrCommitUnknown
	}
	operator, err := i.authenticate(ctx, password)
	if err != nil || operator.userID != set.owner.operator.userID || operator.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	// A's original journal/provider binding reader executes genuine full fsync
	// chain/custody/in-memory-tail checks without granting a recovery capability.
	inspectionAuthority := &OriginalWriterRecoveryAuthorization{set: set, operator: operator, enrollment: enrollment, operation: set.owner.operation, inventory: set.inventorySHA, journal: set.journal}
	if inspectionAuthority.targetPermissions(ctx) != nil {
		return zero, ErrInstall
	}
	journal, err := inspectionAuthority.inspectOriginal(ctx)
	if err != nil || !inspectionAuthority.providersMatchJournal(set.actualHold.providers, journal) {
		return zero, ErrCommitUnknown
	}
	var expected originalAdoptionCommitExpected
	found := 0
	for _, record := range journal.Records {
		if record.Action != "adoption_commit_send_unknown" {
			continue
		}
		found++
		if record.Writer != "" || record.Original != nil {
			return zero, ErrCommitUnknown
		}
		decoder := json.NewDecoder(bytes.NewReader(record.Data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&expected) != nil || decoder.Decode(new(any)) != io.EOF {
			return zero, ErrCommitUnknown
		}
		encoded, e := json.Marshal(expected)
		if e != nil || !bytes.Equal(encoded, record.Data) {
			return zero, ErrCommitUnknown
		}
	}
	target := i.plan.Target
	if found != 1 || expected.Version != "original-adoption-commit-expectation.v1" || expected.Operation != set.owner.operation || expected.InventorySHA256 != set.inventorySHA || expected.InstallationID != target.InstallationID || expected.ServerUUID != target.ServerUUID || expected.Database != target.Database || len(expected.ControlRows) != 17 || len(expected.Sources) != 4 || expected.NewEpoch != expected.OldEpoch+1 {
		return zero, ErrCommitUnknown
	}
	// Permanently close capture before waiting any actual provider. An error
	// retains the actual original journal/keys and never clears the unknown bit.
	set.recovering = true
	set.actualHold.closed = true
	set.owner.mu.Lock()
	set.owner.failed = true
	set.owner.mu.Unlock()
	set.recoveryAuthorization = nil
	for _, provider := range set.actualHold.providers {
		if provider == nil || provider.Stop(ctx) != nil {
			return zero, ErrCommitUnknown
		}
	}
	if checkOriginalAdoptionReconcileAuthority(ctx, inspectionAuthority) != nil {
		return zero, ErrCommitUnknown
	}
	// This existing comparison locks the original held gate and KEK fence before
	// checking all four derived coverage rows, exact reference/binding sets and
	// all 17 actual evidence payload bytes/checksums in one SQL snapshot.
	if readbackOriginalAdoptionCommit(ctx, i.db, expected) != nil {
		return zero, ErrCommitUnknown
	}
	if operator.authority(ctx, enrollment) != nil || checkOriginalAdoptionReconcileAuthority(ctx, inspectionAuthority) != nil {
		return zero, ErrCommitUnknown
	}
	if set.journal.append(ctx, "", "adoption_commit_reconciled_committed_readback", nil, expected) != nil {
		return zero, ErrCommitUnknown
	}
	set.actualHold.adoptionUnknown = false
	return OriginalAdoptionCommitInspection{Version: "original-adoption-commit-inspection.v1", Operation: expected.Operation, State: "committed_exact_original_fresh_admin_readback", InventorySHA256: expected.InventorySHA256, ExpectedSHA256: originalObjectSHA(expected), ExpectedEpoch: expected.NewEpoch}, nil
}

func checkOriginalAdoptionReconcileAuthority(ctx context.Context, authority *OriginalWriterRecoveryAuthorization) error {
	s := authority.set
	tx, err := authority.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrCommitUnknown
	}
	defer tx.Rollback()
	// Use the same ordering as recovery, settling the original uncertain COMMIT
	// before taking the consistent source snapshot. No native/network I/O occurs
	// after these locks are held.
	var admission sql.NullString
	if tx.QueryRowContext(ctx, `SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&admission) != nil || !admission.Valid || admission.String != s.application.owner {
		return ErrCommitUnknown
	}
	var phase, owner, inventory string
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token,registry_hash FROM system_backup_gate WHERE scope=? FOR UPDATE`, s.application.scope).Scan(&phase, &owner, &generation, &token, &inventory) != nil || phase != s.application.phase || phase != "held" || owner != s.application.owner || generation != s.application.generation || token != s.application.token || inventory != s.inventorySHA {
		return ErrCommitUnknown
	}
	actual, err := (c.SQLCoordinationTransaction{Tx: tx}).LockGate(ctx, s.owner.token.Key)
	if err != nil || actual != s.owner.token.GateSnapshot || actual.State != c.GateHeld || authority.lockAuthority(ctx, tx) != nil {
		return ErrCommitUnknown
	}
	sources, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(sources, s.owner.instances) || tx.Rollback() != nil {
		return ErrCommitUnknown
	}
	return nil
}
