package systembackupbusinessa

import (
	"context"
	"database/sql"
)

// SQLBackupReporter reads both actual views; request-supplied snapshot values
// are replaced by those reads. Each view uses its own read-only RR transaction.
// Proof must independently authenticate the two views and their checkpoint;
// sequential reads alone do not establish a common capture checkpoint.
type SQLBackupReporter struct {
	SourceDB *sql.DB
	TargetDB *sql.DB
	Proof    CaptureProofVerifier
}

func (v SQLBackupReporter) VerifyReports(ctx context.Context, target ReportTarget, scope *CaptureScope,
	source, dump CaptureEvidence) (VerificationReports, error) {
	target = target.snapshot()
	if !target.valid() || scope == nil || v.SourceDB == nil || v.TargetDB == nil || v.SourceDB == v.TargetDB || nilProof(v.Proof) {
		return VerificationReports{}, ErrCaptureEvidenceIncomplete
	}
	for _, evidence := range []CaptureEvidence{source, dump} {
		if evidence.RegistrySHA256 != scope.registrySHA || evidence.SchemaSHA256 != scope.schemaSHA ||
			!hashPattern.MatchString(evidence.CheckpointHash) || !hashPattern.MatchString(evidence.CaptureContextHash) || !evidencePattern.MatchString(evidence.EvidenceRef) {
			return VerificationReports{}, ErrInvalidSnapshot
		}
	}
	var err error
	source.Snapshot, err = (SQLCountCollector{DB: v.SourceDB}).CollectSnapshot(ctx, scope)
	if err != nil {
		return VerificationReports{}, err
	}
	dump.Snapshot, err = (SQLCountCollector{DB: v.TargetDB}).CollectSnapshot(ctx, scope)
	if err != nil {
		return VerificationReports{}, err
	}
	return VerifyBackupReports(ctx, target, scope, source, dump, v.Proof)
}
