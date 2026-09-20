package systembackupresources

import (
	"context"
	"errors"
	"fmt"
)

// CaptureSnapshotEvidence is redacted metadata claimed for one source view or
// captured dump. The B-owned proof verifier must authenticate both claims and
// bind them to the same capture certificate before comparison is meaningful.
type CaptureSnapshotEvidence struct {
	CheckpointHash     string         `json:"checkpoint_hash"`
	CaptureContextHash string         `json:"capture_context_hash"`
	EvidenceRef        string         `json:"evidence_ref"`
	Snapshot           SourceSnapshot `json:"snapshot"`
}

// CaptureProofVerifier is supplied by B's capture/reader integration. It must
// verify the certificate, dump content and both snapshots; a reference alone
// is not evidence of a successful capture.
type CaptureProofVerifier interface {
	VerifyCapture(ctx context.Context, source, dump CaptureSnapshotEvidence) error
}

type ResourcesCheck struct {
	ID                  string         `json:"id"`
	Status              string         `json:"status"`
	SkipReason          *string        `json:"skip_reason"`
	Expected            map[string]any `json:"expected"`
	Actual              map[string]any `json:"actual"`
	EvidenceRef         *string        `json:"evidence_ref"`
	WarningCode         *string        `json:"warning_code"`
	CheckClassification *string        `json:"check_classification"`
	FailureCategory     string         `json:"failure_category"`
}

// VerifyBackupSnapshot compares only complete, authenticated resources views.
// It is an offline draft and is not wired into backup eligibility.
func VerifyBackupSnapshot(ctx context.Context, registryJSON []byte, source, dump CaptureSnapshotEvidence, proof CaptureProofVerifier) ([]ResourcesCheck, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tables, err := CaptureTableAllowlist(registryJSON)
	if err != nil {
		return nil, err
	}
	if proof == nil {
		return nil, errors.New("resources capture proof verifier is required")
	}
	for _, entry := range []CaptureSnapshotEvidence{source, dump} {
		if !sha256Pattern.MatchString(entry.CheckpointHash) || !sha256Pattern.MatchString(entry.CaptureContextHash) || !evidenceIDPattern.MatchString(entry.EvidenceRef) {
			return nil, errors.New("invalid resources capture evidence identity")
		}
		if err := validateSnapshot(entry.Snapshot, tables); err != nil {
			return nil, err
		}
	}
	if err := proof.VerifyCapture(ctx, source, dump); err != nil {
		return nil, fmt.Errorf("resources capture proof: %w", err)
	}
	checks := make([]ResourcesCheck, 0, len(tables)+3)
	checks = append(checks, resourcesCheck("resources.checkpoint", "hash", source.CheckpointHash, dump.CheckpointHash, dump.EvidenceRef))
	checks = append(checks, resourcesCheck("resources.capture_context", "hash", source.CaptureContextHash, dump.CaptureContextHash, dump.EvidenceRef))
	for i, table := range tables {
		checks = append(checks, resourcesCheck("resources.table_count."+table, "rows", source.Snapshot.Tables[i].Rows, dump.Snapshot.Tables[i].Rows, dump.EvidenceRef))
	}
	checks = append(checks, resourcesCheck("resources.audit_cutoff", "max_id", source.Snapshot.AuditMaxID, dump.Snapshot.AuditMaxID, dump.EvidenceRef))
	return checks, nil
}

func validateSnapshot(snapshot SourceSnapshot, tables []string) error {
	if len(snapshot.Tables) != len(tables) {
		return errors.New("incomplete resources snapshot table set")
	}
	for i, table := range tables {
		if snapshot.Tables[i].Table != table || snapshot.Tables[i].Rows < 0 {
			return fmt.Errorf("invalid resources snapshot table %s", table)
		}
	}
	count := snapshot.Tables[0].Rows // audit_logs is first in the sorted allowlist.
	if (count == 0) != (snapshot.AuditMaxID == nil) || (snapshot.AuditMaxID != nil && *snapshot.AuditMaxID < 0) {
		return errors.New("invalid resources audit cutoff")
	}
	return nil
}

func resourcesCheck(id, key string, expected, actual any, evidence string) ResourcesCheck {
	check := ResourcesCheck{ID: id, Status: "passed", Expected: map[string]any{key: redactedValue(expected)}, Actual: map[string]any{key: redactedValue(actual)}, EvidenceRef: &evidence, FailureCategory: "none"}
	if !equalRedactedValue(expected, actual) {
		classification := "integrity"
		check.Status = "failed"
		check.CheckClassification = &classification
		check.FailureCategory = "validation_failed"
	}
	return check
}

func redactedValue(value any) any {
	if pointer, ok := value.(*int64); ok {
		if pointer == nil {
			return nil
		}
		return *pointer
	}
	return value
}

func equalRedactedValue(a, b any) bool {
	left, leftPointer := a.(*int64)
	right, rightPointer := b.(*int64)
	if leftPointer || rightPointer {
		if !leftPointer || !rightPointer || (left == nil) != (right == nil) {
			return false
		}
		return left == nil || *left == *right
	}
	return a == b
}
