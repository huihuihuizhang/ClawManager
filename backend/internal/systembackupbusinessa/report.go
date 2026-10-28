package systembackupbusinessa

import (
	"context"
	"errors"
	"regexp"
)

// ReportTarget identifies the controller-owned task. It supplies no authority;
// capture and target-read proofs are still required by the underlying verifier.
type ReportTarget struct {
	Type      string
	PublicID  string
	AttemptNo *int64
}

// VerificationReport is one v12 verifier-result envelope. Its aggregate status
// is derived from Checks, as required by the contract, rather than persisted.
type VerificationReport struct {
	SchemaVersion  string  `json:"schema_version"`
	TargetType     string  `json:"target_type"`
	TargetPublicID string  `json:"target_public_id"`
	AttemptNo      *int64  `json:"attempt_no"`
	Category       string  `json:"category"`
	Mode           string  `json:"mode"`
	Checks         []Check `json:"checks"`
}

// VerificationReports keeps the two category envelopes separate. A report is
// diagnostic output, not a publication, capture certificate or download grant.
type VerificationReports struct {
	Users     VerificationReport `json:"users"`
	AIGateway VerificationReport `json:"ai_gateway"`
}

var reportTargetPatterns = map[string]*regexp.Regexp{
	"backup":          regexp.MustCompile(`^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"drill":           regexp.MustCompile(`^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"preflight":       regexp.MustCompile(`^spf_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"artifact_verify": regexp.MustCompile(`^sav_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
}

func (t ReportTarget) valid() bool {
	p := reportTargetPatterns[t.Type]
	return p != nil && p.MatchString(t.PublicID) && (t.AttemptNo == nil || *t.AttemptNo > 0)
}

func (t ReportTarget) snapshot() ReportTarget {
	if t.AttemptNo != nil {
		n := *t.AttemptNo
		t.AttemptNo = &n
	}
	return t
}

func reportsFromChecks(target ReportTarget, mode string, checks CategoryChecks) VerificationReports {
	makeReport := func(category string, items []Check) VerificationReport {
		var attempt *int64
		if target.AttemptNo != nil {
			n := *target.AttemptNo
			attempt = &n
		}
		return VerificationReport{SchemaVersion: "system-backup-verifier-result.v1",
			TargetType: target.Type, TargetPublicID: target.PublicID, AttemptNo: attempt,
			Category: category, Mode: mode, Checks: items}
	}
	return VerificationReports{Users: makeReport("users", checks.Users), AIGateway: makeReport("ai_gateway", checks.AIGateway)}
}

// VerifyBackupReports preserves completed mismatch checks alongside the error.
// Unauthenticated, invalid or incomplete reads never produce a report.
func VerifyBackupReports(ctx context.Context, target ReportTarget, scope *CaptureScope,
	source, dump CaptureEvidence, proof CaptureProofVerifier) (VerificationReports, error) {
	target = target.snapshot()
	if !target.valid() {
		return VerificationReports{}, ErrCaptureEvidenceIncomplete
	}
	checks, err := VerifyBackupSnapshot(ctx, scope, source, dump, proof)
	if err != nil && (!errors.Is(err, ErrSnapshotMismatch) || len(checks.Users) != 8 || len(checks.AIGateway) != 12) {
		return VerificationReports{}, err
	}
	if len(checks.Users) != 8 || len(checks.AIGateway) != 12 {
		return VerificationReports{}, ErrInvalidSnapshot
	}
	return reportsFromChecks(target, "backup_validate", checks), err
}

// VerifyRestoreReports reads the actual target through the existing SELECT-only
// proof boundary. Failed comparisons are reportable; SQL/proof failures are not.
func (v SQLRestoreVerifier) VerifyRestoreReports(ctx context.Context, target ReportTarget, scope *CaptureScope,
	expected SourceSnapshot, evidenceRef string) (VerificationReports, error) {
	target = target.snapshot()
	if !target.valid() {
		return VerificationReports{}, ErrCaptureEvidenceIncomplete
	}
	checks, err := v.VerifyRestoreTarget(ctx, scope, expected, evidenceRef)
	if err != nil && (!errors.Is(err, ErrRestoreNormalizationMismatch) || len(checks.Users) != 11 || len(checks.AIGateway) != 14) {
		return VerificationReports{}, err
	}
	if len(checks.Users) != 11 || len(checks.AIGateway) != 14 {
		return VerificationReports{}, ErrInvalidSnapshot
	}
	return reportsFromChecks(target, "restore_validate", checks), err
}
