package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
)

// CaptureEvidence is redacted metadata for one source view or captured dump.
// The evidence reference is only an identifier; it is not proof by itself.
type CaptureEvidence struct {
	RegistrySHA256     string         `json:"registry_sha256"`
	SchemaSHA256       string         `json:"schema_sha256"`
	CheckpointHash     string         `json:"checkpoint_hash"`
	CaptureContextHash string         `json:"capture_context_hash"`
	EvidenceRef        string         `json:"evidence_ref"`
	Snapshot           SourceSnapshot `json:"snapshot"`
}

// CaptureProofVerifier is supplied by B. It must authenticate the capture
// certificate, dump, both registered evidence references and their snapshots,
// and prove both views belong to the same checkpoint.
type CaptureProofVerifier interface {
	VerifyCapture(context.Context, CaptureEvidence, CaptureEvidence) error
}

type Check struct {
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

// CategoryChecks can be wrapped into the v12 verifier envelope for either
// business category. No A check is shared across those two envelopes.
type CategoryChecks struct {
	Users     []Check `json:"users"`
	AIGateway []Check `json:"ai_gateway"`
}

// CategoryStatistics are redacted facts; they are not a PartResult or a
// manifest BusinessSummary because staging bytes and task ownership are not
// available from this source-side verifier.
type CategoryStatistics struct {
	Category string `json:"category"`
	Objects  int64  `json:"objects"`
	Rows     int64  `json:"rows"`
}

// VerifiedBusinessMetadata is available only after B's capture proof and all
// A integrity checks pass. D may combine it with separately verified staging
// and job facts; this type cannot claim a completed backup part by itself.
type VerifiedBusinessMetadata struct {
	Checks             CategoryChecks       `json:"checks"`
	Statistics         []CategoryStatistics `json:"statistics"`
	RegistrySHA256     string               `json:"registry_sha256"`
	SchemaSHA256       string               `json:"schema_sha256"`
	CheckpointHash     string               `json:"checkpoint_hash"`
	CaptureContextHash string               `json:"capture_context_hash"`
	EvidenceIDs        []string             `json:"evidence_ids"`
}

var (
	ErrSnapshotMismatch          = errors.New("A business snapshot integrity mismatch")
	ErrInvalidSnapshot           = errors.New("A business snapshot invalid")
	ErrCaptureEvidenceIncomplete = errors.New("A business capture evidence incomplete")
)

// KnownVerificationFailureCategory maps only A-owned failure facts. Provider
// signature, permission, storage and timeout errors retain B's original type.
func KnownVerificationFailureCategory(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrSnapshotMismatch), errors.Is(err, ErrInvalidSnapshot):
		return "validation_failed", true
	case errors.Is(err, ErrRestoreNormalizationMismatch), errors.Is(err, ErrUserRestoreMapping),
		errors.Is(err, ErrUserQuotaRestore), errors.Is(err, ErrNorthboundChallengeRestore),
		errors.Is(err, ErrNorthboundSessionRestore), errors.Is(err, ErrNorthboundCallerPolicyRestore),
		errors.Is(err, ErrEnterpriseAuthRestore), errors.Is(err, ErrLLMModelRestore),
		errors.Is(err, ErrGatewayAliasRestore), errors.Is(err, ErrRiskRuleRestore),
		errors.Is(err, ErrRiskHitRestore), errors.Is(err, ErrChatSessionRestore),
		errors.Is(err, ErrChatMessageRestore), errors.Is(err, ErrModelInvocationRestore),
		errors.Is(err, ErrAuditEventRestore), errors.Is(err, ErrCostRecordRestore),
		errors.Is(err, ErrAIGatewayCrossTableRestore), errors.Is(err, ErrAIGatewayHistoryRestore),
		errors.Is(err, ErrBusinessRestore):
		return "normalization_failed", true
	case errors.Is(err, ErrCaptureEvidenceIncomplete):
		return "evidence_incomplete", true
	default:
		return "", false
	}
}

// VerifyBusinessMetadata returns no metadata on proof failure or mismatch.
// It deliberately has no completed/eligible status or staging byte count.
func VerifyBusinessMetadata(ctx context.Context, scope *CaptureScope, source, dump CaptureEvidence, proof CaptureProofVerifier) (VerifiedBusinessMetadata, error) {
	source.Snapshot = cloneSourceSnapshot(source.Snapshot)
	dump.Snapshot = cloneSourceSnapshot(dump.Snapshot)
	checks, err := VerifyBackupSnapshot(ctx, scope, source, dump, proof)
	if err != nil {
		return VerifiedBusinessMetadata{}, err
	}
	statistics := []CategoryStatistics{{Category: "users"}, {Category: "ai_gateway"}}
	for _, count := range dump.Snapshot.Tables {
		index := 0
		if tables[count.Table].category == "ai_gateway" {
			index = 1
		}
		statistics[index].Objects++
		statistics[index].Rows += count.Rows // validateSnapshot has checked total overflow.
	}
	refs := []string{source.EvidenceRef}
	if dump.EvidenceRef != source.EvidenceRef {
		refs = append(refs, dump.EvidenceRef)
	}
	return VerifiedBusinessMetadata{Checks: checks, Statistics: statistics,
		RegistrySHA256: scope.registrySHA, SchemaSHA256: scope.schemaSHA,
		CheckpointHash: dump.CheckpointHash, CaptureContextHash: dump.CaptureContextHash,
		EvidenceIDs: refs}, nil
}

// VerifyBackupSnapshot compares complete, authenticated redacted statistics.
// It does not normalize rows or grant artifact eligibility.
func VerifyBackupSnapshot(ctx context.Context, scope *CaptureScope, source, dump CaptureEvidence, proof CaptureProofVerifier) (CategoryChecks, error) {
	if ctx == nil {
		return CategoryChecks{}, errors.New("nil A business verification context")
	}
	if err := ctx.Err(); err != nil {
		return CategoryChecks{}, err
	}
	if scope == nil || len(scope.tables) != len(tables) || !hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) {
		return CategoryChecks{}, errors.New("A business pinned scope required")
	}
	if nilProof(proof) {
		return CategoryChecks{}, ErrCaptureEvidenceIncomplete
	}
	source.Snapshot = cloneSourceSnapshot(source.Snapshot)
	dump.Snapshot = cloneSourceSnapshot(dump.Snapshot)
	for _, evidence := range []CaptureEvidence{source, dump} {
		if evidence.EvidenceRef == "" {
			return CategoryChecks{}, ErrCaptureEvidenceIncomplete
		}
		if evidence.RegistrySHA256 != scope.registrySHA || evidence.SchemaSHA256 != scope.schemaSHA ||
			!hashPattern.MatchString(evidence.CheckpointHash) || !hashPattern.MatchString(evidence.CaptureContextHash) ||
			!evidencePattern.MatchString(evidence.EvidenceRef) {
			return CategoryChecks{}, ErrInvalidSnapshot
		}
		if err := validateSnapshot(evidence.Snapshot, scope.tables); err != nil {
			return CategoryChecks{}, err
		}
	}
	proofSource, proofDump := source, dump
	proofSource.Snapshot = cloneSourceSnapshot(source.Snapshot)
	proofDump.Snapshot = cloneSourceSnapshot(dump.Snapshot)
	if err := proof.VerifyCapture(ctx, proofSource, proofDump); err != nil {
		return CategoryChecks{}, fmt.Errorf("A business capture proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return CategoryChecks{}, err
	}
	checks := CategoryChecks{Users: make([]Check, 0, 8), AIGateway: make([]Check, 0, 12)}
	for _, category := range []string{"users", "ai_gateway"} {
		categoryChecks := []Check{
			compare(category+".checkpoint", "hash", source.CheckpointHash, dump.CheckpointHash, dump.EvidenceRef),
			compare(category+".capture_context", "hash", source.CaptureContextHash, dump.CaptureContextHash, dump.EvidenceRef),
		}
		if category == "users" {
			checks.Users = append(checks.Users, categoryChecks...)
		} else {
			checks.AIGateway = append(checks.AIGateway, categoryChecks...)
		}
	}
	for i, table := range scope.tables {
		category := tables[table].category
		check := compare(category+".table_count."+table, "rows", source.Snapshot.Tables[i].Rows, dump.Snapshot.Tables[i].Rows, dump.EvidenceRef)
		if category == "users" {
			checks.Users = append(checks.Users, check)
		} else {
			checks.AIGateway = append(checks.AIGateway, check)
		}
	}
	checks.AIGateway = append(checks.AIGateway, compare("ai_gateway.cost_aggregates", "hash", source.Snapshot.CostAggregateSHA256, dump.Snapshot.CostAggregateSHA256, dump.EvidenceRef))
	for _, check := range append(checks.Users, checks.AIGateway...) {
		if check.Status != "passed" {
			return checks, ErrSnapshotMismatch
		}
	}
	return checks, nil
}

func nilProof(proof CaptureProofVerifier) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validateSnapshot(snapshot SourceSnapshot, allowlist []string) error {
	if len(snapshot.Tables) != len(allowlist) {
		return fmt.Errorf("%w: incomplete table set", ErrInvalidSnapshot)
	}
	if !hashPattern.MatchString(snapshot.CostAggregateSHA256) {
		return fmt.Errorf("%w: missing cost aggregate", ErrInvalidSnapshot)
	}
	var total int64
	for i, table := range allowlist {
		if snapshot.Tables[i].Table != table || snapshot.Tables[i].Rows < 0 || snapshot.Tables[i].Rows > math.MaxInt64-total {
			return fmt.Errorf("%w: count for %s", ErrInvalidSnapshot, table)
		}
		total += snapshot.Tables[i].Rows
	}
	return nil
}

func compare(id, key string, expected, actual any, evidenceRef string) Check {
	check := Check{ID: id, Status: "passed", Expected: map[string]any{key: expected},
		Actual: map[string]any{key: actual}, EvidenceRef: &evidenceRef, FailureCategory: "none"}
	if expected != actual {
		classification := "integrity"
		check.Status = "failed"
		check.CheckClassification = &classification
		check.FailureCategory = "validation_failed"
	}
	return check
}
