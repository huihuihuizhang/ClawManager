package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Internal final decision, not the public local acceptance/signature payload.
// Its complete JCS bytes are the evidence body and eligibility decision hash.
type publicationDecisionPreimage struct {
	Version          string   `json:"schema_version"`
	Installation     string   `json:"origin_installation_id"`
	Backup           string   `json:"backup_public_id"`
	Attempt          uint64   `json:"attempt_no"`
	ConfigVersion    uint64   `json:"config_version"`
	ConfigSHA256     string   `json:"config_checksum"`
	OriginalSHA256   string   `json:"original_artifact_checksum"`
	ManifestSHA256   string   `json:"manifest_checksum"`
	MarkerSHA256     string   `json:"marker_checksum"`
	IndexSHA256      string   `json:"artifact_index_checksum"`
	CaptureSHA256    string   `json:"capture_certificate_hash"`
	AcceptanceSHA256 string   `json:"acceptance_checksum"`
	RegistrationID   string   `json:"registration_id"`
	RegistrationSHA  string   `json:"registration_checksum"`
	CleanupID        string   `json:"staging_cleanup_evidence_id"`
	CleanupSHA256    string   `json:"staging_cleanup_evidence_hash"`
	Eligible         bool     `json:"eligible"`
	Reasons          []string `json:"reason_codes"`
	ReasonsSHA256    string   `json:"reason_codes_hash"`
	DecisionAt       string   `json:"decision_at"`
}

func publicationDecisionID(installation, backup string, attempt uint64) string {
	raw, _ := ce.Canonical([]any{"original-publication-eligibility-decision.v1", installation, backup, attempt})
	return "sev_pub_decision_" + hash(raw)
}

func decodePublicationDecision(raw []byte) (publicationDecisionPreimage, time.Time, error) {
	var p publicationDecisionPreimage
	if len(raw) < 2 || len(raw) > 8192 || decodePublicationCanonical(raw, &p) != nil || p.Version != "system-backup-publication-eligibility-decision.v1" || !manifestBound(p.Installation, 128) || !regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`).MatchString(p.Backup) || !manifestBound(p.Backup, 128) || p.Attempt < 1 || p.Attempt > 9007199254740991 || p.ConfigVersion < 1 || p.ConfigVersion > 9007199254740991 || !regexp.MustCompile(`^scr_[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(p.RegistrationID) || !regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`).MatchString(p.CleanupID) || !manifestBound(p.CleanupID, 128) || !publicationDecisionReasonsValid(p.Eligible, p.Reasons) {
		return publicationDecisionPreimage{}, time.Time{}, c.ErrExecutionRecord
	}
	for _, sha := range []string{p.ConfigSHA256, p.OriginalSHA256, p.ManifestSHA256, p.MarkerSHA256, p.IndexSHA256, p.CaptureSHA256, p.AcceptanceSHA256, p.RegistrationSHA, p.CleanupSHA256, p.ReasonsSHA256} {
		if !formalCandidateDigest(sha) {
			return publicationDecisionPreimage{}, time.Time{}, c.ErrExecutionRecord
		}
	}
	reasons, _ := ce.Canonical(p.Reasons)
	at, err := time.Parse(time.RFC3339Nano, p.DecisionAt)
	if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != p.DecisionAt || !at.Equal(at.Truncate(time.Microsecond)) || hash(reasons) != p.ReasonsSHA256 {
		return publicationDecisionPreimage{}, time.Time{}, c.ErrExecutionRecord
	}
	return p, at, nil
}

func publicationDecisionReasonsValid(eligible bool, reasons []string) bool {
	if len(reasons) < 1 || len(reasons) > 7 {
		return false
	}
	if eligible {
		return len(reasons) == 1 && reasons[0] == "eligible"
	}
	last := ""
	for _, reason := range reasons {
		if reason <= last || !manifestOneOf(reason, "functional_test", "consistency_not_strong", "disqualifying_warning", "target_not_external", "target_risk", "attestation_invalid", "kek_not_recoverable") {
			return false
		}
		last = reason
	}
	return true
}

func decisionRegisteredProof(p *publicationRegisteredObject) *publicationFinalVerification {
	if p == nil || p.signed == nil || !p.signed.prepared.ready() || p.object.receipt == nil {
		return nil
	}
	return p.signed.prepared.proof
}

func publicationDecisionClockValid(at, localAt, catalogAt, now time.Time) bool {
	return !at.IsZero() && !localAt.IsZero() && !catalogAt.IsZero() && !now.IsZero() && at.Equal(at.Truncate(time.Microsecond)) && !at.Before(localAt) && !at.Before(catalogAt) && !at.After(now)
}

func decisionOriginalPreimage(registered *publicationRegisteredObject, now time.Time) (publicationDecisionPreimage, error) {
	proof := decisionRegisteredProof(registered)
	if proof == nil || now.IsZero() || !now.Equal(now.Truncate(time.Microsecond)) {
		return publicationDecisionPreimage{}, c.ErrExecutionAuthority
	}
	accepted := registered.signed.prepared.accepted
	local, err := decodePublicationAcceptancePayload(accepted.signed.prepared.intent.Payload)
	if err != nil {
		return publicationDecisionPreimage{}, err
	}
	catalog, err := decodePublicationCatalogPayload(registered.signed.prepared.intent.Payload)
	if err != nil {
		return publicationDecisionPreimage{}, err
	}
	localAt, _ := time.Parse(time.RFC3339Nano, local.DecisionAt)
	catalogAt, _ := time.Parse(time.RFC3339Nano, catalog.At)
	eligible, reasons, err := publicationOriginalEvaluation(proof)
	if err != nil || local.Accepted != eligible || !reflect.DeepEqual(local.Reasons, reasons) || !publicationDecisionClockValid(now, localAt, catalogAt, now) || catalog.AcceptanceSHA256 != accepted.object.SHA256 || registered.object.SHA256 != registered.signed.sha256 {
		return publicationDecisionPreimage{}, c.ErrExecutionRecord
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	return publicationDecisionPreimage{Version: "system-backup-publication-eligibility-decision.v1", Installation: proof.target.InstallationID, Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, OriginalSHA256: proof.originalSHA256, ManifestSHA256: proof.manifestObject.SHA256, MarkerSHA256: proof.markerObject.SHA256, IndexSHA256: catalog.IndexSHA256, CaptureSHA256: catalog.CaptureSHA256, AcceptanceSHA256: accepted.object.SHA256, RegistrationID: catalog.ID, RegistrationSHA: registered.object.SHA256, CleanupID: proof.cleanup.evidence.PublicID, CleanupSHA256: proof.cleanup.evidence.SHA256, Eligible: local.Accepted, Reasons: append([]string(nil), local.Reasons...), ReasonsSHA256: local.ReasonsSHA256, DecisionAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

func validateDecisionOriginal(raw []byte, registered *publicationRegisteredObject, now time.Time) error {
	p, at, err := decodePublicationDecision(raw)
	if err != nil {
		return err
	}
	want, err := decisionOriginalPreimage(registered, at)
	if err != nil || !reflect.DeepEqual(p, want) || now.IsZero() || at.After(now) {
		return c.ErrExecutionRecord
	}
	return nil
}

// Complete current SQL facts only. Every receipt keeps its own actual current
// token; this neither adopts a newer claim nor reopens historical cleanup.
func decisionCurrentTx(ctx context.Context, tx *sql.Tx, registered *publicationRegisteredObject) (time.Time, error) {
	proof := decisionRegisteredProof(registered)
	if proof == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return time.Time{}, c.ErrExecutionAuthority
	}
	if err := registered.recheckTx(ctx, tx); err != nil {
		return time.Time{}, err
	}
	_, now, err := registered.signed.prepared.currentFactsTx(ctx, tx)
	if err != nil {
		return time.Time{}, err
	}
	accepted := registered.signed.prepared.accepted
	marker := proof.cleanup.native.candidate.exit.marker
	expected := map[string]string{marker.receipt.postManifestMarker.manifest.receipt.action.ID: "manifest_put", marker.receipt.action.ID: "marker_put", accepted.object.receipt.action.ID: "acceptance_put", registered.object.receipt.action.ID: "catalog_registration_append"}
	if len(expected) != 4 {
		return time.Time{}, c.ErrExecutionRecord
	}
	rows, err := tx.QueryContext(ctx, `SELECT public_id,action_type,state FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? ORDER BY public_id LIMIT 5 FOR SHARE`, proof.target.InstallationID, proof.claim.Target.PublicID)
	if err != nil {
		return time.Time{}, err
	}
	seen := map[string]bool{}
	for rows.Next() {
		var id, kind, state string
		if rows.Scan(&id, &kind, &state) != nil || expected[id] != kind || state != "confirmed_present" || seen[id] {
			_ = rows.Close()
			return time.Time{}, c.ErrExecutionRecord
		}
		seen[id] = true
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || len(seen) != 4 {
		return time.Time{}, c.ErrExecutionRecord
	}
	if err = proof.recheckVerifiedTx(ctx, tx); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

func decisionRetentionTx(ctx context.Context, tx *sql.Tx, registered *publicationRegisteredObject, at time.Time) (int64, time.Time, error) {
	proof := decisionRegisteredProof(registered)
	if proof == nil || tx == nil {
		return 0, time.Time{}, c.ErrExecutionAuthority
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	var capacity, seconds int64
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, proof.target.InstallationID, capture.Input.ConfigVersion, capture.Input.ConfigSHA256).Scan(&capacity, &seconds) != nil || seconds < 60 || seconds > 10*365*86400 || !at.Add(time.Duration(seconds)*time.Second).After(capture.Input.Deadline) {
		return 0, time.Time{}, c.ErrExecutionAuthority
	}
	return capacity, at.Add(time.Duration(seconds) * time.Second), nil
}

type publicationDecisionRow struct {
	raw     []byte
	sha     string
	expires time.Time
	version uint64
}

// Inspect ALL root/descendant ownership, including expired/unhealthy rows,
// BEFORE the filtered metadata loader. An orphan never becomes virgin state.
func readDecisionRowTx(ctx context.Context, tx *sql.Tx, registered *publicationRegisteredObject) (publicationDecisionRow, error) {
	proof := decisionRegisteredProof(registered)
	if proof == nil || tx == nil {
		return publicationDecisionRow{}, c.ErrExecutionAuthority
	}
	id := publicationDecisionID(proof.target.InstallationID, proof.claim.Target.PublicID, proof.attempt)
	rows, err := tx.QueryContext(ctx, `SELECT public_id,owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE LEFT(public_id,?)=? ORDER BY public_id LIMIT 3 FOR SHARE`, len(id), id)
	if err != nil {
		return publicationDecisionRow{}, err
	}
	count := 0
	for rows.Next() {
		var actual, kind, owner string
		if rows.Scan(&actual, &kind, &owner) != nil || actual != id || kind != "backup" || owner != proof.claim.Target.PublicID || count != 0 {
			_ = rows.Close()
			return publicationDecisionRow{}, c.ErrExecutionCommitUnknown
		}
		count++
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return publicationDecisionRow{}, c.ErrExecutionRecord
	}
	if count == 0 {
		return publicationDecisionRow{}, sql.ErrNoRows
	}
	raw, err := loadPublicationMetadata(ctx, tx, proof.claim.Target.PublicID, id)
	if err != nil {
		return publicationDecisionRow{}, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	var row publicationDecisionRow
	var installation sql.NullString
	if tx.QueryRowContext(ctx, `SELECT origin_installation_id,expires_at,row_version FROM system_backup_v2_evidence WHERE public_id=? FOR SHARE`, id).Scan(&installation, &row.expires, &row.version) != nil || !installation.Valid || installation.String != proof.target.InstallationID || row.version != 1 {
		return publicationDecisionRow{}, c.ErrExecutionRecord
	}
	var unexpected uint64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM system_backup_v2_evidence_chunks WHERE evidence_id=(SELECT id FROM system_backup_v2_evidence WHERE public_id=?) LIMIT 1 FOR SHARE`, id).Scan(&unexpected); !errors.Is(err, sql.ErrNoRows) {
		return publicationDecisionRow{}, c.ErrExecutionRecord
	}
	row.raw, row.sha = bytes.Clone(raw), hash(raw)
	return row, nil
}

func validateDecisionRowTx(ctx context.Context, tx *sql.Tx, registered *publicationRegisteredObject, row publicationDecisionRow, expected []byte) error {
	now, err := decisionCurrentTx(ctx, tx, registered)
	if err != nil {
		return err
	}
	if !formalCandidateDigest(row.sha) || hash(row.raw) != row.sha || row.version != 1 || len(expected) != 0 && !bytes.Equal(row.raw, expected) {
		return c.ErrExecutionRecord
	}
	if err = validateDecisionOriginal(row.raw, registered, now); err != nil {
		return err
	}
	_, at, _ := decodePublicationDecision(row.raw)
	_, expires, err := decisionRetentionTx(ctx, tx, registered, at)
	if err != nil || !row.expires.Equal(expires) || !now.Before(row.expires) {
		return c.ErrExecutionRecord
	}
	return nil
}

// No caller-supplied eligible flag is accepted. A real committed record and
// current complete receipts are required; this is still NOT TerminalReady.
type publicationDecisionEvidence struct {
	registered *publicationRegisteredObject
	ref        ce.EvidenceRef
	row        publicationDecisionRow
}

func (p *publicationDecisionEvidence) recheckTx(ctx context.Context, tx *sql.Tx) error {
	proof := (*publicationFinalVerification)(nil)
	if p != nil {
		proof = decisionRegisteredProof(p.registered)
	}
	if proof == nil || tx == nil || ctx == nil || ctx.Err() != nil || p.ref.PublicID != publicationDecisionID(proof.target.InstallationID, proof.claim.Target.PublicID, proof.attempt) || p.ref.SHA256 != p.row.sha {
		return c.ErrExecutionAuthority
	}
	if err := validateDecisionRowTx(ctx, tx, p.registered, p.row, p.row.raw); err != nil {
		return err
	}
	row, err := readDecisionRowTx(ctx, tx, p.registered)
	if err != nil || row.sha != p.row.sha || !row.expires.Equal(p.row.expires) || row.version != p.row.version || !bytes.Equal(row.raw, p.row.raw) {
		return c.ErrExecutionRecord
	}
	_, err = decisionCurrentTx(ctx, tx, p.registered)
	return err
}

// One original invocation's retained preimage. Persist is attempted at most
// once, even on pre-commit errors. Thereafter it delegates ONLY to Query.
// Keep this handle on uncertainty; do not call the fresh constructor to retry.
// No process-global ledger is invented. Cross-process proof/preimage recovery
// remains unavailable; SQL absence cannot prove a prior attempt never existed.
type preparedPublicationDecision struct {
	mu         sync.Mutex
	registered *publicationRegisteredObject
	raw        []byte
	attempted  bool
}

// Normal first-invocation constructor, not an ensure/recovery entry point.
// The caller retains this handle after ANY Persist outcome. If that original
// invocation state is lost, use queryOriginalPublicationDecision only; absence
// does not authorize constructing another fresh initializer or clock.
func (s *DeploymentService) prepareOriginalPublicationDecision(ctx context.Context, registered *publicationRegisteredObject) (*preparedPublicationDecision, error) {
	proof := decisionRegisteredProof(registered)
	if s == nil || proof == nil || proof.service != s || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	return &preparedPublicationDecision{registered: registered}, nil
}

func (p *preparedPublicationDecision) Persist(ctx context.Context) (*publicationDecisionEvidence, error) {
	if p == nil || decisionRegisteredProof(p.registered) == nil || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	proof := decisionRegisteredProof(p.registered)
	if p.attempted {
		return proof.service.queryPublicationDecision(ctx, p.registered, p.raw)
	}
	p.attempted = true
	if proof.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := proof.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status='publishing' AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR UPDATE`, proof.target.InstallationID, proof.claim.Target.PublicID, proof.claim.Owner, proof.claim.RowVersion).Scan(&version) != nil || version != proof.claim.RowVersion {
		return nil, c.ErrClaimLost
	}
	if _, err = decisionCurrentTx(ctx, tx, p.registered); err != nil {
		return nil, err
	}
	row, err := readDecisionRowTx(ctx, tx, p.registered)
	if err == nil {
		if err = validateDecisionRowTx(ctx, tx, p.registered, row, nil); err != nil {
			return nil, err
		}
		p.raw = bytes.Clone(row.raw)
		if err = tx.Rollback(); err != nil {
			return nil, err
		}
		return proof.service.queryPublicationDecision(ctx, p.registered, p.raw)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	// This SQL clock is captured only on the normal FIRST absent-root path,
	// after all immutable/health/orphan checks, in the original write tx.
	var at time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6) /* original publication decision clock */`).Scan(&at) != nil {
		return nil, c.ErrExecutionRecord
	}
	value, err := decisionOriginalPreimage(p.registered, at)
	if err != nil {
		return nil, err
	}
	p.raw, err = ce.Canonical(value)
	if err != nil {
		return nil, err
	}
	if err = validateDecisionOriginal(p.raw, p.registered, at); err != nil {
		return nil, err
	}
	capacity, expires, err := decisionRetentionTx(ctx, tx, p.registered, at)
	if err != nil {
		return nil, err
	}
	if err = (security.RegistrationCapacity{ReportFile: proof.service.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(p.raw)); err != nil {
		return nil, err
	}
	id := publicationDecisionID(proof.target.InstallationID, proof.claim.Target.PublicID, proof.attempt)
	if err = registerPublicationMetadata(ctx, tx, proof.target.InstallationID, proof.claim.Target.PublicID, id, p.raw, expires); err != nil {
		return nil, err
	}
	row, err = readDecisionRowTx(ctx, tx, p.registered)
	if err != nil {
		return nil, err
	}
	if err = validateDecisionRowTx(ctx, tx, p.registered, row, p.raw); err != nil {
		return nil, err
	}
	if _, err = decisionCurrentTx(ctx, tx, p.registered); err != nil {
		return nil, err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return nil, c.ErrExecutionCommitUnknown
	}
	result, err := proof.service.queryPublicationDecision(ctx, p.registered, p.raw)
	if err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	return result, nil
}

func (p *preparedPublicationDecision) Query(ctx context.Context) (*publicationDecisionEvidence, error) {
	if p == nil || decisionRegisteredProof(p.registered) == nil {
		return nil, c.ErrExecutionAuthority
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempted = true // A query-only invocation never becomes a fresh initializer.
	return decisionRegisteredProof(p.registered).service.queryPublicationDecision(ctx, p.registered, p.raw)
}

func (s *DeploymentService) queryOriginalPublicationDecision(ctx context.Context, registered *publicationRegisteredObject) (*publicationDecisionEvidence, error) {
	return s.queryPublicationDecision(ctx, registered, nil)
}

// Independent query has no clock capture, capacity reservation or INSERT path.
func (s *DeploymentService) queryPublicationDecision(ctx context.Context, registered *publicationRegisteredObject, expected []byte) (*publicationDecisionEvidence, error) {
	proof := decisionRegisteredProof(registered)
	if s == nil || proof == nil || proof.service != s || ctx == nil || ctx.Err() != nil || proof.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = decisionCurrentTx(ctx, tx, registered); err != nil {
		return nil, err
	}
	row, err := readDecisionRowTx(ctx, tx, registered)
	if err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	if err = validateDecisionRowTx(ctx, tx, registered, row, expected); err != nil {
		return nil, err
	}
	result := &publicationDecisionEvidence{registered: registered, ref: ce.EvidenceRef{PublicID: publicationDecisionID(proof.target.InstallationID, proof.claim.Target.PublicID, proof.attempt), SHA256: row.sha}, row: row}
	if err = result.recheckTx(ctx, tx); err != nil {
		return nil, err
	}
	if err = tx.Rollback(); err != nil {
		return nil, err
	}
	return result, nil
}
