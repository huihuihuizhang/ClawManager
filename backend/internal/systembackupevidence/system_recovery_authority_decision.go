package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const recoveryAuthorityDecisionVersion = "system-backup-recovery-authority-decision.v1"

// RecoveryAuthorityExternalAudit must synchronously persist to independently
// reserved capacity. A result_prepared record is written before SQL COMMIT; it
// never claims that the database commit has already succeeded.
type RecoveryAuthorityExternalAudit interface {
	AppendRecoveryAuthorityAudit(context.Context, RecoveryAuthorityExternalAuditRecord) error
}

type RecoveryAuthorityExternalAuditRecord struct {
	Stage               string `json:"stage"`
	DecisionSHA256      string `json:"decision_sha256"`
	RequestHash         string `json:"request_hash"`
	ManagerIdentityHash string `json:"manager_identity_hash"`
}

type recoveryAuthorityDecisionDocument struct {
	SchemaVersion       string                         `json:"schema_version"`
	Scope               pd.Scope                       `json:"scope"`
	RequestHash         string                         `json:"request_hash"`
	ManagerIdentityHash string                         `json:"manager_identity_hash"`
	ManagerIssuerHash   string                         `json:"manager_issuer_hash"`
	Current             *pd.RecoveryDeploymentProposal `json:"current"`
	Next                pd.RecoveryDeploymentProposal  `json:"next"`
	NotBefore           time.Time                      `json:"not_before"`
	ExpiresAt           time.Time                      `json:"expires_at"`
}

// PinnedRecoveryAuthorityDecision is an offline, exact-request authorization.
// The path and SHA-256 are supplied by installation configuration, not by the
// management request. It does not mint or infer a manager mTLS identity.
type PinnedRecoveryAuthorityDecision struct {
	scope     pd.Scope
	path, pin string
	external  RecoveryAuthorityExternalAudit
	document  recoveryAuthorityDecisionDocument
}

func NewPinnedRecoveryAuthorityDecision(scope pd.Scope, path, pin string, external RecoveryAuthorityExternalAudit) (*PinnedRecoveryAuthorityDecision, error) {
	if nilSystemAdapter(external) || path == "" || !digestPattern.MatchString(pin) {
		return nil, ErrDenied
	}
	doc, err := readRecoveryAuthorityDecision(path, pin)
	if err != nil || doc.Scope != scope {
		return nil, ErrDenied
	}
	return &PinnedRecoveryAuthorityDecision{scope: scope, path: path, pin: pin, external: external, document: doc}, nil
}

func readRecoveryAuthorityDecision(path, pin string) (recoveryAuthorityDecisionDocument, error) {
	deny := func() (recoveryAuthorityDecisionDocument, error) {
		return recoveryAuthorityDecisionDocument{}, ErrDenied
	}
	if path == "" || !digestPattern.MatchString(pin) {
		return deny()
	}
	f, err := os.Open(path)
	if err != nil {
		return deny()
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() < 1 || stat.Size() > 16384 {
		return deny()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return deny()
	}
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return deny()
	}
	actual := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(actual[:], want) != 1 {
		return deny()
	}
	var d recoveryAuthorityDecisionDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || !validRecoveryAuthorityDecision(d) {
		return deny()
	}
	return d, nil
}

func validRecoveryAuthorityDecision(d recoveryAuthorityDecisionDocument) bool {
	if d.SchemaVersion != recoveryAuthorityDecisionVersion || !digestPattern.MatchString(d.RequestHash) ||
		!digestPattern.MatchString(d.ManagerIdentityHash) || !digestPattern.MatchString(d.ManagerIssuerHash) ||
		!systemPeerTime(d.NotBefore) || !systemPeerTime(d.ExpiresAt) || !d.NotBefore.Before(d.ExpiresAt) ||
		d.Next.ManagementIssuerHash != pd.Hash(d.ManagerIssuerHash) {
		return false
	}
	if _, err := pd.RecoveryScopeKey(d.Scope); err != nil {
		return false
	}
	return validRecoveryDeploymentProposal(d.Next) && (d.Current == nil || validRecoveryDeploymentProposal(*d.Current))
}

func validRecoveryDeploymentProposal(p pd.RecoveryDeploymentProposal) bool {
	for _, h := range []pd.Hash{p.WorkloadIdentityHash, p.IssuerIdentityHash, p.SubjectHash, p.ManagementIssuerHash,
		p.ActorIdentityHash, p.AdmissionHash, p.ClientCASHA256, p.CertificateSHA256, p.StatProfileHash} {
		if !digestPattern.MatchString(string(h)) {
			return false
		}
	}
	_, epochErr := p.Epoch.SQLInt64()
	_, versionErr := p.RowVersion.SQLInt64()
	until, untilErr := p.AuthorizedUntil.Time()
	return epochErr == nil && versionErr == nil && untilErr == nil && systemPeerTime(until)
}

func (d *PinnedRecoveryAuthorityDecision) check(ctx context.Context, r pd.RecoveryAuthorityRequest, facts RecoveryManagerPeerFacts, now time.Time) error {
	if d == nil || ctx == nil || ctx.Err() != nil || nilSystemAdapter(d.external) || !systemPeerTime(now) ||
		now.Before(d.document.NotBefore) || !now.Before(d.document.ExpiresAt) || facts.Scope != d.scope ||
		facts.IdentityHash != d.document.ManagerIdentityHash || facts.IssuerIdentityHash != d.document.ManagerIssuerHash ||
		!now.Before(facts.ExpiresAt) {
		return ErrDenied
	}
	h, err := pd.RecoveryAuthorityHash(r)
	if err != nil || string(h) != d.document.RequestHash {
		return ErrDenied
	}
	current, err := readRecoveryAuthorityDecision(d.path, d.pin)
	if err != nil || !sameRecoveryAuthorityDecisionDocument(current, d.document) {
		return ErrDenied
	}
	return nil
}

func sameRecoveryAuthorityDecisionDocument(a, b recoveryAuthorityDecisionDocument) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Scope != b.Scope || a.RequestHash != b.RequestHash ||
		a.ManagerIdentityHash != b.ManagerIdentityHash || a.ManagerIssuerHash != b.ManagerIssuerHash ||
		a.Next != b.Next || !a.NotBefore.Equal(b.NotBefore) || !a.ExpiresAt.Equal(b.ExpiresAt) ||
		(a.Current == nil) != (b.Current == nil) {
		return false
	}
	return a.Current == nil || *a.Current == *b.Current
}

func (d *PinnedRecoveryAuthorityDecision) NextDeployment(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, current *pd.RecoveryDeploymentProposal, facts RecoveryManagerPeerFacts) (pd.RecoveryDeploymentProposal, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || d == nil {
		return pd.RecoveryDeploymentProposal{}, ErrDenied
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryDeploymentProposal{}, ErrUnavailable
	}
	if err := d.check(ctx, r, facts, now); err != nil || current == nil && d.document.Current != nil || current != nil && d.document.Current == nil {
		return pd.RecoveryDeploymentProposal{}, ErrDenied
	}
	if current != nil && *current != *d.document.Current {
		return pd.RecoveryDeploymentProposal{}, ErrDenied
	}
	return d.document.Next, nil
}

func (d *PinnedRecoveryAuthorityDecision) Audit(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, stage string) error {
	if d == nil || tx == nil || ctx == nil || ctx.Err() != nil || stage != "intent" && stage != "result" {
		return ErrDenied
	}
	h, err := pd.RecoveryAuthorityHash(r)
	if err != nil || string(h) != d.document.RequestHash {
		return ErrDenied
	}
	if _, err := readRecoveryAuthorityDecision(d.path, d.pin); err != nil {
		return ErrDenied
	}
	externalStage := stage
	if stage == "result" {
		externalStage = "result_prepared"
	}
	if err := d.external.AppendRecoveryAuthorityAudit(ctx, RecoveryAuthorityExternalAuditRecord{
		Stage: externalStage, DecisionSHA256: d.pin, RequestHash: string(h), ManagerIdentityHash: d.document.ManagerIdentityHash,
	}); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(action,resource_type,details)
VALUES (?,'system_backup',JSON_OBJECT('request_hash',?,'decision_sha256',?,'manager_identity_hash',?))`,
		"system_backup.recovery_authority."+stage, string(h), d.pin, d.document.ManagerIdentityHash); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (d *PinnedRecoveryAuthorityDecision) RecheckDecision(ctx context.Context, r pd.RecoveryAuthorityRequest, facts RecoveryManagerPeerFacts, now time.Time) error {
	return d.check(ctx, r, facts, now)
}

var _ SystemRecoveryAuthorityDecision = (*PinnedRecoveryAuthorityDecision)(nil)
