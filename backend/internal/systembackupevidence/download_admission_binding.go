package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"sync"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// DownloadAdmissionContentFacts are supplied by the outer, prelocked admission
// owner. AuthorityUntil is the original minimum config/material/capacity limit;
// this helper cannot establish those authorities. Record must be the exact
// admitted claim/row-version snapshot, not a separately authorized provider read.
type DownloadAdmissionContentFacts struct {
	Actor          systembackupsecurity.RegistrationActor
	Record         Record
	Intent         DownloadAdmissionIntent
	Proof          systembackupsecurity.SensitiveDownloadProofVerification
	AuthorityUntil time.Time
}

func (DownloadAdmissionContentFacts) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// DownloadAdmissionContentBinding seals representation to one transaction and
// original audit anchor. It is NOT a prelocked context, a committed receipt, a
// nonce reservation or provider authority. Only the outer owner may commit.
type DownloadAdmissionContentBinding struct {
	mu           sync.Mutex
	tx           *sql.Tx
	audit        DownloadIntentAuditAnchor
	actor        systembackupsecurity.RegistrationActor
	proof        systembackupsecurity.SensitiveDownloadProofVerification
	receipt      DownloadAdmissionReceiptFacts
	operation    DownloadAdmissionOperationFacts
	privateJSON  string
	publicJSON   string
	lastObserved time.Time
	failed       bool
}

func (*DownloadAdmissionContentBinding) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*DownloadAdmissionContentBinding) String() string               { return "DownloadAdmissionContentBinding" }
func (*DownloadAdmissionContentBinding) GoString() string             { return "DownloadAdmissionContentBinding" }

func downloadAdmissionActorAt(a systembackupsecurity.RegistrationActor, now time.Time) bool {
	return a.UserID > 0 && a.UserID <= 2147483647 && downloadAdmissionContentTime(a.SessionIssuedAt) &&
		downloadAdmissionContentTime(a.SessionExpiresAt) && !a.SessionIssuedAt.After(now) && now.Before(a.SessionExpiresAt)
}

func sameDownloadAdmissionActor(a, b systembackupsecurity.RegistrationActor) bool {
	return a.UserID == b.UserID && a.Subject == b.Subject && a.Session == b.Session &&
		a.SessionIssuedAt.Equal(b.SessionIssuedAt) && a.SessionExpiresAt.Equal(b.SessionExpiresAt)
}

func bindDownloadAdmissionRequest(a systembackupsecurity.RegistrationActor, r Record, v systembackupsecurity.SensitiveDownloadProofVerification) (systembackupsecurity.SensitiveDownloadRequest, error) {
	bad := func() (systembackupsecurity.SensitiveDownloadRequest, error) {
		return systembackupsecurity.SensitiveDownloadRequest{}, ErrIntegrity
	}
	m, err := snapshotReadManifest(r.Manifest)
	if err != nil || r.State != "ready" || r.Failure != "none" || !oneOf(m.Identity.Classification, "confidential", "sensitive") ||
		r.RowVersion < 1 || r.RowVersion > 9007199254740991 || !downloadAdmissionClaimID.MatchString(r.Claim) || !downloadAdmissionContentTime(r.ClaimUntil) {
		return bad()
	}
	original := v.Request()
	start, end, present := original.Range()
	bound, err := systembackupsecurity.NewSensitiveDownloadRequest(systembackupsecurity.SensitiveDownloadRequestFacts{
		Installation: m.Identity.Installation, EvidenceID: m.Identity.ID, Actor: a, ManifestSHA256: hash(canonical(m)),
		ContentSize: m.Identity.ContentSize, RangeStart: start, RangeEnd: end, RangePresent: present, IdempotencyKey: original.IdempotencyKey(),
	})
	if err != nil || !bytes.Equal(bound.CanonicalJSON(), original.CanonicalJSON()) || bound.RequestHash() != original.RequestHash() {
		return bad()
	}
	return bound, nil
}

// BindDownloadAdmissionContent rechecks the actual original intent row, derives
// subject/session/claim digests itself, and freezes independent private/public
// bytes. No caller-supplied audit ID or saved JSON is accepted as authority.
// Every error requires the outer owner to abort its transaction.
func BindDownloadAdmissionContent(ctx context.Context, tx *sql.Tx, audit DownloadIntentAuditAnchor, f DownloadAdmissionContentFacts) (*DownloadAdmissionContentBinding, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || audit.tx != tx || audit.id < 1 || audit.observedAt.IsZero() ||
		!f.Intent.valid() || audit.actor != f.Actor.UserID || f.Intent.ActorID != f.Actor.UserID ||
		audit.body != string(downloadIntentBody(f.Intent, audit.observedAt)) || !downloadAdmissionContentTime(f.AuthorityUntil) {
		return nil, ErrAudit
	}
	bound, err := bindDownloadAdmissionRequest(f.Actor, f.Record, f.Proof)
	if err != nil {
		return nil, err
	}
	start, end, present := bound.Range()
	if f.Intent.Installation != f.Record.Manifest.Identity.Installation || f.Intent.EvidenceID != f.Record.Manifest.Identity.ID ||
		f.Intent.RequestHash != bound.RequestHash() || f.Intent.ManifestSHA256 != bound.ManifestSHA256() || f.Intent.Claim != f.Record.Claim ||
		f.Intent.EvidenceRowVersion != f.Record.RowVersion || f.Intent.Start != start || f.Intent.End != end || f.Intent.RangePresent != present {
		return nil, ErrIntegrity
	}
	now, err := downloadIntentNow(ctx, tx, audit.observedAt)
	if err != nil || verifyDownloadIntent(ctx, tx, audit) != nil {
		return nil, ErrAudit
	}
	// Row rechecks can block. This is a new SQL sample AFTER the audit read.
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !downloadAdmissionActorAt(f.Actor, now) || f.Proof.RecheckProofAt(now) != nil {
		return nil, ErrUnavailable
	}
	until := f.AuthorityUntil
	proofUntil, err := f.Proof.AdmissionDeadlineAt()
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, limit := range []time.Time{f.Record.ClaimUntil, f.Actor.SessionExpiresAt, proofUntil} {
		if limit.IsZero() || limit.Before(until) {
			until = limit
		}
	}
	if f.Record.Manifest.Identity.Type == "job_log_chunk" {
		if !downloadAdmissionContentTime(f.Record.ExpiresAt) {
			return nil, ErrUnavailable
		}
		if f.Record.ExpiresAt.Before(until) {
			until = f.Record.ExpiresAt
		}
	}
	// SQL DATETIME(6) cannot round an original sub-microsecond proof limit up.
	// Preserve the original proof internally and use its conservative floor for
	// the stored operation deadline; no original expiry is ever extended.
	until = until.UTC().Truncate(time.Microsecond)
	if !now.Before(until) {
		return nil, ErrUnavailable
	}
	r := DownloadAdmissionReceiptFacts{
		Installation: f.Intent.Installation, OperationID: f.Intent.OperationID, EvidenceID: f.Intent.EvidenceID,
		SubjectSHA256: hash([]byte(f.Actor.Subject)), SessionSHA256: hash([]byte(f.Actor.Session)),
		RequestHash: bound.RequestHash(), ClaimSHA256: hash([]byte(f.Record.Claim)), ManifestSHA256: bound.ManifestSHA256(),
		EvidenceRowVersion: f.Record.RowVersion, IntentAuditID: audit.id, Start: start, End: end, RangePresent: present,
		ClaimExpiresAt: f.Record.ClaimUntil, AdmittedAt: now,
	}
	o := DownloadAdmissionOperationFacts{Installation: r.Installation, OperationID: r.OperationID, EvidenceID: r.EvidenceID,
		IdempotencyKey: bound.IdempotencyKey(), RequestHash: r.RequestHash, ActorID: f.Actor.UserID, RowVersion: 1, AdmittedAt: now, DeadlineAt: until}
	privateJSON, e1 := CanonicalDownloadAdmissionReceipt(r)
	publicJSON, e2 := CanonicalDownloadAdmissionOperation(o)
	if e1 != nil || e2 != nil || VerifyDownloadAdmissionContent(privateJSON, publicJSON, hash(privateJSON), hash(publicJSON), int64(len(privateJSON)), int64(len(publicJSON)), r, o) != nil || ctx.Err() != nil {
		return nil, ErrIntegrity
	}
	return &DownloadAdmissionContentBinding{tx: tx, audit: audit, actor: f.Actor, proof: f.Proof, receipt: r, operation: o,
		privateJSON: string(privateJSON), publicJSON: string(publicJSON), lastObserved: now}, nil
}

func (b *DownloadAdmissionContentBinding) ReceiptJSON() []byte {
	if b == nil {
		return nil
	}
	return []byte(b.privateJSON)
}
func (b *DownloadAdmissionContentBinding) OperationJSON() []byte {
	if b == nil {
		return nil
	}
	return []byte(b.publicJSON)
}
func (b *DownloadAdmissionContentBinding) DeadlineAt() time.Time {
	if b == nil {
		return time.Time{}
	}
	return b.operation.DeadlineAt
}

// Recheck reads only the original audit row and SQL clock: it takes no earlier
// locks and cannot refresh a proof, claim or deadline. Current actor/record must
// come from the outer transaction's independently rechecked original rows.
// A failed binding cannot be recovered by restoring changed callback facts.
func (b *DownloadAdmissionContentBinding) Recheck(ctx context.Context, tx *sql.Tx, actor systembackupsecurity.RegistrationActor, current Record) error {
	if b == nil {
		return ErrAudit
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed {
		return ErrAudit
	}
	b.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || b.tx != tx || b.audit.id != b.receipt.IntentAuditID ||
		b.audit.actor != b.operation.ActorID || !sameDownloadAdmissionActor(actor, b.actor) {
		return ErrAudit
	}
	bound, err := bindDownloadAdmissionRequest(actor, current, b.proof)
	if err != nil || current.Manifest.Identity.Installation != b.receipt.Installation || current.Manifest.Identity.ID != b.receipt.EvidenceID ||
		current.RowVersion != b.receipt.EvidenceRowVersion || hash([]byte(current.Claim)) != b.receipt.ClaimSHA256 ||
		!current.ClaimUntil.Equal(b.receipt.ClaimExpiresAt) || bound.RequestHash() != b.receipt.RequestHash {
		return ErrIntegrity
	}
	now, err := downloadIntentNow(ctx, tx, b.lastObserved)
	if err != nil || verifyDownloadIntent(ctx, tx, b.audit) != nil {
		return ErrAudit
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !now.Before(b.operation.DeadlineAt) || !downloadAdmissionActorAt(actor, now) || b.proof.RecheckProofAt(now) != nil ||
		current.Manifest.Identity.Type == "job_log_chunk" && (!downloadAdmissionContentTime(current.ExpiresAt) || !now.Before(current.ExpiresAt)) {
		return ErrUnavailable
	}
	b.lastObserved, b.failed = now, false
	return nil
}
