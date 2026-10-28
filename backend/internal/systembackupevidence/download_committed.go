package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type committedDownloadAccessKey struct{}
type committedDownloadState struct {
	mu              sync.Mutex
	bound, failed   bool
	resultAttempted bool
	authority       *SQLDownloadAuthority
}
type committedDownloadRows struct {
	receipt                                             DownloadAdmissionReceiptFacts
	operation                                           DownloadAdmissionOperationFacts
	audit                                               DownloadIntentAuditAnchor
	operationID, evidenceID, nonceID                    int64
	retainUntil, acceptedAt, nonceExpiresAt, consumedAt time.Time
	issuerSHA256                                        string
	active                                              sec.NonceHMACCandidate
	candidates                                          []sec.NonceHMACCandidate
}

// Copy only original database facts and safe hashes, no raw proof/nonce/bearer
// or reusable pending transaction. Called only after a known timely commit.
func sealCommittedDownloadRows(r *DownloadAdmissionRecords, n *DownloadAdmissionNonce) committedDownloadRows {
	b := r.binding
	audit := b.audit
	audit.tx = nil
	return committedDownloadRows{receipt: b.receipt, operation: b.operation, audit: audit,
		operationID: r.operationID, evidenceID: r.evidenceID, nonceID: n.id, retainUntil: r.retainUntil,
		acceptedAt: b.proof.ProofAcceptedAt(), nonceExpiresAt: n.expiresAt, consumedAt: n.consumedAt,
		issuerSHA256: b.proof.IssuerSHA256(), active: b.proof.ActiveNonce(), candidates: b.proof.NonceCandidates()}
}

func (c *CommittedDownloadAdmission) fail() {
	if c == nil || c.state == nil {
		return
	}
	c.state.mu.Lock()
	c.state.failed = true
	c.state.mu.Unlock()
}
func committedDownloadFrom(ctx context.Context) *CommittedDownloadAdmission {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(committedDownloadAccessKey{}).(*CommittedDownloadAdmission)
	return c
}
func (c *CommittedDownloadAdmission) matchesAuthority(a *SQLDownloadAuthority) bool {
	if c == nil || c.service == nil || a == nil {
		return false
	}
	s, target := c.service.registry, a.c.Registry
	return s.DB == target.DB && s.Installation == target.Installation && s.ServerUUID == target.ServerUUID && s.Database == target.Database &&
		bytes.Equal(c.service.secret, a.c.JWTSecret) && c.configVersion == a.c.ConfigVersion && c.configSHA256 == a.c.ConfigSHA256
}
func (c *CommittedDownloadAdmission) live(ctx context.Context, a *SQLDownloadAuthority) bool {
	if c == nil || c.state == nil || ctx == nil || ctx.Err() != nil || committedDownloadFrom(ctx) != c || !c.matchesAuthority(a) || !time.Now().Before(c.localDeadline) {
		return false
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return c.state.bound && !c.state.failed && c.state.authority == a
}

// BindCommittedDownload attaches the already committed request to this exact
// current SQL/provider authority, once even through Go value copies. Binding
// itself grants no provider access: every SQL/S3/Transit authorization must
// re-read the original group and current identity/owner/claim. It never consumes
// another nonce, refreshes the original deadline or re-parses mutable headers.
func (a *SQLDownloadAuthority) BindCommittedDownload(ctx context.Context, c *CommittedDownloadAdmission) (context.Context, context.CancelFunc, error) {
	if c == nil || c.state == nil {
		return nil, nil, ErrDenied
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if c.state.bound || c.state.failed {
		c.state.failed = true
		return nil, nil, ErrDenied
	}
	c.state.failed = true
	if ctx == nil || ctx.Err() != nil || !c.matchesAuthority(a) || !time.Now().Before(c.localDeadline) ||
		c.rows.operationID < 1 || c.rows.evidenceID < 1 || c.rows.nonceID < 1 || c.rows.consumedAt.IsZero() || !c.request.MatchesActor(c.actor) ||
		c.rows.receipt.IntentAuditID != c.intentAuditID || c.rows.receipt.OperationID != c.operationID || !oneOf(c.record.Manifest.Identity.Classification, "confidential", "sensitive") {
		return nil, nil, ErrDenied
	}
	bound, cancel := context.WithDeadline(ctx, c.localDeadline)
	bound = withVerifiedDownloadActor(bound, a.c.Registry, c.actor)
	bound = context.WithValue(bound, a, c.actor)
	bound = context.WithValue(bound, committedDownloadAccessKey{}, c)
	bound = withEvidenceAccess(bound, "download", c.record)
	c.state.bound, c.state.failed, c.state.authority = true, false, a
	return bound, cancel, nil
}

// CheckCommittedDownload is also the explicit pre-header/plaintext guard.
// Legacy unbound contexts cannot turn a live claim into this capability.
func (a *SQLDownloadAuthority) CheckCommittedDownload(ctx context.Context, c *CommittedDownloadAdmission) error {
	if c == nil || !c.live(ctx, a) {
		c.fail()
		return ErrDenied
	}
	if err := a.AuthorizeDownload(ctx, downloadActor(c.actor), c.Record()); err != nil {
		c.fail()
		return err
	}
	if !c.live(ctx, a) {
		c.fail()
		return ErrDenied
	}
	return nil
}

func (c *CommittedDownloadAdmission) checkOperationReceipt(ctx context.Context, tx *sql.Tx) error {
	r := c.rows
	return readDownloadAdmissionOperationReceipt(ctx, tx, r.operationID, r.evidenceID, r.retainUntil, r.receipt, r.operation)
}

// Reuse the complete canonical/materialized L0/L1 reader, without consuming a
// nonce. The later legacy pin projection re-locks only these same held rows.
func (c *CommittedDownloadAdmission) checkConfig(ctx context.Context, tx *sql.Tx) (*sec.SensitiveDownloadConfig, error) {
	s := c.service.registry
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, sec.DatabaseIdentity{ServerUUID: s.ServerUUID, Database: s.Database}, s.Installation)
	if err != nil {
		return nil, ErrDenied
	}
	versions := scope.RequiredVersions()
	if len(versions) != len(c.rows.candidates) {
		return nil, ErrDenied
	}
	for _, version := range versions {
		found := false
		for _, candidate := range c.rows.candidates {
			found = found || candidate.KeyVersion == version
		}
		if !found {
			return nil, ErrDenied
		}
	}
	config, err := scope.LoadConfig(ctx, tx)
	if err != nil || config.Version() != c.configVersion || config.Values().SHA256() != c.configSHA256 {
		return nil, ErrDenied
	}
	return config, nil
}
func (c *CommittedDownloadAdmission) checkNonce(ctx context.Context, tx *sql.Tx) error {
	n, r := c.rows, c.rows.receipt
	for _, candidate := range n.candidates {
		var id int64
		err := tx.QueryRowContext(ctx, downloadAdmissionNonceCandidateReadSQL, candidate.HMAC, candidate.KeyVersion).Scan(&id)
		if candidate == n.active {
			if err != nil || id != n.nonceID {
				return ErrDenied
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
	}
	var consumed, created time.Time
	if tx.QueryRowContext(ctx, downloadAdmissionNonceReadSQL, n.nonceID, r.Installation, n.issuerSHA256, r.SubjectSHA256, r.SessionSHA256, n.active.HMAC, n.active.KeyVersion,
		r.RequestHash, n.operation.IdempotencyKey, n.acceptedAt, n.nonceExpiresAt, n.operationID, r.IntentAuditID, n.retainUntil).Scan(&consumed, &created) != nil || !consumed.Equal(n.consumedAt) || !created.Equal(n.consumedAt) {
		return ErrDenied
	}
	return nil
}
func (c *CommittedDownloadAdmission) checkIntent(ctx context.Context, tx *sql.Tx) error {
	anchor := c.rows.audit
	anchor.tx = tx // read-only verification of the original sealed committed facts
	return verifyDownloadIntent(ctx, tx, anchor)
}

// All deployment-owned callbacks precede this independent final read. Owner
// visibility/deadline was checked above under its held locks; the final manifest
// decoder uses the sealed deadline and invokes no owner code a second time.
func (c *CommittedDownloadAdmission) recheckOriginal(ctx context.Context, tx *sql.Tx, s SQLRegistry) error {
	if c.checkOperationReceipt(ctx, tx) != nil || c.checkNonce(ctx, tx) != nil || c.checkIntent(ctx, tx) != nil || c.checkOwner(ctx, tx) != nil {
		return ErrDenied
	}
	r, err := s.loadManifest(ctx, tx, c.record.Manifest.Identity.ID, true, func(context.Context, *sql.Tx, Identity) (time.Time, error) {
		return c.record.OwnerDeadline, nil
	})
	if err != nil || !c.sameCurrent(r) {
		return ErrDenied
	}
	return nil
}

func (c *CommittedDownloadAdmission) checkSession(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	until, err := sec.CheckRegistrationSessionUntil(ctx, tx, c.record.Manifest.Identity.Installation, c.actor)
	if err != nil || until.Before(c.actor.SessionExpiresAt) {
		return time.Time{}, ErrDenied
	}
	var revoked time.Time
	err = tx.QueryRowContext(ctx, "SELECT revoked_before FROM system_backup_v2_admin_revocations WHERE origin_installation_id=? AND user_id=? FOR UPDATE", c.record.Manifest.Identity.Installation, c.actor.UserID).Scan(&revoked)
	if err != nil && !errors.Is(err, sql.ErrNoRows) || err == nil && (revoked.IsZero() || !c.actor.SessionIssuedAt.After(revoked)) {
		return time.Time{}, ErrDenied
	}
	return until, nil
}

const downloadCommittedOwnerSQL = `SELECT origin_installation_id,owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE`

func (c *CommittedDownloadAdmission) checkOwner(ctx context.Context, tx *sql.Tx) error {
	var installation sql.NullString
	var ownerType, ownerID string
	i := c.record.Manifest.Identity
	if tx.QueryRowContext(ctx, downloadCommittedOwnerSQL, i.ID).Scan(&installation, &ownerType, &ownerID) != nil || !installation.Valid || installation.String != i.Installation || ownerType != i.OwnerType || ownerID != i.OwnerID {
		return ErrDenied
	}
	return nil
}
func (c *CommittedDownloadAdmission) sameCurrent(r Record) bool {
	return sameDownloadAdmissionImmutable(c.record, r) && c.record.RowVersion == r.RowVersion && c.record.Claim == r.Claim && c.record.ClaimUntil.Equal(r.ClaimUntil)
}
func (c *CommittedDownloadAdmission) allowsS3(scope S3Scope) bool {
	if scope.Operation == S3Stat {
		return true
	}
	if scope.Operation != S3Range {
		return false
	}
	m := c.record.Manifest
	if scope.Offset == 0 && scope.Length == m.HeaderSize {
		return true
	}
	start, end, _ := c.Range()
	for _, chunk := range m.Chunks {
		if chunk.PlainOffset <= end && chunk.PlainOffset+chunk.PlainLength > start && scope.Offset == chunk.FrameOffset && scope.Length == chunk.FrameLength {
			return true
		}
	}
	return false
}
