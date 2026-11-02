package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Acceptance's original business protocol, not a new task/signing framework.
// Phase IDs exclude clock/Pod/current claim; each immutable value is INSERTed
// under the real original task lock and never refreshed on an unknown result.
type publicationAcceptanceSigningIntent struct {
	Version, Installation, Backup, ArtifactSHA256, PayloadSHA256 string
	Attempt                                                      uint64
	Claim                                                        c.ClaimToken
	SignUntil                                                    time.Time
	Payload                                                      json.RawMessage
}
type publicationAcceptanceSigningSend struct {
	Version, PreparedSHA256, PayloadSHA256 string
	Claim                                  c.ClaimToken
	SignUntil                              time.Time
}
type publicationAcceptanceSigningResult struct {
	Version, PreparedSHA256, PayloadSHA256, SignatureSHA256 string
	Record                                                  json.RawMessage
}
type preparedPublicationAcceptance struct {
	proof        *publicationFinalVerification
	intent       publicationAcceptanceSigningIntent
	intentSHA256 string
	signers      *security.SQLPublicationTaskSigners
	record       *security.SQLPreparedPublicationRecord
}

func acceptanceSigningID(installation, backup string, attempt uint64) string {
	raw, _ := ce.Canonical([]any{"original-publication-signature.v1", installation, backup, attempt, "acceptance_record"})
	return "sev_pub_accept_" + hash(raw)
}
func (p *preparedPublicationAcceptance) id() string {
	return acceptanceSigningID(p.proof.target.InstallationID, p.proof.claim.Target.PublicID, p.proof.attempt)
}
func (p *preparedPublicationAcceptance) Close() {
	if p != nil && p.signers != nil {
		p.signers.Close()
		p.signers = nil
	}
}
func (p *preparedPublicationAcceptance) ready() bool {
	return p != nil && p.proof != nil && p.proof.service != nil && p.proof.service.publisherVerifierDB != nil && p.proof.access != nil && p.proof.cleanup.ready() && formalCandidateDigest(p.proof.verifiedSHA256)
}

func acceptanceJournalAbsentTx(ctx context.Context, tx *sql.Tx, backup, prefix string) error {
	var count uint64
	if tx == nil || tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND LEFT(public_id,?)=?`, backup, len(prefix), prefix).Scan(&count) != nil {
		return c.ErrExecutionRecord
	}
	if count != 0 {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (p *preparedPublicationAcceptance) recheckTx(ctx context.Context, tx *sql.Tx) (publicationRecoveryFacts, time.Time, error) {
	var zero publicationRecoveryFacts
	if !p.ready() || tx == nil {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	i := p.intent
	if i.Version != "system-backup-original-acceptance-signing.v1" || i.Installation != p.proof.target.InstallationID || i.Backup != p.proof.claim.Target.PublicID || i.Attempt != p.proof.attempt || i.Claim.Target != p.proof.claim.Target || i.Claim.Owner == "" || i.Claim.RowVersion < 1 || i.ArtifactSHA256 != p.proof.originalSHA256 || i.PayloadSHA256 != hash(i.Payload) || i.SignUntil.IsZero() {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	if p.intentSHA256 != "" {
		raw, err := loadPublicationMetadata(ctx, tx, i.Backup, p.id()+"_prepared")
		want, _ := ce.Canonical(i)
		if err != nil || hash(raw) != p.intentSHA256 || !bytes.Equal(raw, want) {
			return zero, time.Time{}, c.ErrExecutionRecord
		}
	}
	recovery, now, err := acceptanceRecoveryFactsTx(ctx, tx, p.proof)
	if err != nil {
		return zero, time.Time{}, err
	}
	if err = validateAcceptanceBusinessPayload(i.Payload, p.proof, recovery, now); err != nil {
		return zero, time.Time{}, err
	}
	return recovery, now, nil
}

func (p *preparedPublicationAcceptance) transaction(ctx context.Context, body func(*sql.Tx, publicationRecoveryFacts, time.Time) error) error {
	if !p.ready() || ctx == nil || ctx.Err() != nil || p.proof.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	s := p.proof.service
	claim := p.proof.claim
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status='publishing' AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) FOR UPDATE`, s.Config.InstallationID, claim.Target.PublicID, claim.Owner, claim.RowVersion).Scan(&version) != nil || version != claim.RowVersion {
		return c.ErrClaimLost
	}
	recovery, now, err := p.recheckTx(ctx, tx)
	if err != nil {
		return err
	}
	if err = body(tx, recovery, now); err != nil {
		return err
	}
	if _, _, err = p.recheckTx(ctx, tx); err != nil {
		return err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (p *preparedPublicationAcceptance) storeTx(ctx context.Context, tx *sql.Tx, id string, body []byte, now time.Time) error {
	if len(body) < 2 || len(body) > 8192 {
		return c.ErrExecutionRecord
	}
	var capacity, retention int64
	capture := p.proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, p.intent.Installation, capture.Input.ConfigVersion, capture.Input.ConfigSHA256).Scan(&capacity, &retention) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(capture.Input.Deadline) {
		return c.ErrExecutionAuthority
	}
	if err := (security.RegistrationCapacity{ReportFile: p.proof.service.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return err
	}
	return registerPublicationMetadata(ctx, tx, p.intent.Installation, p.intent.Backup, id, body, now.Add(time.Duration(retention)*time.Second))
}

func (p *preparedPublicationAcceptance) expectedSend() ([]byte, error) {
	if !p.ready() || !formalCandidateDigest(p.intentSHA256) {
		return nil, c.ErrExecutionAuthority
	}
	return ce.Canonical(publicationAcceptanceSigningSend{Version: "system-backup-original-acceptance-signing-sent.v1", PreparedSHA256: p.intentSHA256, PayloadSHA256: p.intent.PayloadSHA256, Claim: p.intent.Claim, SignUntil: p.intent.SignUntil})
}
func readAcceptanceSigningSendTx(ctx context.Context, tx *sql.Tx, p *preparedPublicationAcceptance) error {
	want, err := p.expectedSend()
	if err != nil {
		return err
	}
	got, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, p.id()+"_sent")
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return c.ErrExecutionRecord
	}
	return nil
}
func readAcceptanceSigningResultTx(ctx context.Context, tx *sql.Tx, p *preparedPublicationAcceptance) ([]byte, error) {
	if !p.ready() {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, p.id()+"_result")
	if errors.Is(err, sql.ErrNoRows) {
		if prior := acceptanceJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_result"); prior != nil {
			return nil, prior
		}
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	var result publicationAcceptanceSigningResult
	if decodePublicationCanonical(raw, &result) != nil || result.Version != "system-backup-original-acceptance-signing-result.v1" || result.PreparedSHA256 != p.intentSHA256 || result.PayloadSHA256 != p.intent.PayloadSHA256 || len(result.Record) < 2 || len(result.Record) > 8192 || hash(result.Record) != result.SignatureSHA256 {
		return nil, c.ErrExecutionRecord
	}
	if err = readAcceptanceSigningSendTx(ctx, tx, p); err != nil {
		return nil, c.ErrExecutionRecord
	}
	return bytes.Clone(result.Record), nil
}

func (s *DeploymentService) prepareOriginalPublicationAcceptance(ctx context.Context, proof *publicationFinalVerification) (_ *preparedPublicationAcceptance, resultErr error) {
	p := &preparedPublicationAcceptance{proof: proof}
	if !p.ready() || proof.service != s || ctx == nil || ctx.Err() != nil || proof.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	defer func() {
		if resultErr != nil {
			p.Close()
		}
	}()
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	recovery, now, err := acceptanceRecoveryFactsTx(ctx, tx, proof)
	if err != nil {
		return nil, err
	}
	raw, err := loadPublicationMetadata(ctx, tx, proof.claim.Target.PublicID, p.id()+"_prepared")
	if err == nil {
		if decodePublicationCanonical(raw, &p.intent) != nil {
			return nil, c.ErrExecutionRecord
		}
		p.intentSHA256 = hash(raw)
		if _, _, err = p.recheckTx(ctx, tx); err != nil {
			return nil, err
		}
		return p, nil // query/known-result recovery does not require another signer
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err = acceptanceJournalAbsentTx(ctx, tx, proof.claim.Target.PublicID, p.id()); err != nil {
		return nil, err
	}
	if err = tx.Rollback(); err != nil {
		return nil, err
	}
	p.signers, err = s.PublicationSignersForTask(ctx, proof.claim)
	if err != nil {
		return nil, err
	}
	key, err := p.signers.PublicationSigningKey(ctx, "acceptance_record")
	if err != nil {
		return nil, err
	}
	eligible, codes, err := publicationOriginalEvaluation(proof)
	if err != nil {
		return nil, err
	}
	reasons, err := ce.Canonical(codes)
	if err != nil {
		return nil, err
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	payload, err := ce.Canonical(publicationAcceptancePayload{Version: "system-backup-acceptance.v1", Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, ManifestSHA256: proof.manifestObject.SHA256, MarkerSHA256: proof.markerObject.SHA256, CleanupID: proof.cleanup.evidence.PublicID, CleanupSHA256: proof.cleanup.evidence.SHA256, Accepted: eligible, Reasons: codes, ReasonsSHA256: hash(reasons), DecisionAt: now.UTC().Format(time.RFC3339Nano), ConfigVersion: capture.Input.ConfigVersion, Key: key})
	if err != nil {
		return nil, err
	}
	if err = validateAcceptanceBusinessPayload(payload, proof, recovery, now); err != nil {
		return nil, err
	}
	p.intent = publicationAcceptanceSigningIntent{Version: "system-backup-original-acceptance-signing.v1", Installation: s.Config.InstallationID, Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, ArtifactSHA256: proof.originalSHA256, PayloadSHA256: hash(payload), Payload: payload, Claim: proof.claim, SignUntil: recovery.until.UTC().Truncate(time.Microsecond)}
	p.record, err = p.signers.PreparePublicationRecord(ctx, "acceptance_record", payload)
	if err != nil {
		return nil, err
	}
	err = p.transaction(ctx, func(tx *sql.Tx, current publicationRecoveryFacts, at time.Time) error {
		if !at.Before(p.intent.SignUntil) || p.intent.SignUntil.After(current.until) {
			return c.ErrExecutionAuthority
		}
		if err := acceptanceJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()); err != nil {
			return err
		}
		body, err := ce.Canonical(p.intent)
		if err != nil {
			return err
		}
		if err = p.storeTx(ctx, tx, p.id()+"_prepared", body, at); err != nil {
			return err
		}
		p.intentSHA256 = hash(body)
		// A owns the real first-input barrier across workloads and orphan
		// chunks for this original backup/attempt/purpose. Reusing a known C
		// prepared/result never takes this fresh-stage path.
		if err = p.record.StageFirst(ctx, tx); err != nil {
			if errors.Is(err, security.ErrPublicationFirstStage) {
				return errors.Join(c.ErrExecutionCommitUnknown, err)
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *preparedPublicationAcceptance) ensureSigner(ctx context.Context) error {
	if !p.ready() || p.intent.Claim != p.proof.claim {
		return c.ErrExecutionAuthority
	}
	if p.record != nil && p.signers != nil {
		return nil
	}
	q, err := p.proof.service.PublicationSignersForTask(ctx, p.proof.claim)
	if err != nil {
		return err
	}
	p.signers = q
	key, err := q.PublicationSigningKey(ctx, "acceptance_record")
	if err != nil {
		return err
	}
	payload, err := decodePublicationAcceptancePayload(p.intent.Payload)
	if err != nil || key != payload.Key {
		return c.ErrExecutionRecord
	}
	p.record, err = q.PreparePublicationRecord(ctx, "acceptance_record", p.intent.Payload)
	return err
}

func (p *preparedPublicationAcceptance) SignCommitted(ctx context.Context) (*publicationSignedAcceptance, error) {
	if !p.ready() || !formalCandidateDigest(p.intentSHA256) {
		return nil, c.ErrExecutionAuthority
	}
	var known []byte
	var sent bool
	err := p.transaction(ctx, func(tx *sql.Tx, _ publicationRecoveryFacts, _ time.Time) error {
		var err error
		known, err = readAcceptanceSigningResultTx(ctx, tx, p)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = readAcceptanceSigningSendTx(ctx, tx, p)
		if err == nil {
			sent = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return acceptanceJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_sent")
	})
	if err != nil {
		return nil, err
	}
	if known != nil {
		result := &publicationSignedAcceptance{prepared: p, raw: known, sha256: hash(known)}
		if err = result.verifyBytes(ctx); err != nil {
			return nil, err
		}
		return result, nil
	}
	if sent {
		return nil, c.ErrExecutionCommitUnknown
	}
	if err = p.ensureSigner(ctx); err != nil {
		return nil, err
	}
	// Only this invocation's acknowledged FIRST sent commit can reach the RPC.
	err = p.transaction(ctx, func(tx *sql.Tx, recovery publicationRecoveryFacts, now time.Time) error {
		if p.intent.Claim != p.proof.claim || !now.Before(p.intent.SignUntil) || !now.Before(recovery.until) {
			return c.ErrExecutionAuthority
		}
		if err := acceptanceJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_sent"); err != nil {
			return err
		}
		if err := acceptanceJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_result"); err != nil {
			return err
		}
		raw, err := p.expectedSend()
		if err != nil {
			return err
		}
		return p.storeTx(ctx, tx, p.id()+"_sent", raw, now)
	})
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithDeadline(ctx, p.intent.SignUntil)
	defer cancel()
	raw, sha, err := p.record.SignCommitted(bounded)
	if err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	result := &publicationSignedAcceptance{prepared: p, raw: bytes.Clone(raw), sha256: sha}
	if err = result.verifyBytes(ctx); err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	err = p.transaction(ctx, func(tx *sql.Tx, _ publicationRecoveryFacts, now time.Time) error {
		if err := readAcceptanceSigningSendTx(ctx, tx, p); err != nil {
			return err
		}
		body, err := ce.Canonical(publicationAcceptanceSigningResult{Version: "system-backup-original-acceptance-signing-result.v1", PreparedSHA256: p.intentSHA256, PayloadSHA256: p.intent.PayloadSHA256, SignatureSHA256: sha, Record: raw})
		if err != nil {
			return err
		}
		if err = p.storeTx(ctx, tx, p.id()+"_result", body, now); err != nil {
			return err
		}
		read, err := readAcceptanceSigningResultTx(ctx, tx, p)
		if err != nil || !bytes.Equal(read, raw) {
			return c.ErrExecutionRecord
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	return result, nil
}
