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

// Catalog's original business protocol, not a new task/signing framework.
// Phase IDs exclude clock/Pod/current claim; each immutable value is INSERTed
// under the real original task lock and never refreshed on an unknown result.
type publicationCatalogSigningIntent struct {
	Version, Installation, Backup, ArtifactSHA256, PayloadSHA256 string
	Attempt                                                      uint64
	Claim                                                        c.ClaimToken
	SignUntil                                                    time.Time
	Payload                                                      json.RawMessage
	Catalog                                                      PublicationCatalogMaterials
	CatalogKey                                                   string
	Accepted                                                     publicationCatalogAcceptedIdentity
	ConfigVersion                                                uint64
	ConfigSHA256                                                 string
}
type publicationCatalogAcceptedIdentity struct {
	Key, Version, SHA256 string
	Size                 int64
}
type publicationCatalogSigningSend struct {
	Version, PreparedSHA256, PayloadSHA256 string
	Claim                                  c.ClaimToken
	SignUntil                              time.Time
}
type publicationCatalogSigningResult struct {
	Version, PreparedSHA256, PayloadSHA256, SignatureSHA256 string
	Record                                                  json.RawMessage
}
type preparedPublicationCatalog struct {
	proof        *publicationFinalVerification
	accepted     *publicationAcceptedObject
	catalog      PublicationCatalogMaterials
	intent       publicationCatalogSigningIntent
	intentSHA256 string
	signers      *security.SQLPublicationTaskSigners
	record       *security.SQLPreparedPublicationRecord
}

func catalogSigningID(installation, backup string, attempt uint64) string {
	return "sev_pub_catalog_" + hash(publicationCatalogIdentity(installation, backup, attempt))
}
func (p *preparedPublicationCatalog) id() string {
	return catalogSigningID(p.proof.target.InstallationID, p.proof.claim.Target.PublicID, p.proof.attempt)
}
func (p *preparedPublicationCatalog) Close() {
	if p != nil && p.signers != nil {
		p.signers.Close()
		p.signers = nil
	}
}
func (p *preparedPublicationCatalog) ready() bool {
	return p != nil && p.accepted != nil && p.accepted.signed != nil && p.accepted.signed.prepared.ready() && p.proof == p.accepted.signed.prepared.proof && p.accepted.object.receipt != nil && p.catalog.validate(p.proof.target) == nil
}

func catalogJournalAbsentTx(ctx context.Context, tx *sql.Tx, backup, prefix string) error {
	var count uint64
	if tx == nil || tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND LEFT(public_id,?)=?`, backup, len(prefix), prefix).Scan(&count) != nil {
		return c.ErrExecutionRecord
	}
	if count != 0 {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (p *preparedPublicationCatalog) currentFactsTx(ctx context.Context, tx *sql.Tx) (publicationRecoveryFacts, time.Time, error) {
	var zero publicationRecoveryFacts
	if !p.ready() || tx == nil {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	if err := p.accepted.recheckTx(ctx, tx); err != nil {
		return zero, time.Time{}, err
	}
	current, err := p.proof.service.currentPublicationCatalog(ctx)
	if err != nil || current != p.catalog {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	guard, err := p.proof.access.Bind(ctx, tx)
	if err != nil {
		return zero, time.Time{}, err
	}
	if err = p.proof.service.checkPublicationActionTargetTx(ctx, tx, guard.Facts(), p.catalog.transport(), "catalog_registration_append"); err != nil {
		return zero, time.Time{}, err
	}
	recovery, now, err := acceptanceRecoveryFactsTx(ctx, tx, p.proof)
	if err != nil {
		return zero, time.Time{}, err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return zero, time.Time{}, err
	}
	return recovery, now, nil
}

func (p *preparedPublicationCatalog) recheckTx(ctx context.Context, tx *sql.Tx) (publicationRecoveryFacts, time.Time, error) {
	var zero publicationRecoveryFacts
	if !p.ready() || tx == nil {
		return zero, time.Time{}, c.ErrExecutionAuthority
	}
	i := p.intent
	if i.Version != "system-backup-original-catalog-signing.v1" || i.Installation != p.proof.target.InstallationID || i.Backup != p.proof.claim.Target.PublicID || i.Attempt != p.proof.attempt || i.Claim.Target != p.proof.claim.Target || i.Claim.Owner == "" || i.Claim.RowVersion < 1 || i.ArtifactSHA256 != p.proof.originalSHA256 || i.PayloadSHA256 != hash(i.Payload) || i.SignUntil.IsZero() {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	capture := p.proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	accepted := p.accepted.object
	if i.Catalog != p.catalog || i.CatalogKey != publicationCatalogKey(p.catalog, i.Backup, i.Attempt) || i.Accepted != (publicationCatalogAcceptedIdentity{Key: accepted.Key, Version: accepted.Version, SHA256: accepted.SHA256, Size: accepted.Size}) || i.ConfigVersion != capture.Input.ConfigVersion || i.ConfigSHA256 != capture.Input.ConfigSHA256 {
		return zero, time.Time{}, c.ErrExecutionRecord
	}
	if p.intentSHA256 != "" {
		raw, err := loadPublicationMetadata(ctx, tx, i.Backup, p.id()+"_prepared")
		want, _ := ce.Canonical(i)
		if err != nil || hash(raw) != p.intentSHA256 || !bytes.Equal(raw, want) {
			return zero, time.Time{}, c.ErrExecutionRecord
		}
	}
	recovery, now, err := p.currentFactsTx(ctx, tx)
	if err != nil {
		return zero, time.Time{}, err
	}
	if err = validateCatalogBusinessPayload(i.Payload, p.accepted, now); err != nil {
		return zero, time.Time{}, err
	}
	return recovery, now, nil
}

func (p *preparedPublicationCatalog) transaction(ctx context.Context, body func(*sql.Tx, publicationRecoveryFacts, time.Time) error) error {
	return p.transactionWithSigningStatePrefix(ctx, false, body)
}

func (p *preparedPublicationCatalog) transactionWithSigningStatePrefix(ctx context.Context, firstSigning bool, body func(*sql.Tx, publicationRecoveryFacts, time.Time) error) error {
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
	// Only the fresh signing-input transaction needs current signer authority.
	// Historical result queries retain their original TTL and recovery rules.
	if firstSigning {
		if p.record == nil {
			return c.ErrExecutionAuthority
		}
		installation, e := p.record.SigningInstallationID()
		if e != nil || installation != s.Config.InstallationID || installation != p.proof.target.InstallationID {
			return c.ErrExecutionAuthority
		}
		if e = p.record.LockSigningStatePrefix(ctx, tx); e != nil {
			return e
		}
	}
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

func (p *preparedPublicationCatalog) storeTx(ctx context.Context, tx *sql.Tx, id string, body []byte, now time.Time) error {
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

func (p *preparedPublicationCatalog) expectedSend() ([]byte, error) {
	if !p.ready() || !formalCandidateDigest(p.intentSHA256) {
		return nil, c.ErrExecutionAuthority
	}
	return ce.Canonical(publicationCatalogSigningSend{Version: "system-backup-original-catalog-signing-sent.v1", PreparedSHA256: p.intentSHA256, PayloadSHA256: p.intent.PayloadSHA256, Claim: p.intent.Claim, SignUntil: p.intent.SignUntil})
}
func readCatalogSigningSendTx(ctx context.Context, tx *sql.Tx, p *preparedPublicationCatalog) error {
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
func readCatalogSigningResultTx(ctx context.Context, tx *sql.Tx, p *preparedPublicationCatalog) ([]byte, error) {
	if !p.ready() {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := loadPublicationMetadata(ctx, tx, p.intent.Backup, p.id()+"_result")
	if errors.Is(err, sql.ErrNoRows) {
		if prior := catalogJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_result"); prior != nil {
			return nil, prior
		}
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	var result publicationCatalogSigningResult
	if decodePublicationCanonical(raw, &result) != nil || result.Version != "system-backup-original-catalog-signing-result.v1" || result.PreparedSHA256 != p.intentSHA256 || result.PayloadSHA256 != p.intent.PayloadSHA256 || len(result.Record) < 2 || len(result.Record) > 8192 || hash(result.Record) != result.SignatureSHA256 {
		return nil, c.ErrExecutionRecord
	}
	if err = readCatalogSigningSendTx(ctx, tx, p); err != nil {
		return nil, c.ErrExecutionRecord
	}
	return bytes.Clone(result.Record), nil
}

func (s *DeploymentService) prepareOriginalPublicationCatalog(ctx context.Context, accepted *publicationAcceptedObject) (_ *preparedPublicationCatalog, resultErr error) {
	if s == nil || accepted == nil || accepted.signed == nil || !accepted.signed.prepared.ready() || accepted.signed.prepared.proof.service != s || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	proof := accepted.signed.prepared.proof
	catalog, err := s.currentPublicationCatalog(ctx)
	if err != nil {
		return nil, err
	}
	p := &preparedPublicationCatalog{proof: proof, accepted: accepted, catalog: catalog}
	if !p.ready() || proof.access.Check(ctx) != nil {
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
	recovery, now, err := p.currentFactsTx(ctx, tx)
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
	if err = catalogJournalAbsentTx(ctx, tx, proof.claim.Target.PublicID, p.id()); err != nil {
		return nil, err
	}
	if err = tx.Rollback(); err != nil {
		return nil, err
	}
	p.signers, err = s.PublicationSignersForTask(ctx, proof.claim)
	if err != nil {
		return nil, err
	}
	key, err := p.signers.PublicationSigningKey(ctx, "catalog_record")
	if err != nil {
		return nil, err
	}
	capture := proof.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture
	value, err := catalogPayloadFromOriginal(accepted, key, now)
	if err != nil {
		return nil, err
	}
	payload, err := ce.Canonical(value)
	if err != nil {
		return nil, err
	}
	if err = validateCatalogBusinessPayload(payload, accepted, now); err != nil {
		return nil, err
	}
	p.intent = publicationCatalogSigningIntent{Version: "system-backup-original-catalog-signing.v1", Installation: s.Config.InstallationID, Backup: proof.claim.Target.PublicID, Attempt: proof.attempt, ArtifactSHA256: proof.originalSHA256, PayloadSHA256: hash(payload), Payload: payload, Claim: proof.claim, SignUntil: recovery.until.UTC().Truncate(time.Microsecond), Catalog: catalog, CatalogKey: publicationCatalogKey(catalog, proof.claim.Target.PublicID, proof.attempt), Accepted: publicationCatalogAcceptedIdentity{Key: accepted.object.Key, Version: accepted.object.Version, SHA256: accepted.object.SHA256, Size: accepted.object.Size}, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256}
	p.record, err = p.signers.PreparePublicationRecord(ctx, "catalog_record", payload)
	if err != nil {
		return nil, err
	}
	err = p.transactionWithSigningStatePrefix(ctx, true, func(tx *sql.Tx, current publicationRecoveryFacts, at time.Time) error {
		if !at.Before(p.intent.SignUntil) || p.intent.SignUntil.After(current.until) {
			return c.ErrExecutionAuthority
		}
		if err := catalogJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()); err != nil {
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

func (p *preparedPublicationCatalog) ensureSigner(ctx context.Context) error {
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
	key, err := q.PublicationSigningKey(ctx, "catalog_record")
	if err != nil {
		return err
	}
	payload, err := decodePublicationCatalogPayload(p.intent.Payload)
	if err != nil || key != payload.Key {
		return c.ErrExecutionRecord
	}
	p.record, err = q.PreparePublicationRecord(ctx, "catalog_record", p.intent.Payload)
	return err
}

func (p *preparedPublicationCatalog) SignCommitted(ctx context.Context) (*publicationSignedCatalog, error) {
	if !p.ready() || !formalCandidateDigest(p.intentSHA256) {
		return nil, c.ErrExecutionAuthority
	}
	var known []byte
	var sent bool
	err := p.transaction(ctx, func(tx *sql.Tx, _ publicationRecoveryFacts, _ time.Time) error {
		var err error
		known, err = readCatalogSigningResultTx(ctx, tx, p)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = readCatalogSigningSendTx(ctx, tx, p)
		if err == nil {
			sent = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return catalogJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_sent")
	})
	if err != nil {
		return nil, err
	}
	if known != nil {
		result := &publicationSignedCatalog{prepared: p, raw: known, sha256: hash(known)}
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
		if err := catalogJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_sent"); err != nil {
			return err
		}
		if err := catalogJournalAbsentTx(ctx, tx, p.intent.Backup, p.id()+"_result"); err != nil {
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
	result := &publicationSignedCatalog{prepared: p, raw: bytes.Clone(raw), sha256: sha}
	if err = result.verifyBytes(ctx); err != nil {
		return nil, errors.Join(c.ErrExecutionCommitUnknown, err)
	}
	err = p.transaction(ctx, func(tx *sql.Tx, _ publicationRecoveryFacts, now time.Time) error {
		if err := readCatalogSigningSendTx(ctx, tx, p); err != nil {
			return err
		}
		body, err := ce.Canonical(publicationCatalogSigningResult{Version: "system-backup-original-catalog-signing-result.v1", PreparedSHA256: p.intentSHA256, PayloadSHA256: p.intent.PayloadSHA256, SignatureSHA256: sha, Record: raw})
		if err != nil {
			return err
		}
		if err = p.storeTx(ctx, tx, p.id()+"_result", body, now); err != nil {
			return err
		}
		read, err := readCatalogSigningResultTx(ctx, tx, p)
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
