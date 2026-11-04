package systembackupexecution

import (
	"context"
	"database/sql"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
)

// Public effective target binding; local material paths and credentials are
// excluded. Their identities, versions and exact CA bytes are still bound.
func publicationRecoveryTargetSHA(p PublicationTargetMaterials) string {
	raw, err := ce.Canonical(struct {
		Installation, Endpoint, Region, Bucket, Root, Staging                                   string
		ReadIdentity, ReadVersion, WriteIdentity, WriteVersion, CAIdentity, CAVersion, CASHA256 string
	}{p.InstallationID, p.Endpoint, p.Region, p.Bucket, p.Root, p.RemoteStagingRoot, p.ReadIdentityHash, p.ReadRefVersion, p.WriteIdentityHash, p.WriteRefVersion, p.CAIdentityHash, p.CARefVersion, p.CASHA256})
	if err != nil {
		return ""
	}
	return hash(raw)
}

func readPublicationRecoveryEvidence(ctx context.Context, tx *sql.Tx, installation, kind string, pin publicationEvidencePin) (publicationCurrentEvidence, error) {
	var e publicationCurrentEvidence
	var sum string
	var size int64
	if pin.validate() != nil || (kind != "failure_domain_attestation" && kind != "capability_snapshot") {
		return e, c.ErrExecutionRecord
	}
	// Registered original system evidence is read through the current owner's
	// transaction. Invalidation/expiry and exact immutable bytes all matter.
	err := tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type=? AND storage_state='inline' AND observed_health='healthy' AND evidence_failure_code='none' AND encryption='none' AND media_type='application/json' AND expires_at>UTC_TIMESTAMP(6) FOR SHARE`, pin.ID, installation, kind).Scan(&e.Raw, &sum, &size, &e.Expires)
	if err != nil {
		return publicationCurrentEvidence{}, err
	}
	if len(e.Raw) < 2 || len(e.Raw) > 8192 || int64(len(e.Raw)) != size || hash(e.Raw) != sum || sum != pin.SHA256 {
		return publicationCurrentEvidence{}, c.ErrExecutionRecord
	}
	return e, nil
}

// Positive original evidence is observed under the same current publisher
// authority as the task. No source GET, new mapping, grant, signature, provider
// request or task state is produced here. KEK fence precedes original records.
func (s *DeploymentService) preparePublicationRecoveryFacts(ctx context.Context, claim c.ClaimToken, attempt uint64, capture publicationVerifiedCapture, target PublicationTargetMaterials) (publicationRecoveryFacts, error) {
	var zero publicationRecoveryFacts
	if !capture.checked() || s == nil || s.publisherVerifier == nil || s.checkPublisherVerifierBinding(ctx) != nil || capture.SourceFacts.PublicationPolicy == nil {
		return zero, c.ErrExecutionAuthority
	}
	p := *capture.SourceFacts.PublicationPolicy
	if p.validate() != nil || p.Policy.Installation != capture.Input.InstallationID {
		return zero, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, err
	}
	facts := guard.Facts()
	if facts.Status != "validating" || facts.ConfigVersion != capture.Input.ConfigVersion || facts.ConfigSHA256 != capture.Input.ConfigSHA256 || facts.CaptureResultSHA256 != capture.CaptureResultSHA256 || facts.CaptureAttemptNo != attempt || s.checkPublicationTargetTx(ctx, tx, facts, target) != nil {
		return zero, c.ErrExecutionAuthority
	}
	originalConfig, err := readOriginalEnabledConfiguration(ctx, tx, facts.InstallationID, p.Policy.ConfigSHA256, facts.ConfigVersion, facts.ConfigSHA256, capture.Input.ConfigSnapshot)
	if err != nil {
		return zero, c.ErrExecutionAuthority
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return zero, c.ErrExecutionAuthority
	}
	binding := s.publisherVerifier.Binding
	if p.Policy.RecoveryEvidenceStatus == "not_provided" {
		zero.Target = p.Policy.Target
		zero.KEK = publicationManifestKEK{Provider: binding.Key.Provider, KeyID: binding.Key.ProviderKeyID, KeyVersion: binding.Key.ProviderVersion}
		raw, err := ce.Canonical(struct{ Policy, Target, Capture string }{p.SHA256, publicationRecoveryTargetSHA(target), capture.receipt.sha256})
		if err != nil {
			return publicationRecoveryFacts{}, err
		}
		zero.evidenceSHA256 = hash(raw)
		zero.until = access.ValidUntil()
	} else {
		trust := s.publisherVerifier.RecoveryTrust
		if trust == nil || trust.validate() != nil || p.Policy.RecoveryEvidence == nil {
			return zero, c.ErrExecutionAuthority
		}
		var epoch uint64
		if tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, facts.InstallationID).Scan(&epoch) != nil {
			return zero, c.ErrExecutionAuthority
		}
		owner, sig, err := (a.SQLOriginalReader{}).RecheckOriginal(ctx, tx, facts.InstallationID, binding.ConfigRef)
		if err != nil {
			return zero, err
		}
		att, err := readPublicationRecoveryEvidence(ctx, tx, facts.InstallationID, "failure_domain_attestation", trust.Selection.Attestation)
		if err != nil {
			return zero, err
		}
		cap, err := readPublicationRecoveryEvidence(ctx, tx, facts.InstallationID, "capability_snapshot", trust.Selection.Capability)
		if err != nil {
			return zero, err
		}
		zero, err = verifyPublicationRecoveryEvidence(originalConfig, p, trust, binding, s.publisherVerifier.InstallationIssuer, owner, sig, att, cap, publicationRecoveryTargetSHA(target), now)
		if err != nil {
			return publicationRecoveryFacts{}, err
		}
	}
	if guard.RecheckTx(ctx, tx) != nil || s.checkPublisherVerifierBinding(ctx) != nil {
		return publicationRecoveryFacts{}, c.ErrExecutionAuthority
	}
	// SQL writes are absent. A successful read transaction is still explicitly
	// closed before returning detached inert facts to the manifest assembler.
	if tx.Commit() != nil || ctx.Err() != nil {
		return publicationRecoveryFacts{}, c.ErrExecutionAuthority
	}
	zero.captureSHA256 = capture.receipt.sha256
	if access.ValidUntil().Before(zero.until) {
		zero.until = access.ValidUntil()
	}
	zero.targetSHA256 = publicationRecoveryTargetSHA(target)
	return zero, nil
}
