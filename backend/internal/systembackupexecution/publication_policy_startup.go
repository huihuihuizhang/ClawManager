package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	deployment "clawreef/internal/systembackupdeployment"
	a "clawreef/internal/systembackupkekadapter"
)

var ErrOriginalPublicationPolicy = errors.New("original publication policy material unavailable or conflicting")

func (s *DeploymentService) requiresOriginalPublicationPolicy() bool {
	return s != nil && s.ForwardEnabled && s.Config.CaptureScope == "six-part" && s.Config.PublicationTarget != nil
}

// The early database path and live readiness also compare the declared policy
// with the original pinned 097 bytes. A policy cannot choose a different
// failure-domain registry merely because it carries a well-shaped hash.
func (s *DeploymentService) checkOriginalPublicationPolicyCurrent(ctx context.Context, db *sql.DB) error {
	if !s.requiresOriginalPublicationPolicy() {
		return nil
	}
	bad := func() error { return errors.Join(c.ErrExecutionAuthority, ErrOriginalPublicationPolicy) }
	if ctx == nil || ctx.Err() != nil || db == nil || s.Forward == nil || s.captureMaterials == nil || s.publicationTarget == nil || s.publisherVerifier == nil || s.checkOriginalPublicationPolicyStartup(*s.captureMaterials) != nil || s.Forward.CheckDeployment(ctx, db) != nil {
		return bad()
	}
	ref := s.captureMaterials.Discovery.PublicationPolicy
	raw, err := pinnedDeploymentFile(ref.Path, ref.SHA256, 65536)
	if err != nil {
		return bad()
	}
	var policy originalPublicationPolicy
	if decodePublicationCanonical(raw, &policy) != nil {
		return bad()
	}
	g := s.Forward.DeploymentBinding()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return bad()
	}
	defer tx.Rollback()
	var config []byte
	var sum string
	var size int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT canonical_config_json,config_sha256,config_size_bytes,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, g.InstallationID, g.ConfigVersion, g.ConfigSHA256).Scan(&config, &sum, &size, &now) != nil || len(config) < 2 || len(config) > 262144 || int64(len(config)) != size || hash(config) != sum || sum != g.ConfigSHA256 {
		return bad()
	}
	pin, err := originalFailureDomainsPin(config)
	if err != nil || pin != policy.FailureDomains {
		return bad()
	}
	if policy.RecoveryEvidenceStatus == "provided" {
		p := s.publisherVerifier
		trust := p.RecoveryTrust
		if trust == nil || trust.validate() != nil || !reflect.DeepEqual(policy.RecoveryEvidence, &trust.Selection) {
			return bad()
		}
		var epoch uint64
		if tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, g.InstallationID).Scan(&epoch) != nil {
			return bad()
		}
		owner, sig, err := (a.SQLOriginalReader{}).RecheckOriginal(ctx, tx, g.InstallationID, p.Binding.ConfigRef)
		if err != nil {
			return bad()
		}
		att, err := readPublicationRecoveryEvidence(ctx, tx, g.InstallationID, "failure_domain_attestation", trust.Selection.Attestation)
		if err != nil {
			return bad()
		}
		cap, err := readPublicationRecoveryEvidence(ctx, tx, g.InstallationID, "capability_snapshot", trust.Selection.Capability)
		if err != nil {
			return bad()
		}
		if _, err = verifyPublicationRecoveryEvidence(config, frozenPublicationPolicy{SHA256: hash(raw), Policy: policy}, trust, p.Binding, p.InstallationIssuer, owner, sig, att, cap, publicationRecoveryTargetSHA(*s.publicationTarget), now); err != nil {
			return bad()
		}
	}
	if tx.Rollback() != nil {
		return bad()
	}
	if s.Forward.CheckDeployment(ctx, db) != nil {
		return bad()
	}
	return nil
}

// Real file/database startup and current readiness call this before a task is
// claimed or any writer is paused. Pure RBAC rendering retains shape checks;
// it does not manufacture a runtime readiness observation.
func (s *DeploymentService) checkOriginalPublicationPolicyStartup(m productionCaptureMaterials) error {
	if s == nil {
		return c.ErrExecutionAuthority
	}
	if !s.ForwardEnabled {
		return nil
	}
	var ref *originalPublicationPolicyReference
	if m.Discovery != nil {
		ref = m.Discovery.PublicationPolicy
	}
	if ref == nil {
		if s.requiresOriginalPublicationPolicy() {
			return errors.Join(c.ErrExecutionAuthority, ErrOriginalPublicationPolicy)
		}
		return nil
	}
	bad := func() error { return errors.Join(c.ErrExecutionAuthority, ErrOriginalPublicationPolicy) }
	if ref.validate() != nil || s.Forward == nil {
		return bad()
	}
	raw, err := pinnedDeploymentFile(ref.Path, ref.SHA256, 65536)
	if err != nil {
		return bad()
	}
	var p originalPublicationPolicy
	if decodePublicationCanonical(raw, &p) != nil || p.validate() != nil {
		return bad()
	}
	binding := s.Forward.DeploymentBinding()
	if p.Installation != s.Config.InstallationID || p.Installation != binding.InstallationID || p.ConfigSHA256 != binding.ConfigSHA256 {
		return bad()
	}
	profile, err := deployment.LoadExecutionProfile(s.Config.ProfileFile)
	if err != nil {
		return bad()
	}
	_, sha, err := profile.CanonicalIdentity()
	if err != nil || sha != binding.ProfileSHA256 || profile.InstallationID != p.Installation || p.Target.Class != profile.TargetClass || p.Target.Domain != profile.FailureDomain || !reflect.DeepEqual(p.Target.Risks, profile.TargetRisks) {
		return bad()
	}
	// A declared positive selection never chooses its own trust anchor. During
	// full runtime startup the independent publisher is already loaded; the
	// source-owner's pre-composition fixture stage is rechecked at readiness.
	if p.RecoveryEvidenceStatus == "provided" && s.publisherVerifier != nil {
		trust := s.publisherVerifier.RecoveryTrust
		if trust == nil || trust.validate() != nil || !reflect.DeepEqual(p.RecoveryEvidence, &trust.Selection) {
			return bad()
		}
		if _, err := publicationDomainIdentities(trust.FailureDomainRegistry, p.Installation, p.FailureDomains); err != nil {
			return bad()
		}
	}
	return nil
}
