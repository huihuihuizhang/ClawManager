package systembackupexecution

import (
	"context"
	"time"

	"clawreef/internal/systembackup/control"
	c "clawreef/internal/systembackupcontroller"
)

// Ephemeral mTLS Job material. Its request digest/phase is distinct from every
// original capture invocation. Artifact JCS/JWS still use their three original
// independent external signing authorities.
func (s *DeploymentService) issuePublicationWorkerIdentity(ctx context.Context, claim c.ClaimToken, attempt uint64, requestSHA string) (control.TaskIdentity, error) {
	var zero control.TaskIdentity
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || !formalCandidateDigest(requestSHA) || s.publicationBinding() != nil || s.Forward.CheckDeployment(ctx, s.publisherVerifierDB) != nil {
		return zero, c.ErrExecutionAuthority
	}
	o := s.Runtime.Owner
	issuer := o.Issuer
	g := s.Forward.DeploymentBinding()
	allowed := false
	for _, action := range g.Actions {
		if action == "issue_worker" {
			allowed = true
		}
	}
	if !allowed || issuer.Certificate == nil || issuer.Signer == nil || issuer.TrustDomain != s.Config.TrustDomain || g.WorkerIssuerSHA256 != hash(issuer.Certificate.Raw) || s.Config.IssuerSHA256 != g.WorkerIssuerSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	deployment := access.Deployment()
	if deployment.CaptureGrantSHA256 != s.Forward.GrantSHA256() || deployment.ControllerOwner != g.ControllerOwner || deployment.DeploymentConfigSHA256 != g.DeploymentConfigSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		tx.Rollback()
		return zero, err
	}
	facts := guard.Facts()
	if (facts.Status != "validating" && facts.Status != "publishing") || facts.ConfigSHA256 != g.ConfigSHA256 || facts.ConfigVersion != g.ConfigVersion || facts.InstallationID != g.InstallationID {
		tx.Rollback()
		return zero, c.ErrExecutionAuthority
	}
	until := access.ValidUntil()
	if g.ExpiresAt.Before(until) {
		until = g.ExpiresAt
	}
	if facts.TaskDeadline.Before(until) {
		until = facts.TaskDeadline
	}
	if issuer.Certificate.NotAfter.Before(until) {
		until = issuer.Certificate.NotAfter
	}
	until = until.UTC().Truncate(time.Second)
	if err = guard.RecheckTx(ctx, tx); err != nil {
		tx.Rollback()
		return zero, err
	}
	if err = tx.Rollback(); err != nil {
		return zero, err
	}
	// No original SQL lock is held across CA signing. Permission is the explicit
	// CURRENT signed deployment issue_worker action plus CURRENT publisher scope;
	// no old capture Authority, gate claim or source-Generate permit is fabricated.
	identity, err := issuer.IssueWorker(claim.Target.PublicID, until, requestSHA)
	if err != nil {
		return zero, err
	}
	accepted := false
	defer func() {
		if !accepted {
			identity.Clear()
		}
	}()
	if !time.Now().Before(until) || s.Forward.CheckDeployment(ctx, s.publisherVerifierDB) != nil {
		return zero, c.ErrExecutionAuthority
	}
	current, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || current.Check(ctx) != nil || !current.ValidUntil().Equal(access.ValidUntil()) {
		return zero, c.ErrExecutionAuthority
	}
	final, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer final.Rollback()
	last, err := current.Bind(ctx, final)
	if err != nil {
		return zero, err
	}
	if last.Facts() != facts || last.RecheckTx(ctx, final) != nil {
		return zero, c.ErrExecutionAuthority
	}
	accepted = true
	return identity, nil
}
