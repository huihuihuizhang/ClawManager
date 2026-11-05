package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
)

type OriginalEnabledSourcePin struct{ File, SHA256 string }

// Independently installed file selections only. Native signed pairing and
// exact normal enable SQL lineage below create the private service binding.
type EnabledPublicationStartupFiles struct {
	Forward, OriginalForward OriginalEnabledSourcePin
	Signers                  PublicationSignerInput
	Verifier                 PublisherVerifierInput
	Formal                   FormalVerifierInput
}

func (s *DeploymentService) originalCaptureSourceForward() *c.PinnedExecutionIdentity {
	if s.originalSourceForward != nil {
		return s.originalSourceForward
	}
	return s.Forward
}

func (s *DeploymentService) bindOriginalEnabledPublicationSources(ctx context.Context, db *sql.DB, files EnabledPublicationStartupFiles) error {
	if s == nil || s.Forward == nil || db == nil || files.OriginalForward.File != s.Config.ForwardGrant.Path || files.Forward.File == files.OriginalForward.File || files.Forward.SHA256 != s.Forward.GrantSHA256() {
		return c.ErrExecutionAuthority
	}
	if _, e := pinnedDeploymentFile(files.Signers.File, files.Signers.SHA256, 1<<20); e != nil {
		return e
	}
	if _, e := pinnedDeploymentFile(files.Verifier.File, files.Verifier.SHA256, 1<<20); e != nil {
		return e
	}
	if files.Formal != (FormalVerifierInput{}) {
		if s.Config.FormalVerifier == nil || files.Formal.File == s.Config.FormalVerifier.Path {
			return c.ErrExecutionAuthority
		}
		if _, e := pinnedDeploymentFile(files.Formal.File, files.Formal.SHA256, 1<<20); e != nil {
			return e
		}
	}
	old, e := s.Forward.OpenOriginalEnabledOnlyPredecessor(files.OriginalForward.File, files.OriginalForward.SHA256)
	if e != nil {
		return e
	}
	current, original := s.Forward.DeploymentBinding(), old.DeploymentBinding()
	view, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: false})
	if e != nil {
		return e
	}
	defer view.Rollback()
	if s.Forward.CheckOriginalEnabledOnlyPredecessorInView(ctx, reg.SQLReadView(view), old) != nil {
		return c.ErrExecutionAuthority
	}
	proof, e := sec.ReadOriginalEnabledOnlyLineage(ctx, view, current.InstallationID, original.ConfigSHA256, current.ConfigVersion, current.ConfigSHA256)
	if e != nil {
		return e
	}
	authorized, e := proof.AuthorizationConfigSHA256(ctx, view)
	if e != nil || authorized != original.ConfigSHA256 {
		return c.ErrExecutionAuthority
	}
	if s.Forward.CheckOriginalEnabledOnlyPredecessorInView(ctx, view, old) != nil || view.Rollback() != nil {
		return c.ErrExecutionAuthority
	}
	copyFiles := files
	s.enabledPublicationFiles = &copyFiles
	s.originalSourceForward = old
	return nil
}
