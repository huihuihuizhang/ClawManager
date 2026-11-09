package systembackupexecution

import (
	"context"
	"database/sql"

	c "clawreef/internal/systembackupcontroller"
)

// CheckDeploymentDatabase admits the production metadata connection using the
// same pinned identities and mode as NewDeploymentService. It never migrates,
// publishes readiness, or grants permissions. Service construction rechecks.
func CheckDeploymentDatabase(ctx context.Context, db *sql.DB, path, digest, forwardDigest, recoveryDigest string, forwardEnabled bool, verifierInputs ...FormalVerifierInput) error {
	return CheckDeploymentDatabaseWithInputs(ctx, db, path, digest, forwardDigest, recoveryDigest, forwardEnabled, DeploymentStartupInputs{FormalVerifier: verifierInputs})
}

func CheckDeploymentDatabaseWithInputs(ctx context.Context, db *sql.DB, path, digest, forwardDigest, recoveryDigest string, forwardEnabled bool, inputs DeploymentStartupInputs) error {
	cfg, err := LoadDeploymentConfig(path, digest)
	if err != nil {
		return err
	}
	s := &DeploymentService{Config: cfg, ConfigPath: path, ConfigDigest: digest, ForwardEnabled: forwardEnabled, metadataControllerPodName: inputs.ControllerPodName}
	if err = s.loadDeploymentIdentities(ctx, db, forwardDigest, recoveryDigest, inputs.EnabledPublication); err != nil {
		return err
	}
	if s.ForwardEnabled {
		if err = s.loadFormalVerifier(inputs.FormalVerifier); err != nil {
			return err
		}
		if err = s.loadPublicationSignerInput(inputs.PublicationSigners); err != nil {
			return err
		}
		if err = s.loadPublisherVerifierInput(inputs.PublisherVerifier); err != nil {
			return err
		}
		if err = s.loadProductionCapture(inputs.CaptureModules); err != nil {
			return err
		}
		if err = s.loadPublicationTargetInput(inputs.PublicationTarget); err != nil {
			return err
		}
		if err = s.checkOriginalPublicationPolicyCurrent(ctx, db); err != nil {
			return err
		}
	}
	return s.checkControlGrants(ctx, db)
}

func (s *DeploymentService) loadDeploymentIdentities(ctx context.Context, db *sql.DB, forwardDigest, recoveryDigest string, selected ...*EnabledPublicationStartupFiles) error {
	cfg := s.Config
	var err error
	s.Recovery, err = deploymentIdentity(cfg.RecoveryGrant, recoveryDigest, cfg.KeyDirectory)
	if err != nil {
		return err
	}
	if err = s.Recovery.CheckDeployment(ctx, db); err != nil {
		return err
	}
	g := s.Recovery.DeploymentBinding()
	if len(g.Actions) != 1 || g.Actions[0] != "recover" || g.DeploymentConfigSHA256 != s.ConfigDigest || g.InstallationID != cfg.InstallationID || g.ControllerOwner != cfg.ControllerOwner {
		return c.ErrExecutionAuthority
	}
	if len(selected) > 1 {
		return c.ErrExecutionAuthority
	}
	if !s.ForwardEnabled {
		s.useIndependentRecovery()
		return nil
	}
	forwardReference := cfg.ForwardGrant
	if len(selected) == 1 && selected[0] != nil {
		if selected[0].OriginalForward.File != cfg.ForwardGrant.Path || selected[0].Forward.SHA256 != forwardDigest {
			return c.ErrExecutionAuthority
		}
		forwardReference.Path = selected[0].Forward.File
	}
	s.Forward, err = deploymentIdentity(forwardReference, forwardDigest, cfg.KeyDirectory)
	if err != nil {
		s.useIndependentRecovery()
		return nil
	}
	if err = s.Forward.CheckDeployment(ctx, db); err != nil || !forwardCaptureActions(s.Forward.DeploymentBinding()) {
		s.useIndependentRecovery()
		return nil
	}
	if len(selected) == 1 && selected[0] != nil {
		if err = s.bindOriginalEnabledPublicationSources(ctx, db, *selected[0]); err != nil {
			if s.Forward.CheckDeployment(ctx, db) != nil {
				s.useIndependentRecovery()
				return nil
			}
			return err
		}
	}
	// Recheck after the predecessor's SQL/file reads before selecting forward
	// startup. A loss of forward authority leaves only independent recovery.
	if err = s.Forward.CheckDeployment(ctx, db); err != nil {
		s.useIndependentRecovery()
	}
	return nil
}

func (s *DeploymentService) useIndependentRecovery() {
	s.Forward = s.Recovery
	s.ForwardEnabled = false
	s.originalSourceForward = nil
	s.enabledPublicationFiles = nil
}
