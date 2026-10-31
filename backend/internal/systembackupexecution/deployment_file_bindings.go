package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
)

// This is the production constructor's pure file-binding stage. The DB stage
// already chose current Forward or independent Recovery mode; no provider,
// source/staging IO, platform bypass or SQL authorization is performed here.
func (s *DeploymentService) bindDeploymentFileInputs(inputs []FormalVerifierInput) error {
	return s.bindDeploymentStartupInputs(DeploymentStartupInputs{FormalVerifier: inputs})
}

func (s *DeploymentService) bindDeploymentStartupInputs(inputs DeploymentStartupInputs) error {
	cfg, err := LoadDeploymentConfig(s.ConfigPath, s.ConfigDigest)
	if err != nil {
		return err
	}
	profile, err := api.LoadExecutionProfile(cfg.ProfileFile)
	if err != nil {
		return err
	}
	_, profileHash, err := profile.CanonicalIdentity()
	if err != nil {
		return err
	}
	for _, identity := range []*c.PinnedExecutionIdentity{s.Forward, s.Recovery} {
		if identity == nil {
			return c.ErrExecutionAuthority
		}
		grant := identity.DeploymentBinding()
		if grant.DeploymentConfigSHA256 != s.ConfigDigest || grant.InstallationID != cfg.InstallationID || grant.ControllerOwner != cfg.ControllerOwner || grant.ProfileSHA256 != profileHash || profile.InstallationID != cfg.InstallationID {
			return c.ErrExecutionAuthority
		}
	}
	s.Config, s.profile, s.profileHash = cfg, profile, profileHash
	if s.ForwardEnabled {
		if err = s.loadFormalVerifier(inputs.FormalVerifier); err != nil {
			return err
		}
		return s.loadPublicationSignerInput(inputs.PublicationSigners)
	}
	return nil
}
