package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"reflect"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Same bounded context, original owner/definition and failure latch as every
// other source factory continuation. No task/attempt/Skills permit is accepted
// as Teams source authority; original worker task checks remain unchanged.
func (s *OriginalCaptureSequence) ValidateTeamsSource(ctx context.Context) (resultErr error) {
	leave, e := s.enter(ctx)
	if e != nil {
		return e
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	if s.authority == nil || s.teamsSourceOutputDisjoint() != nil {
		return install.ErrInstall
	}
	return s.authority.ValidateTeamsSource(ctx)
}

func (s *OriginalCaptureSequence) teamsSourceOutputDisjoint() error {
	if s == nil || s.definition.TeamsSource == nil || s.core.CaptureModules == nil || s.materials.Discovery == nil {
		return install.ErrTeamsSourceUnavailable
	}
	d := s.definition.TeamsSource
	for _, reserved := range []string{s.core.CaptureModules.Path, s.materials.Discovery.GrantFile, s.materials.Redis.GrantFile, s.materials.Objects.GrantFile, s.definition.CoreFile, s.definition.ConfigFile, s.core.ForwardGrant.Path, s.privateFile, d.PartsRegistry.File, d.DatabaseCredential.File, d.Source.CredentialFile} {
		if reserved != "" && d.Source.GrantFile == reserved {
			return install.ErrInstall
		}
	}
	if s.materials.ControlEvidenceSource != nil && (d.Source.GrantFile == s.materials.ControlEvidenceSource.GrantFile || d.Source.GrantFile == s.materials.ControlEvidenceSource.ControllerGrantFile) {
		return install.ErrInstall
	}
	return nil
}

func (s *OriginalCaptureSequence) IssueTeamsSourceGrant(ctx context.Context) (_ install.TeamsSourceIssueResult, resultErr error) {
	var zero install.TeamsSourceIssueResult
	leave, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	if s.authority == nil || s.teamsSourceOutputDisjoint() != nil || s.authority.Recheck(ctx) != nil {
		return zero, install.ErrInstall
	}
	key, e := install.ReadPrivateFile(s.privateFile, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return zero, install.ErrInstall
	}
	defer clear(key)
	result, e := s.authority.IssueTeamsSource(ctx, key)
	if e != nil {
		return zero, e
	}
	if !s.sameTeamsSourceResult(result) {
		return zero, install.ErrInstall
	}
	return result, nil
}

func (s *OriginalCaptureSequence) QueryTeamsSourceGrant(ctx context.Context) (_ install.TeamsSourceIssueResult, resultErr error) {
	var zero install.TeamsSourceIssueResult
	leave, e := s.enter(ctx)
	if e != nil {
		return zero, e
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	if s.authority == nil || s.teamsSourceOutputDisjoint() != nil {
		return zero, install.ErrInstall
	}
	result, e := s.authority.QueryTeamsSource(ctx)
	if e != nil {
		return zero, e
	}
	if !s.sameTeamsSourceResult(result) {
		return zero, install.ErrInstall
	}
	return result, nil
}

func (s *OriginalCaptureSequence) sameTeamsSourceResult(result install.TeamsSourceIssueResult) bool {
	if s == nil || s.definition.TeamsSource == nil || result.OriginalDefinitionSHA256 != hashMustMaterialDefinition(s.definition) || !formalCandidateDigest(result.Source.GrantSHA256) {
		return false
	}
	expected := s.definition.TeamsSource.Source
	expected.GrantSHA256 = result.Source.GrantSHA256
	return reflect.DeepEqual(expected, result.Source) && result.Grant.File == expected.GrantFile && result.Grant.SHA256 == expected.GrantSHA256 && result.NotBefore.Equal(s.definition.NotBefore) && result.Until.Equal(s.definition.Until)
}
