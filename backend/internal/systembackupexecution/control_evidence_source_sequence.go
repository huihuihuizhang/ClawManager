package systembackupexecution

import (
	"bytes"
	"context"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Use the already authenticated ORIGINAL factory continuation, not a task or
// a caller-built SourceMaterialIssuer. D owns actual mapping/path materialization.
func (s *OriginalCaptureSequence) IssueControlEvidenceSourceGrant(ctx context.Context) (_ install.ControlEvidenceSourceIssueResult, resultErr error) {
	var zero install.ControlEvidenceSourceIssueResult
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
	if s.authority == nil || s.materials.ControlEvidenceSource == nil || s.authority.Recheck(ctx) != nil {
		return zero, install.ErrInstall
	}
	key, e := install.ReadPrivateFile(s.privateFile, 64)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	result, e := s.authority.IssueControlEvidenceSource(ctx, key)
	if e != nil || result.OriginalDefinitionSHA256 == "" || !bytes.Equal(result.Source.Issuer, s.materials.ControlEvidenceSource.Issuer) || result.Source.Endpoint != s.materials.ControlEvidenceSource.Endpoint || result.Source.GrantFile != s.materials.ControlEvidenceSource.GrantFile || result.Source.ControllerGrantFile != s.materials.ControlEvidenceSource.ControllerGrantFile {
		return zero, install.ErrInstall
	}
	*s.materials.ControlEvidenceSource = result.Source
	return result, nil
}

func (s *OriginalCaptureSequence) QueryControlEvidenceSourceGrant(ctx context.Context) (_ install.ControlEvidenceSourceIssueResult, resultErr error) {
	var zero install.ControlEvidenceSourceIssueResult
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
	if s.authority == nil || s.authority.Recheck(ctx) != nil {
		return zero, install.ErrInstall
	}
	return s.authority.QueryControlEvidenceSource(ctx)
}
