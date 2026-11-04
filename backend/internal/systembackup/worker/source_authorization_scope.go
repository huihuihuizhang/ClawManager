package worker

import (
	"context"

	ce "clawreef/internal/systembackupcontrolevidence"
	k "clawreef/internal/systembackupkms"
)

// This selects comparison DATA from an original frozen invocation. It does not
// authenticate SQL succession or create a source/key-use authority. The actual
// controller producer must derive the extra pin from its real SQL lineage;
// OpenFormalCaptureSources/OpenControlEvidenceCaptureSources still require the
// genuine current CaptureKeyJob, exact original invocation hash and Recheck.
func formalSourceAuthorizationConfigSHA256(i Invocation) (string, error) {
	if i.FormalCapture == nil || !keyUseHash.MatchString(i.FormalCapture.SourceConfigSHA256) {
		return "", ErrNotReady
	}
	current := i.FormalCapture.SourceConfigSHA256
	if i.FormalCapture.SourceAuthorizationConfigSHA256 == "" {
		return current, nil
	}
	if !validFormalInvocation(i) {
		return "", ErrNotReady
	}
	return i.FormalCapture.SourceAuthorizationConfigSHA256, nil
}

// ControlEvidenceSourceAuthorizationExpected is an original-grant comparison
// projection only. The actual CE payload Expected, task configuration and CD
// description remain the CURRENT configuration and are never rewritten here.
func ControlEvidenceSourceAuthorizationExpected(i Invocation) (ce.Expected, error) {
	if i.Request.ControlEvidence == nil || !validControlEvidenceRequest(i.Request) || i.FormalCapture == nil || i.FormalCapture.SourceConfigSHA256 != i.Request.ControlEvidence.Expected.ConfigSHA256 {
		return ce.Expected{}, ErrNotReady
	}
	authorizationSHA, err := formalSourceAuthorizationConfigSHA256(i)
	if err != nil {
		return ce.Expected{}, err
	}
	expected := i.Request.ControlEvidence.Expected
	expected.ConfigSHA256 = authorizationSHA
	return expected, nil
}

// ReadControlEvidenceInvocationSourceGrant retains the original independent
// source signature, scope, workload, revocation and Until checks. Callers MUST
// first authenticate the actual original invocation/current job. This returns
// comparison data, just like ReadControlEvidenceSourceGrant; it mints no grant.
func ReadControlEvidenceInvocationSourceGrant(ctx context.Context, mount ControlEvidenceSourceMount, i Invocation, identity k.JobIdentity, controller bool) (ControlEvidenceSourceGrant, error) {
	expected, err := ControlEvidenceSourceAuthorizationExpected(i)
	if err != nil {
		return ControlEvidenceSourceGrant{}, err
	}
	return ReadControlEvidenceSourceGrant(ctx, mount, expected, identity, controller)
}
