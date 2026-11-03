package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"

	d "clawreef/internal/systembackupdispatch"
	ma "clawreef/internal/systembackupminioauthority"
)

// Retain the SAME concrete C observations the existing combined-v2 entry
// obtains, including its private owner/resource/native identities. The public
// combined entry returns only time bounds, which cannot detect replacement
// between two complete runtime passes. No C protocol/permission rule changes.
func (s *DeploymentService) observeRuntimePublicationSources(ctx context.Context, input RuntimeReadinessInput) (PublicationDependencyObservation, string, error) {
	var zero PublicationDependencyObservation
	base, err := s.CheckPublicationDependencies(ctx)
	// The base deliberately returns this precise missing-provider sentinel
	// alongside COMPLETE base facts. Only the real effective-v2 reader below
	// can discharge it; every other error or zero/partial base is rejected.
	if err != nil && !errors.Is(err, ErrPublicationProviderPermissionObservationMissing) {
		return zero, "", err
	}
	if base.checkedAt.IsZero() {
		return zero, "", d.ErrNotReady
	}
	reader, err := newRuntimeReadinessPermissionReader(input)
	if err != nil {
		return zero, "", err
	}
	var provider MinIOPublicationPermissionObservation
	switch input.Profile {
	case ma.PermissionProfile:
		provider, err = reader.CheckCurrentEffectiveV2(ctx, s)
	case ma.SeptemberPermissionProfile:
		provider, err = reader.CheckCurrentEffectiveSeptember(ctx, s)
	default:
		return zero, "", d.ErrNotReady
	}
	if err != nil {
		return zero, "", err
	}
	window := publicationDependencyWindow{notBefore: base.notBefore, until: base.until}
	if provider.checkedAt.Before(base.checkedAt) || window.include(provider.checkedAt, provider.notBefore, provider.until) != nil {
		return zero, "", d.ErrNotReady
	}
	stamp, err := runtimePublicationSourceStamp(provider, input.Profile)
	if err != nil {
		return zero, "", err
	}
	return PublicationDependencyObservation{checkedAt: provider.checkedAt, notBefore: window.notBefore, until: window.until}, stamp, nil
}

// Identity projection DATA, not a constructor of permission. Observation time
// may advance; its original source/native identities may not change mid-attempt.
func runtimePublicationSourceStamp(provider MinIOPublicationPermissionObservation, profile string) (string, error) {
	if profile != ma.PermissionProfile && profile != ma.SeptemberPermissionProfile {
		return "", d.ErrNotReady
	}
	for _, value := range []string{provider.configuration, provider.owner, provider.resources, provider.native} {
		if !formalCandidateDigest(value) {
			return "", d.ErrNotReady
		}
	}
	raw, err := json.Marshal(struct{ Profile, Configuration, Owner, Resources, Native string }{profile, provider.configuration, provider.owner, provider.resources, provider.native})
	if err != nil {
		return "", d.ErrNotReady
	}
	return hash(raw), nil
}
