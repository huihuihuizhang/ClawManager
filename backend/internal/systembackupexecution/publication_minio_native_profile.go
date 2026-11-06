package systembackupexecution

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	"k8s.io/client-go/kubernetes"
)

func minioNativeProfile(permission string) (ma.NativeCompatibilityProfile, bool) {
	return ma.NativeProfile(permission)
}

func (r *minioPermissionHTTP) collectNativeProfile(ctx context.Context, cfg minioPermissionConfiguration, uses []minioPermissionUse, permission string) (string, error) {
	profile, ok := minioNativeProfile(permission)
	if !ok || cfg.Version != profile.Source {
		return "", minioPermissionFailure("native-profile-collector-source-pair")
	}
	switch permission {
	case ma.PermissionProfile:
		return r.collectV2(ctx, cfg, uses)
	case ma.SeptemberPermissionProfile, ma.DeleteCompatPermissionProfile:
		return r.collectBuiltinFlat(ctx, cfg, uses, permission)
	}
	return "", minioPermissionFailure("unsupported-native-profile")
}

// Explicit September opt-in API for the composition owner. The April v2
// constructor and main wiring retain their existing accepted source version.
func NewMinIOSeptemberEffectivePublicationPermissionReader(input MinIOPublicationPermissionInput) (*MinIOPublicationPermissionReader, error) {
	return newMinIOBuiltinFlatPermissionReader(input, ma.SeptemberPermissionProfile)
}

func newMinIOProfilePermissionReader(input MinIOPublicationPermissionInput, permission string) (*MinIOPublicationPermissionReader, error) {
	switch permission {
	case ma.PermissionProfile:
		return NewMinIOEffectivePublicationPermissionV2Reader(input)
	case ma.SeptemberPermissionProfile, ma.DeleteCompatPermissionProfile:
		return newMinIOBuiltinFlatPermissionReader(input, permission)
	}
	return nil, minioPermissionFailure("unsupported-native-source-profile")
}

func minioCurrentProfileOwner(r *MinIOPublicationPermissionReader, permission string, ctx context.Context, k kubernetes.Interface, now time.Time) (minioPermissionOwnerState, error) {
	if r == nil {
		return minioPermissionOwnerState{}, minioPermissionFailure("native-profile-reader")
	}
	profile, ok := minioNativeProfile(permission)
	if !ok || r.configuration.Version != profile.Source {
		return minioPermissionOwnerState{}, minioPermissionFailure("native-profile-source-pair")
	}
	if permission == ma.PermissionProfile {
		return r.effectiveOwnerV2(ctx, k, now)
	}
	return r.effectiveOwnerBuiltinFlat(ctx, k, now, permission)
}

// Separate closed September Admin response contract. Only bounded usage/stats
// are ignored; each admitted identity field and single server are explicit.
// Actual TLS, owner/config state, six policies and protocol checks are still
// mandatory: this predicate alone never creates a fresh source observation.
func (r *minioPermissionHTTP) serverSeptember(ctx context.Context) (string, error) {
	return r.serverBuiltinFlat(ctx, ma.SeptemberPermissionProfile)
}

func (r *minioPermissionHTTP) serverBuiltinFlat(ctx context.Context, permission string) (string, error) {
	if !ma.MatchesBuiltinFlatImage(permission, r.provider.ImageID) {
		return "", minioPermissionFailure("builtin-flat-provider-image")
	}
	raw, status, err := r.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	if err != nil || status != http.StatusOK || minioPermissionUniqueJSON(raw) != nil {
		return "", minioPermissionFailure("september-native-server-info")
	}
	var info struct {
		DeploymentID string `json:"deploymentID"`
		Region       string `json:"region"`
		Servers      []struct {
			State   string `json:"state"`
			Version string `json:"version"`
			Commit  string `json:"commitID"`
		} `json:"servers"`
	}
	if json.Unmarshal(raw, &info) != nil || info.DeploymentID != r.provider.DeploymentID || info.Region != r.provider.Region || len(info.Servers) != 1 {
		return "", minioPermissionFailure("september-native-server-identity")
	}
	s := info.Servers[0]
	if s.State != "online" || !ma.MatchesNativeServer(permission, s.Version, s.Commit) {
		return "", minioPermissionFailure("september-native-release-contract")
	}
	stable, err := ce.Canonical(info)
	if err != nil {
		return "", err
	}
	return hash(stable), nil
}
