package systembackupminioauthority

import "strings"

// These are closed source compatibility declarations, never observations,
// current permissions, image attestations or admission capabilities.
const SeptemberPermissionProfile = "minio-2025-09-07-builtin-flat.v1"
const SeptemberNativeObservationProfile = "minio-2025-09-07-six-principal-current-source.v1"

const DeleteCompatPermissionProfile = "minio-2026-11-05-delete-compat-builtin-flat.v1"
const DeleteCompatNativeObservationProfile = "minio-2026-11-05-delete-compat-six-principal-current-source.v1"
const DeleteCompatImageManifest = "sha256:b01b328707219c9d27f818583e0aef896a10e7580e59ad5bb2930a6965969548"

// MatchesDeleteCompatImageID accepts the observed manifest ID and immutable
// repository references carrying exactly that manifest.
func MatchesDeleteCompatImageID(imageID string) bool {
	return imageID == DeleteCompatImageManifest || MatchesDeleteCompatImageReference(strings.TrimPrefix(imageID, "docker-pullable://"))
}

func MatchesDeleteCompatImageReference(image string) bool {
	repository, digest, ok := strings.Cut(image, "@")
	return ok && repository != "" && !strings.ContainsAny(repository, " \t\r\n?#\\") &&
		!strings.Contains(repository, "://") && digest == DeleteCompatImageManifest
}

// MatchesBuiltinFlatImage keeps the patched image on its separate source row.
func MatchesBuiltinFlatImage(permission, imageID string) bool {
	switch permission {
	case SeptemberPermissionProfile:
		return !MatchesDeleteCompatImageID(imageID)
	case DeleteCompatPermissionProfile:
		return MatchesDeleteCompatImageID(imageID)
	default:
		return false
	}
}

type NativeCompatibilityProfile struct {
	Permission, Observation, Definition, Source string
	ServerVersion, ServerCommit                 string
	Provider, Reference, Scope, Protocol        string
}

func NativeProfile(permission string) (NativeCompatibilityProfile, bool) {
	switch permission {
	case PermissionProfile:
		return NativeCompatibilityProfile{PermissionProfile, NativeObservationProfile,
			"original-minio-permission-definition.v2", "minio-publication-effective-permission-source.v2",
			"2025-04-22T22:12:26Z", "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e",
			"original-minio-terminal-provider.v1", "original-minio-terminal-reference.v1",
			"original-minio-terminal-scope.v1", "original-minio-terminal-s3-protocol.v1"}, true
	case SeptemberPermissionProfile:
		return NativeCompatibilityProfile{SeptemberPermissionProfile, SeptemberNativeObservationProfile,
			"original-minio-september-permission-definition.v1", "minio-publication-september-effective-permission-source.v1",
			"2025-09-07T16:13:09Z", "07c3a429bfed433e49018cb0f78a52145d4bedeb",
			"original-minio-september-terminal-provider.v1", "original-minio-september-terminal-reference.v1",
			"original-minio-september-terminal-scope.v1", "original-minio-september-terminal-s3-protocol.v1"}, true
	case DeleteCompatPermissionProfile:
		return NativeCompatibilityProfile{DeleteCompatPermissionProfile, DeleteCompatNativeObservationProfile,
			"original-minio-delete-compat-permission-definition.v1", "minio-publication-delete-compat-effective-permission-source.v1",
			"2026-11-05T07:23:54Z", "0f7c8e3a781129ddbf1c7a6ce834727ff5efdedb",
			"original-minio-delete-compat-terminal-provider.v1", "original-minio-delete-compat-terminal-reference.v1",
			"original-minio-delete-compat-terminal-scope.v1", "original-minio-delete-compat-terminal-s3-protocol.v1"}, true
	}
	return NativeCompatibilityProfile{}, false
}

// MatchesNativeServer compares an observed tuple with the named, closed profile.
// Callers still check the online state, deployment identity, and image binding.
func MatchesNativeServer(permission, version, commit string) bool {
	profile, ok := NativeProfile(permission)
	return ok && version == profile.ServerVersion && commit == profile.ServerCommit
}

func nativeProviderVersion(p Provider) bool {
	for _, permission := range []string{PermissionProfile, SeptemberPermissionProfile, DeleteCompatPermissionProfile} {
		if MatchesNativeServer(permission, p.ServerVersion, p.ServerCommit) && nativeProviderProfile(permission, p) {
			return true
		}
	}
	return false
}

func nativeProviderProfile(permission string, p Provider) bool {
	profile, ok := NativeProfile(permission)
	if !ok {
		return false
	}
	if permission == PermissionProfile {
		september, _ := NativeProfile(SeptemberPermissionProfile)
		compat, _ := NativeProfile(DeleteCompatPermissionProfile)
		return p.IdentityProfile != september.Provider && p.IdentityProfile != compat.Provider && !MatchesDeleteCompatImageID(p.ImageID)
	}
	return p.IdentityProfile == profile.Provider && MatchesBuiltinFlatImage(permission, p.ImageID)
}

func nativeGrantProfile(g SQLGrant) bool {
	permission := g.PermissionSource.Profile
	profile, ok := NativeProfile(permission)
	return ok && MatchesNativeServer(permission, g.Provider.ServerVersion, g.Provider.ServerCommit) &&
		g.Observation.Profile == profile.Observation && nativeProviderProfile(permission, g.Provider)
}

func nativeReferenceProfile(g SQLGrant, r Reference) bool {
	permission := g.PermissionSource.Profile
	profile, ok := NativeProfile(permission)
	if !ok {
		return false
	}
	if permission == PermissionProfile {
		for _, other := range []string{SeptemberPermissionProfile, DeleteCompatPermissionProfile} {
			p, _ := NativeProfile(other)
			if r.IdentityProfile == p.Reference || r.ScopeProfile == p.Scope || r.CapabilityProfile == p.Protocol {
				return false
			}
		}
		return true
	}
	return r.IdentityProfile == profile.Reference && r.ScopeProfile == profile.Scope && r.CapabilityProfile == profile.Protocol &&
		r.CapabilityIntentSHA256 == g.Observation.CapabilityIntentSHA256 && (r.Purpose != ArtifactRead || r.Capability == "range_read")
}
