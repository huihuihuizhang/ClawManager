package systembackupminioauthority

// These are closed source compatibility declarations, never observations,
// current permissions, image attestations or admission capabilities.
const SeptemberPermissionProfile = "minio-2025-09-07-builtin-flat.v1"
const SeptemberNativeObservationProfile = "minio-2025-09-07-six-principal-current-source.v1"

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
	}
	return NativeCompatibilityProfile{}, false
}

func nativeProviderVersion(p Provider) bool {
	for _, permission := range []string{PermissionProfile, SeptemberPermissionProfile} {
		profile, _ := NativeProfile(permission)
		if p.ServerVersion == profile.ServerVersion && p.ServerCommit == profile.ServerCommit {
			september, _ := NativeProfile(SeptemberPermissionProfile)
			return permission == PermissionProfile && p.IdentityProfile != september.Provider || permission == SeptemberPermissionProfile && p.IdentityProfile == profile.Provider
		}
	}
	return false
}

func nativeGrantProfile(g SQLGrant) bool {
	profile, ok := NativeProfile(g.PermissionSource.Profile)
	return ok && g.Provider.ServerVersion == profile.ServerVersion && g.Provider.ServerCommit == profile.ServerCommit &&
		g.Observation.Profile == profile.Observation &&
		(g.PermissionSource.Profile != SeptemberPermissionProfile || g.Provider.IdentityProfile == profile.Provider)
}

func nativeReferenceProfile(g SQLGrant, r Reference) bool {
	profile, _ := NativeProfile(SeptemberPermissionProfile)
	if g.PermissionSource.Profile != SeptemberPermissionProfile {
		return r.IdentityProfile != profile.Reference && r.ScopeProfile != profile.Scope && r.CapabilityProfile != profile.Protocol
	}
	return r.IdentityProfile == profile.Reference && r.ScopeProfile == profile.Scope && r.CapabilityProfile == profile.Protocol &&
		r.CapabilityIntentSHA256 == g.Observation.CapabilityIntentSHA256 && (r.Purpose != ArtifactRead || r.Capability == "range_read")
}
