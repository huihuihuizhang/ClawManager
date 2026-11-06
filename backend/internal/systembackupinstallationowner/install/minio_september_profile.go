package install

import ma "clawreef/internal/systembackupminioauthority"

func minioPermissionDefinitionProfile(d MinIOPermissionDefinition) bool {
	profile, ok := ma.NativeProfile(d.Grant.Profile)
	return ok && d.Version == profile.Definition &&
		(d.Grant.Profile == ma.PermissionProfile && !ma.MatchesDeleteCompatImageID(d.Grant.Provider.ImageID) ||
			ma.MatchesBuiltinFlatImage(d.Grant.Profile, d.Grant.Provider.ImageID))
}
