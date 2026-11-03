package install

import ma "clawreef/internal/systembackupminioauthority"

func minioPermissionDefinitionProfile(d MinIOPermissionDefinition) bool {
	profile, ok := ma.NativeProfile(d.Grant.Profile)
	return ok && d.Version == profile.Definition
}
