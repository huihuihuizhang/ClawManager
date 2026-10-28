package systembackupsecurity

import "strconv"

// AuthorizeEvidencePermissions applies v12's fixed role mapping to the same
// hash-pinned RBAC wire profile used by registration. This is only RBAC;
// callers must check the live session and owner visibility in their transaction.
func AuthorizeEvidencePermissions(raw []byte, digest, version, installation string, actor RegistrationActor, required []string) error {
	var registry RegistrationRBACRegistry
	if decodePinnedRegistry(raw, digest, &registry) != nil || registry.SchemaVersion != "system-backup-registration-rbac.draft.v1" ||
		registry.Version != version || registry.InstallationID != installation || len(registry.Bindings) > 10000 || len(required) == 0 {
		return ErrRegistrationUnavailable
	}
	seen := map[string]bool{}
	role := ""
	for _, binding := range registry.Bindings {
		id, err := strconv.ParseInt(binding.ActorID, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != binding.ActorID || binding.Subject == "" || seen[binding.ActorID] ||
			!contains([]string{"viewer", "operator", "config_admin", "security_admin"}, binding.Role) {
			return ErrRegistrationUnavailable
		}
		seen[binding.ActorID] = true
		if id == actor.UserID && binding.Subject == actor.Subject {
			role = binding.Role
		}
	}
	for _, permission := range required {
		allowed := false
		switch permission {
		case "system_backup.read":
			allowed = role != ""
		case "system_backup.operate":
			allowed = role == "operator" || role == "security_admin"
		case "system_backup.configure":
			allowed = role == "config_admin" || role == "security_admin"
		case "system_backup.security_configure", "system_backup.destructive":
			allowed = role == "security_admin"
		}
		if !allowed {
			return ErrRegistrationPermission
		}
	}
	return nil
}
