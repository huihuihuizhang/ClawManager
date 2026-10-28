package systembackupsecurity

import (
	"reflect"
	"strconv"
	"unicode/utf8"
)

// ConfigMutationRBAC is an immutable server-side comparison, not a write grant.
// It does NOT authenticate sessions, resolve refs, verify MFA, reserve capacity,
// consume nonce or commit. The runtime authority still owns those boundaries.
type ConfigMutationRBAC struct {
	risk     ConfigMutationRisk
	required []string
}

func (r ConfigMutationRBAC) Risk() ConfigMutationRisk { return r.risk }
func (r ConfigMutationRBAC) RequiredPermissions() []string {
	return append([]string(nil), r.required...)
}
func (ConfigMutationRBAC) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }

type configMutationRoleBinding struct{ subject, role string }

// VerifyConfigMutationRBAC checks exact registry bytes against the two fully
// decoded ConfigValues pins. Hash/version changes alone do not classify a
// security change: role/subject contents are compared without array-order bias.
// installation/actor must come from the independently authenticated runtime.
// extraRisk is the trusted resolver's classification of OTHER registry facts.
func VerifyConfigMutationRBAC(installation string, actor RegistrationActor, current, proposed ConfigValues, currentRegistry, proposedRegistry []byte, extraRisk ConfigMutationRisk) (ConfigMutationRBAC, error) {
	zero := ConfigMutationRBAC{}
	if !configMutationInstallation.MatchString(installation) || actor.UserID < 1 || actor.Subject == "" || len(actor.Subject) > 256 || !utf8.ValidString(actor.Subject) || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 {
		return zero, ErrRegistrationUnavailable
	}
	oldPin, newPin := configMutationRBACPin(current), configMutationRBACPin(proposed)
	// Own copies are retained before any registry parsing; no adapter callback
	// can turn the later semantic comparison into a comparison of mutated input.
	oldBytes, newBytes := append([]byte(nil), currentRegistry...), append([]byte(nil), proposedRegistry...)
	oldBindings, oldAdmins, err := configMutationRoleBindings(oldBytes, oldPin, installation)
	if err != nil || oldAdmins == 0 {
		return zero, ErrRegistrationUnavailable
	}
	newBindings, newAdmins, err := configMutationRoleBindings(newBytes, newPin, installation)
	if err != nil {
		return zero, err
	}
	if newAdmins == 0 {
		return zero, ErrRegistrationPermission
	}
	actorID := strconv.FormatInt(actor.UserID, 10)
	oldSelf, newSelf := oldBindings[actorID], newBindings[actorID]
	// Check by stable actor ID even when proposed subject mapping also changes.
	// A caller cannot obtain security/destructive on the next login by changing
	// both their own subject and role in the same request.
	if oldSelf.role != "security_admin" && newSelf.role == "security_admin" {
		return zero, ErrRegistrationPermission
	}
	risk := configMutationBaseRisk(current, proposed)
	risk.SecurityBoundary = risk.SecurityBoundary || extraRisk.SecurityBoundary || !reflect.DeepEqual(oldBindings, newBindings)
	risk.ProtectionReduction = risk.ProtectionReduction || extraRisk.ProtectionReduction
	required := []string{"system_backup.configure"}
	if risk.SecurityBoundary {
		required = append(required, "system_backup.security_configure")
	}
	if risk.ProtectionReduction {
		required = append(required, "system_backup.destructive")
	}
	if err = AuthorizeEvidencePermissions(oldBytes, oldPin.SHA256, oldPin.Version, installation, actor, required); err != nil {
		return zero, err
	}
	return ConfigMutationRBAC{risk, required}, nil
}

func configMutationRBACPin(c ConfigValues) BootstrapRegistryRef {
	for _, r := range c.Registries() {
		if r.Kind == "rbac_bindings" {
			return r
		}
	}
	return BootstrapRegistryRef{}
}
func configMutationRoleBindings(raw []byte, pin BootstrapRegistryRef, installation string) (map[string]configMutationRoleBinding, int, error) {
	var registry RegistrationRBACRegistry
	if pin.Kind != "rbac_bindings" || decodePinnedRegistry(raw, pin.SHA256, &registry) != nil || registry.SchemaVersion != "system-backup-registration-rbac.draft.v1" || registry.Version != pin.Version || registry.InstallationID != installation || len(registry.Bindings) > 10000 {
		return nil, 0, ErrRegistrationUnavailable
	}
	bindings := map[string]configMutationRoleBinding{}
	admins := 0
	for _, binding := range registry.Bindings {
		id, err := strconv.ParseInt(binding.ActorID, 10, 64)
		if err != nil || id < 1 || strconv.FormatInt(id, 10) != binding.ActorID || binding.Subject == "" || len(binding.Subject) > 256 || !utf8.ValidString(binding.Subject) || !contains([]string{"viewer", "operator", "config_admin", "security_admin"}, binding.Role) {
			return nil, 0, ErrRegistrationUnavailable
		}
		if _, exists := bindings[binding.ActorID]; exists {
			return nil, 0, ErrRegistrationUnavailable
		}
		bindings[binding.ActorID] = configMutationRoleBinding{binding.Subject, binding.Role}
		if binding.Role == "security_admin" {
			admins++
		}
	}
	return bindings, admins, nil
}
