package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func configRBACFixture(t *testing.T, version string, bindings ...[3]string) []byte {
	t.Helper()
	entries := []map[string]string{}
	for _, b := range bindings {
		entries = append(entries, map[string]string{"actor_id": b[0], "subject": b[1], "role": b[2]})
	}
	raw, err := json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": version, "installation_id": "installation_synthetic", "bindings": entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func configWithRBAC(t *testing.T, raw []byte, version string) ConfigValues {
	t.Helper()
	var doc map[string]json.RawMessage
	if json.Unmarshal(bootstrapFixture(t), &doc) != nil {
		t.Fatal("config fixture")
	}
	var refs []BootstrapRegistryRef
	if json.Unmarshal(doc["registries"], &refs) != nil {
		t.Fatal("registry fixture")
	}
	for i := range refs {
		if refs[i].Kind == "rbac_bindings" {
			refs[i].Version = version
			refs[i].SHA256 = registrationHash(string(raw))
		}
	}
	doc["registries"], _ = json.Marshal(refs)
	encoded, _ := json.Marshal(doc)
	c, err := DecodeConfigValues(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigMutationRBACCurrentPermissionsAndSemanticComparison(t *testing.T) {
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	for _, role := range []string{"viewer", "operator", "config_admin", "security_admin"} {
		t.Run(role, func(t *testing.T) {
			old := configRBACFixture(t, "v1", [3]string{"42", "user:42", role}, [3]string{"7", "user:7", "security_admin"})
			// Different exact version/hash and reversed array order; same bindings.
			next := configRBACFixture(t, "v2", [3]string{"7", "user:7", "security_admin"}, [3]string{"42", "user:42", role})
			r, err := VerifyConfigMutationRBAC("installation_synthetic", actor, configWithRBAC(t, old, "v1"), configWithRBAC(t, next, "v2"), old, next, ConfigMutationRisk{})
			if role == "viewer" || role == "operator" {
				if err != ErrRegistrationPermission {
					t.Fatal("unprivileged config", err)
				}
				return
			}
			if err != nil || r.Risk().StrongAuthRequired() || !reflect.DeepEqual(r.RequiredPermissions(), []string{"system_backup.configure"}) {
				t.Fatal("metadata/order falsely changed security", r, err)
			}
			copy := r.RequiredPermissions()
			copy[0] = "tampered"
			if r.RequiredPermissions()[0] != "system_backup.configure" {
				t.Fatal("mutable permissions")
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("comparison serialized as authority receipt")
			}
		})
	}
}
func TestConfigMutationRBACSelfGrantLastAdminAndOtherBindingChanges(t *testing.T) {
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	for _, name := range []string{"self-grant", "subject-and-self-grant", "last-admin", "other-binding-config-admin", "other-binding-security-admin", "self-demotion"} {
		t.Run(name, func(t *testing.T) {
			oldRole, nextRole := "config_admin", "config_admin"
			oldOther, nextOther := "security_admin", "security_admin"
			nextSubject := "user:42"
			switch name {
			case "self-grant":
				nextRole = "security_admin"
			case "subject-and-self-grant":
				nextRole = "security_admin"
				nextSubject = "new:subject"
			case "last-admin":
				oldRole = "security_admin"
				nextRole = "viewer"
				oldOther = "viewer"
				nextOther = "viewer"
			case "other-binding-config-admin":
				nextOther = "viewer"
			case "other-binding-security-admin":
				oldRole = "security_admin"
				nextRole = "security_admin"
				nextOther = "viewer"
			case "self-demotion":
				oldRole = "security_admin"
				nextRole = "operator"
			}
			oldSet := [][3]string{{"42", "user:42", oldRole}, {"7", "user:7", oldOther}}
			nextSet := [][3]string{{"42", nextSubject, nextRole}, {"7", "user:7", nextOther}}
			if name == "other-binding-config-admin" {
				oldSet = append(oldSet, [3]string{"8", "user:8", "security_admin"})
				nextSet = append(nextSet, [3]string{"8", "user:8", "security_admin"})
			}
			old := configRBACFixture(t, "v1", oldSet...)
			next := configRBACFixture(t, "v2", nextSet...)
			r, err := VerifyConfigMutationRBAC("installation_synthetic", actor, configWithRBAC(t, old, "v1"), configWithRBAC(t, next, "v2"), old, next, ConfigMutationRisk{})
			allowed := name == "other-binding-security-admin" || name == "self-demotion"
			if allowed {
				if err != nil || !r.Risk().SecurityBoundary || !r.Risk().StrongAuthRequired() {
					t.Fatal("authorized security change", err)
				}
			} else if err != ErrRegistrationPermission {
				t.Fatal("unsafe transition", name, err)
			}
		})
	}
}
func TestConfigMutationRBACProtectionAndResolverRisk(t *testing.T) {
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	for _, role := range []string{"config_admin", "security_admin"} {
		for _, name := range []string{"retention", "resolved-security", "resolved-reduction"} {
			t.Run(role+"/"+name, func(t *testing.T) {
				raw := configRBACFixture(t, "v1", [3]string{"42", "user:42", role}, [3]string{"7", "user:7", "security_admin"})
				old := configWithRBAC(t, raw, "v1")
				next := old
				extra := ConfigMutationRisk{}
				switch name {
				case "retention":
					changed := bytes.Replace(old.CanonicalJSON(), []byte(`"retention_seconds":2592000`), []byte(`"retention_seconds":86400`), 1)
					var err error
					next, err = DecodeConfigValues(changed)
					if err != nil {
						t.Fatal(err)
					}
				case "resolved-security":
					extra.SecurityBoundary = true
				case "resolved-reduction":
					extra.ProtectionReduction = true
				}
				r, err := VerifyConfigMutationRBAC("installation_synthetic", actor, old, next, raw, raw, extra)
				if role == "config_admin" {
					if err != ErrRegistrationPermission {
						t.Fatal("conditional permission omitted", err)
					}
					return
				}
				if err != nil || !r.Risk().StrongAuthRequired() || len(r.RequiredPermissions()) != 2 {
					t.Fatal("required additional permission", err, r)
				}
			})
		}
	}
}
func TestConfigMutationRBACRejectsUnpinnedAndMalformedRegistries(t *testing.T) {
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	good := configRBACFixture(t, "v1", [3]string{"42", "user:42", "security_admin"})
	for name, raw := range map[string][]byte{
		"duplicate-actor":        configRBACFixture(t, "v1", [3]string{"42", "user:42", "security_admin"}, [3]string{"42", "other", "viewer"}),
		"noncanonical-actor":     configRBACFixture(t, "v1", [3]string{"042", "user:42", "security_admin"}),
		"unknown-role":           configRBACFixture(t, "v1", [3]string{"42", "user:42", "owner"}),
		"foreign-installation":   bytes.Replace(good, []byte("installation_synthetic"), []byte("installation_foreign"), 1),
		"built-in-role-override": append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"roles":{"viewer":["system_backup.destructive"]}}`)...),
		"null-bindings":          []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"v1","installation_id":"installation_synthetic","bindings":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyConfigMutationRBAC("installation_synthetic", actor, configWithRBAC(t, good, "v1"), configWithRBAC(t, raw, "v1"), good, raw, ConfigMutationRisk{})
			if err != ErrRegistrationUnavailable {
				t.Fatal("malformed registry accepted", err)
			}
		})
	}
	c := configWithRBAC(t, good, "v1")
	if _, err := VerifyConfigMutationRBAC("installation_synthetic", actor, c, c, good, append(append([]byte(nil), good...), byte(' ')), ConfigMutationRisk{}); err != ErrRegistrationUnavailable {
		t.Fatal("wrong exact bytes accepted", err)
	}
	if _, err := VerifyConfigMutationRBAC("installation_synthetic", actor, ConfigValues{}, c, good, good, ConfigMutationRisk{}); err != ErrRegistrationUnavailable {
		t.Fatal("zero config accepted")
	}
	actor.Subject = "other-subject"
	if _, err := VerifyConfigMutationRBAC("installation_synthetic", actor, c, c, good, good, ConfigMutationRisk{}); err != ErrRegistrationPermission {
		t.Fatal("foreign subject accepted", err)
	}
}
