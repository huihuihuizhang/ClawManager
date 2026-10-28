package systembackupsecurity

import (
	"context"
	"strings"
	"testing"
)

func TestConfigMutationRBACRequiresRepresentableAdminSubjects(t *testing.T) {
	for name, subject := range map[string]string{
		"ascii-overflow": strings.Repeat("s", 257),
		"utf8-overflow":  strings.Repeat("中", 86),
	} {
		t.Run(name, func(t *testing.T) {
			svc, actor, _, _, _ := mutationTransactionFixture(t)
			if !svc.valid(context.Background(), actor, "mutation_key_0123456789", "rbac-current") {
				t.Fatal("current authenticated actor fixture must be representable")
			}
			proposedActor := actor
			proposedActor.Subject = subject
			if svc.valid(context.Background(), proposedActor, "mutation_key_0123456789", "rbac-proposed") {
				t.Fatal("overflow subject must be outside the executor's actor domain")
			}
			old := configRBACFixture(t, "v1", [3]string{"42", actor.Subject, "security_admin"})
			proposed := configRBACFixture(t, "v2", [3]string{"42", subject, "security_admin"})
			if _, err := VerifyConfigMutationRBAC("installation_synthetic", actor, configWithRBAC(t, old, "v1"), configWithRBAC(t, proposed, "v2"), old, proposed, ConfigMutationRisk{}); err != ErrRegistrationUnavailable {
				t.Fatal("unrepresentable last admin counted as a usable binding", err)
			}
		})
	}
}

func TestConfigMutationRBACPreservesValidSubjectBoundary(t *testing.T) {
	for name, subject := range map[string]string{
		"ascii-256-bytes": strings.Repeat("s", 256),
		"utf8-256-bytes":  strings.Repeat("中", 85) + "s",
	} {
		t.Run(name, func(t *testing.T) {
			svc, actor, _, _, _ := mutationTransactionFixture(t)
			actor.Subject = subject
			if !svc.valid(context.Background(), actor, "mutation_key_0123456789", "rbac-boundary") {
				t.Fatal("boundary subject must be representable by executor")
			}
			raw := configRBACFixture(t, "v1", [3]string{"42", subject, "security_admin"})
			c := configWithRBAC(t, raw, "v1")
			r, err := VerifyConfigMutationRBAC("installation_synthetic", actor, c, c, raw, raw, ConfigMutationRisk{})
			if err != nil || r.Risk().StrongAuthRequired() {
				t.Fatal("valid boundary subject rejected", err)
			}
		})
	}
}
