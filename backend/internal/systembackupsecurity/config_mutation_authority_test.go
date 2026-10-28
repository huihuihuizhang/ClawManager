package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// These doubles verify boundary wiring and RBAC. They are not current session,
// MFA or capacity implementations and are never used outside unit tests.
func mutationAuthoritySourcesFixture(t *testing.T, tx *sql.Tx, old, next []byte) ConfigMutationAuthoritySources {
	t.Helper()
	shared := make([]byte, 0, 4096)
	return ConfigMutationAuthoritySources{
		CheckSession: func(_ context.Context, got *sql.Tx, installation string, _ RegistrationActor, _ time.Time) error {
			if got != tx || installation != "installation_synthetic" {
				return errors.New("wrong binding")
			}
			return nil
		},
		RegistryBytes: func(kind, version, digest string) ([]byte, error) {
			raw := old
			if version == "v2" {
				raw = next
			}
			if kind != "rbac_bindings" || registrationHash(string(raw)) != digest {
				return nil, errors.New("bad registry binding")
			}
			shared = append(shared[:0], raw...)
			return shared, nil
		},
		StrongAuth: func(context.Context, *sql.Tx, RegistrationActor, string, ConfigValues, []string, time.Time) (VerifyConfig, error) {
			return VerifyConfig{}, ErrRegistrationUnavailable
		},
		ReserveMetadata: func(_ context.Context, got *sql.Tx, _, _ ConfigValues, _ int, now time.Time) (ConfigMutationCapacityReservation, error) {
			if got != tx {
				return nil, errors.New("wrong transaction")
			}
			return &mutationTestCapacity{tx: tx, until: now.Add(time.Minute)}, nil
		},
		RedactReason: func(_ context.Context, reason *string) (*string, error) { return reason, nil },
	}
}
func TestConfigMutationAuthorityRequiresEveryTrustedSource(t *testing.T) {
	for _, missing := range []string{"session", "registries", "strong-auth", "capacity", "redaction", "installation"} {
		t.Run(missing, func(t *testing.T) {
			tx := &sql.Tx{}
			s := mutationAuthoritySourcesFixture(t, tx, nil, nil)
			installation := "installation_synthetic"
			switch missing {
			case "session":
				s.CheckSession = nil
			case "registries":
				s.RegistryBytes = nil
			case "strong-auth":
				s.StrongAuth = nil
			case "capacity":
				s.ReserveMetadata = nil
			case "redaction":
				s.RedactReason = nil
			case "installation":
				installation = "foreign"
			}
			if a, err := NewPinnedConfigMutationAuthority(installation, s); err != ErrRegistrationUnavailable || a != nil {
				t.Fatal("incomplete runtime accepted", err)
			}
		})
	}
}
func TestConfigMutationAuthorityRejectsMissedRiskAndAllowsClassifiedMFAPath(t *testing.T) {
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	old := configRBACFixture(t, "v1", [3]string{"42", "user:42", "security_admin"}, [3]string{"7", "user:7", "viewer"})
	next := configRBACFixture(t, "v2", [3]string{"42", "user:42", "security_admin"}, [3]string{"7", "user:7", "operator"})
	tx := &sql.Tx{}
	s := mutationAuthoritySourcesFixture(t, tx, old, next)
	a, err := NewPinnedConfigMutationAuthority("installation_synthetic", s)
	if err != nil {
		t.Fatal(err)
	}
	current, proposed := configWithRBAC(t, old, "v1"), configWithRBAC(t, next, "v2")
	now := time.Now().UTC()
	if err = a.Authorize(context.Background(), tx, actor, "installation_synthetic", current, proposed, ConfigMutationRisk{}, now); err != ErrRegistrationUnavailable {
		t.Fatal("privileged caller bypassed MFA risk classification", err)
	}
	if err = a.Authorize(context.Background(), tx, actor, "installation_synthetic", current, proposed, ConfigMutationRisk{SecurityBoundary: true}, now); err != nil {
		t.Fatal("classified change rejected or shared bytes not frozen", err)
	}
	if err = a.Authorize(context.Background(), tx, actor, "installation_foreign", current, proposed, ConfigMutationRisk{SecurityBoundary: true}, now); err != ErrRegistrationUnavailable {
		t.Fatal("foreign installation accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = a.Authorize(ctx, tx, actor, "installation_synthetic", current, proposed, ConfigMutationRisk{}, now); err != ErrRegistrationUnavailable {
		t.Fatal("canceled authorization accepted", err)
	}
}
func TestConfigMutationAuthorityDelegationCopiesInputsAndRedactsErrors(t *testing.T) {
	tx := &sql.Tx{}
	raw := configRBACFixture(t, "v1", [3]string{"42", "user:42", "security_admin"})
	c := configWithRBAC(t, raw, "v1")
	actor := RegistrationActor{UserID: 42, Subject: "user:42"}
	now := time.Now().UTC()
	s := mutationAuthoritySourcesFixture(t, tx, raw, raw)
	called := false
	s.StrongAuth = func(_ context.Context, got *sql.Tx, _ RegistrationActor, installation string, _ ConfigValues, versions []string, _ time.Time) (VerifyConfig, error) {
		if got != tx || installation != "installation_synthetic" {
			return VerifyConfig{}, errors.New("wrong scope")
		}
		versions[0] = "mutated"
		called = true
		return VerifyConfig{ExpectedAudience: "synthetic"}, nil
	}
	a, err := NewPinnedConfigMutationAuthority("installation_synthetic", s)
	if err != nil {
		t.Fatal(err)
	}
	versions := []string{"old", "v1"}
	if _, err = a.StrongAuth(context.Background(), tx, actor, "installation_synthetic", c, versions, now); err != nil || !called || versions[0] != "old" {
		t.Fatal("key snapshot alias", err)
	}
	if _, err = a.Reserve(context.Background(), tx, c, c, 100000, now); err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(context.Background(), tx, c, c, 0, now); err != ErrRegistrationUnavailable {
		t.Fatal("invalid reservation accepted", err)
	}
	reason := "reviewed"
	redacted, err := a.RedactReason(context.Background(), &reason)
	if err != nil {
		t.Fatal(err)
	}
	*redacted = "changed"
	if reason != "reviewed" {
		t.Fatal("reason aliases caller")
	}
	s.ReserveMetadata = func(context.Context, *sql.Tx, ConfigValues, ConfigValues, int, time.Time) (ConfigMutationCapacityReservation, error) {
		return nil, errors.New("PRIVATE capacity details")
	}
	s.RedactReason = func(context.Context, *string) (*string, error) { return nil, errors.New("PRIVATE redaction details") }
	a, err = NewPinnedConfigMutationAuthority("installation_synthetic", s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Reserve(context.Background(), tx, c, c, 100000, now); err != ErrRegistrationUnavailable {
		t.Fatal("private capacity error escaped", err)
	}
	if _, err = a.RedactReason(context.Background(), &reason); err != ErrRegistrationUnavailable {
		t.Fatal("private redaction error escaped", err)
	}
}
