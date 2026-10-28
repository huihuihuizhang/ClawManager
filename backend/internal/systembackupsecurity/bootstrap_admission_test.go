package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All adapters in these tests are synthetic. They validate orchestration only,
// not the actual provider, administrator MFA or deployment readiness.
type admissionTestValidator struct {
	prepare func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error)
	recheck func(context.Context, *sql.Tx, time.Time) error
}

func (v *admissionTestValidator) Prepare(ctx context.Context, g OfflineBootstrapGrant, c BootstrapConfig) (BootstrapResourceCheck, error) {
	if v.prepare != nil {
		return v.prepare(ctx, g, c)
	}
	return v, nil
}
func (v *admissionTestValidator) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if v.recheck != nil {
		return v.recheck(ctx, tx, now)
	}
	return nil
}

func admissionFixture(t *testing.T) (ConfigBootstrapService, OfflineBootstrapGrant, []byte, BootstrapAdmissionSources, *bootstrapTestState) {
	t.Helper()
	svc, g, raw, state := bootstrapServiceFixture(t)
	var values bootstrapValues
	if json.Unmarshal(raw, &values) != nil {
		t.Fatal("fixture")
	}
	files := map[string][]byte{}
	for i, r := range values.Registries {
		b := []byte(`{"synthetic":true}`)
		if r.Kind == "rbac_bindings" {
			b = []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"synthetic-v1","installation_id":"installation_synthetic","bindings":[{"actor_id":"42","subject":"user:42","role":"security_admin"}]}`)
		}
		values.Registries[i].SHA256 = registrationHash(string(b))
		files[r.Kind] = b
	}
	raw, _ = json.Marshal(values)
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	g.ConfigSHA256 = c.SHA256()
	state.grant = g
	s := BootstrapAdmissionSources{
		ReadGrant: func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
			return g, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil
		},
		RegistryBytes: func(kind, _, _ string) ([]byte, error) { return append([]byte(nil), files[kind]...), nil },
		Registries:    map[string]BootstrapResourceValidator{}, References: map[string]BootstrapResourceValidator{},
		CrossResources: &admissionTestValidator{},
		NonceMaterial:  func(_, _ string) ([]byte, error) { return make([]byte, 32), nil },
		ReserveMetadata: func(ctx context.Context, tx *sql.Tx, _ int64, _ int) error {
			_, err := tx.ExecContext(ctx, "synthetic reserve")
			return err
		},
	}
	for _, kind := range bootstrapRegistryKinds {
		s.Registries[kind] = &admissionTestValidator{}
	}
	for _, purpose := range bootstrapReferencePurposes {
		s.References[purpose] = &admissionTestValidator{}
	}
	return svc, g, raw, s, state
}

func TestAdmissionRequiresEveryAdapterBeforeProviderWork(t *testing.T) {
	for _, kind := range bootstrapRegistryKinds {
		t.Run("registry/"+kind, func(t *testing.T) {
			_, g, raw, s, _ := admissionFixture(t)
			delete(s.Registries, kind)
			s.ReadGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
				t.Fatal("work before completeness gate")
				return g, time.Time{}, time.Time{}, nil
			}
			if _, err := PrepareBootstrapAdmission(context.Background(), g, raw, s); err != ErrRegistrationUnavailable {
				t.Fatal(err)
			}
		})
	}
	for _, purpose := range bootstrapReferencePurposes {
		t.Run("reference/"+purpose, func(t *testing.T) {
			_, g, raw, s, _ := admissionFixture(t)
			delete(s.References, purpose)
			if _, err := PrepareBootstrapAdmission(context.Background(), g, raw, s); err != ErrRegistrationUnavailable {
				t.Fatal(err)
			}
		})
	}
}

func TestAdmissionPreparedSnapshotAndRevokedRetry(t *testing.T) {
	svc, g, raw, s, state := admissionFixture(t)
	prepared, checked := 0, 0
	check := &admissionTestValidator{recheck: func(_ context.Context, tx *sql.Tx, _ time.Time) error {
		if tx == nil {
			t.Fatal("missing transaction")
		}
		checked++
		return nil
	}}
	s.CrossResources = &admissionTestValidator{prepare: func(_ context.Context, _ OfflineBootstrapGrant, _ BootstrapConfig) (BootstrapResourceCheck, error) {
		prepared++
		return check, nil
	}}
	revoked := false
	s.ReadGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
		if revoked {
			return g, time.Time{}, time.Time{}, errors.New("PRIVATE grant detail")
		}
		return g, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil
	}
	key := make([]byte, 32)
	key[0] = 42
	s.NonceMaterial = func(identity, version string) ([]byte, error) {
		if identity != strings.Repeat("b", 64) || version != "synthetic-v1" {
			t.Fatal("nonce identity not pinned")
		}
		return key, nil
	}
	var err error
	svc.Admission, err = PrepareBootstrapAdmission(context.Background(), g, raw, s)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.Bootstrap(context.Background(), g, raw)
	if err != nil || first.Version != 1 || prepared != 1 || checked != 1 || key[0] != 0 {
		t.Fatal(first, err, prepared, checked)
	}
	retry, err := svc.Bootstrap(context.Background(), g, raw)
	if err != nil || !retry.Replayed || checked != 1 || len(state.committed) != 6 {
		t.Fatal("replay", retry, err)
	}
	revoked = true
	if _, err = svc.Bootstrap(context.Background(), g, raw); err != ErrRegistrationPermission {
		t.Fatal("revoked retry", err)
	}
}

func TestAdmissionRejectsDriftBeforeAnyWrite(t *testing.T) {
	for _, fault := range []string{"registry", "expired_check", "nonce", "capacity", "grant", "config"} {
		t.Run(fault, func(t *testing.T) {
			svc, g, raw, s, state := admissionFixture(t)
			drift := false
			originalRead := s.RegistryBytes
			s.RegistryBytes = func(kind, version, digest string) ([]byte, error) {
				if drift && fault == "registry" && kind == "parts" {
					return []byte("changed"), nil
				}
				return originalRead(kind, version, digest)
			}
			s.CrossResources = &admissionTestValidator{recheck: func(_ context.Context, _ *sql.Tx, _ time.Time) error {
				if drift && fault == "expired_check" {
					return errors.New("PRIVATE stale observation")
				}
				return nil
			}}
			if fault == "nonce" {
				s.NonceMaterial = func(_, _ string) ([]byte, error) { return make([]byte, 31), nil }
			}
			if fault == "capacity" {
				s.ReserveMetadata = func(context.Context, *sql.Tx, int64, int) error { return errors.New("PRIVATE capacity") }
			}
			var err error
			svc.Admission, err = PrepareBootstrapAdmission(context.Background(), g, raw, s)
			if err != nil {
				t.Fatal(err)
			}
			drift = true
			if fault == "grant" {
				g.ChangeReason = "changed authorization"
			}
			if fault == "config" {
				raw = []byte(strings.Replace(string(raw), `"minimum_recovery_points":1`, `"minimum_recovery_points":2`, 1))
			}
			if _, err = svc.Bootstrap(context.Background(), g, raw); err == nil || strings.Contains(err.Error(), "PRIVATE") || len(state.committed) != 0 || len(state.pending) != 0 {
				t.Fatal("unsafe admission", err, state.committed)
			}
		})
	}
}

func TestBootstrapGrantFilePinsExactBytesAndCanBeRevoked(t *testing.T) {
	_, g, _, _, _ := admissionFixture(t)
	doc := BootstrapGrantFile{"system-backup-offline-bootstrap-grant.v1", time.Now().UTC(), time.Now().UTC().Add(time.Hour), g}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "grant.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := registrationHash(string(raw))
	got, _, _, err := ReadBootstrapGrantFile(path, digest)
	if err != nil || got != g {
		t.Fatal(got, err)
	}
	if err = os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = ReadBootstrapGrantFile(path, digest); err != ErrRegistrationPermission {
		t.Fatal("changed grant accepted", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = ReadBootstrapGrantFile(path, digest); err != ErrRegistrationPermission {
		t.Fatal("removed grant accepted", err)
	}
}
