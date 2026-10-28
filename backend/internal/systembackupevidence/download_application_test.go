package systembackupevidence

import (
	"bytes"
	"testing"
)

// SQL/identity/provider transport are fixtures. Constructors must still choose
// the concrete owner/material/admission/result path, not the fixture's owner.
func downloadApplicationFixture(t *testing.T) DownloadApplicationConfig {
	t.Helper()
	runtime, _, _ := downloadRuntimeFixture(t)
	p := newAdmissionPinnedFixture(t)
	runtime.Authority.Registry = p.service.registry
	runtime.Authority.Registry.Policy = nil
	runtime.Authority.SensitiveStepUp = nil
	runtime.Authority.JWTSecret = append([]byte(nil), p.secret...)
	runtime.Authority.RegistryDirectory = p.configuration.RegistryDirectory
	runtime.S3.Store.Installation = runtime.Authority.Registry.Installation
	for n := range runtime.Transit {
		runtime.Transit[n].Transit.Installation = runtime.Authority.Registry.Installation
	}
	journal := failureJournalConfig(t)
	return DownloadApplicationConfig{Authority: runtime.Authority, S3: runtime.S3, Transit: runtime.Transit, Sessions: p.configuration.Sessions, Materials: p.configuration.Materials,
		Capacity: p.configuration.Capacity, ProofIssuer: p.configuration.Issuer, AdmissionReservationBytes: p.configuration.MeasuredReservationBytes, ResultReservationBytes: 65536,
		MaterialsUntil: p.configuration.MaterialsUntil, AuditMinimumRetainUntil: p.configuration.AuditMinimumRetainUntil, JournalPath: journal.Path, JournalMaxBytes: journal.MaxBytes}
}

func TestDownloadApplicationConcreteBindingsAndClose(t *testing.T) {
	c := downloadApplicationFixture(t)
	a, err := NewDownloadApplication(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	env, ok := a.admission.environment.(*PinnedDownloadAdmissionEnvironment)
	if !ok || a.Runtime.admitted == nil || a.ProofTargets == nil || a.ProofTargets.source != env || a.Runtime.admitted.admission != a.admission {
		t.Fatal("proof/admission/runtime not assembled from one environment")
	}
	owners, ok := env.config.Owners.(*SQLDownloadOwners)
	if !ok || !owners.producer || a.admission.registry.Policy != owners.SQLTaskDownloadOwners || a.Runtime.authority.c.Registry.Policy != owners.SQLTaskDownloadOwners || a.Runtime.admitted.results.c.Owners != owners {
		t.Fatal("nonconcrete or different SQL owner path")
	}
	if env.config.Issuer != c.ProofIssuer || env.config.Issuer == c.Authority.Issuer || !env.config.MaterialsUntil.Equal(c.MaterialsUntil) || !env.config.AuditMinimumRetainUntil.Equal(c.AuditMinimumRetainUntil) || a.Runtime.CheckFailurePersistence() != nil {
		t.Fatal("original material limits or distinct proof issuer lost")
	}
	before := append([]byte(nil), c.Authority.JWTSecret...)
	c.Authority.JWTSecret[0] ^= 255
	if !bytes.Equal(a.admission.secret, before) || !bytes.Equal(a.Runtime.authority.c.JWTSecret, before) {
		t.Fatal("caller secret alias retained")
	}
	a.Close()
	if a.Runtime.CheckFailurePersistence() == nil || !bytes.Equal(a.admission.secret, make([]byte, len(before))) || !bytes.Equal(a.Runtime.authority.c.JWTSecret, make([]byte, len(before))) || bytes.Equal(c.Authority.JWTSecret, make([]byte, len(before))) {
		t.Fatal("close failed or erased caller secret")
	}
}

func TestDownloadApplicationMissingProductionInputsReject(t *testing.T) {
	for _, mode := range []string{"arbitrary_policy", "legacy_proof", "sessions", "materials", "capacity", "proof_issuer", "admission_budget", "result_budget", "original_material_deadline", "retention_deadline", "journal"} {
		t.Run(mode, func(t *testing.T) {
			c := downloadApplicationFixture(t)
			switch mode {
			case "arbitrary_policy":
				c.Authority.Registry.Policy = &downloadTestPolicy{}
			case "legacy_proof":
				c.Authority.SensitiveStepUp = &downloadTestStepUp{}
			case "sessions":
				c.Sessions = nil
			case "materials":
				c.Materials = nil
			case "capacity":
				c.Capacity = nil
			case "proof_issuer":
				c.ProofIssuer = ""
			case "admission_budget":
				c.AdmissionReservationBytes = 0
			case "result_budget":
				c.ResultReservationBytes = 0
			case "original_material_deadline":
				c.MaterialsUntil = c.MaterialsUntil.AddDate(-2026, 0, 0)
			case "retention_deadline":
				c.AuditMinimumRetainUntil = c.AuditMinimumRetainUntil.AddDate(-2026, 0, 0)
			case "journal":
				c.JournalPath = ""
			}
			if a, err := NewDownloadApplication(c); err == nil {
				a.Close()
				t.Fatal("missing or arbitrary production input accepted")
			}
		})
	}
}
