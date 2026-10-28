package systembackupsecurity

import (
	"context"
	"testing"
	"time"
)

func TestAdmissionRejectsTypedNilBeforeAnySource(t *testing.T) {
	for _, slot := range []string{"registry", "reference", "cross", "context", "cancelled"} {
		t.Run(slot, func(t *testing.T) {
			_, g, raw, s, _ := admissionFixture(t)
			var missing *admissionTestValidator
			ctx := context.Background()
			switch slot {
			case "registry":
				s.Registries[bootstrapRegistryKinds[0]] = missing
			case "reference":
				s.References[bootstrapReferencePurposes[0]] = missing
			case "cross":
				s.CrossResources = missing
			case "context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			s.ReadGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
				t.Fatal("invalid boundary reached original source")
				return g, time.Time{}, time.Time{}, nil
			}
			if _, err := PrepareBootstrapAdmission(ctx, g, raw, s); err != ErrRegistrationUnavailable {
				t.Fatal(err)
			}
		})
	}
}

func TestAdmissionRejectsTypedNilPreparedCheck(t *testing.T) {
	_, g, raw, s, _ := admissionFixture(t)
	var absent *admissionTestValidator
	s.Registries[bootstrapRegistryKinds[0]] = &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
		return absent, nil
	}}
	if _, err := PrepareBootstrapAdmission(context.Background(), g, raw, s); err != ErrRegistrationUnavailable {
		t.Fatal("typed nil check escaped preparation", err)
	}
}

func TestAdmissionDetachesOwnerTablesBeforeTrustedCallbacks(t *testing.T) {
	_, g, raw, s, _ := admissionFixture(t)
	registryChecks, referenceChecks := 0, 0
	for _, kind := range bootstrapRegistryKinds {
		s.Registries[kind] = &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
			registryChecks++
			return &admissionTestValidator{}, nil
		}}
	}
	for _, purpose := range bootstrapReferencePurposes {
		s.References[purpose] = &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
			referenceChecks++
			return &admissionTestValidator{}, nil
		}}
	}
	original := s.ReadGrant
	s.ReadGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
		for key := range s.Registries {
			s.Registries[key] = nil
		}
		for key := range s.References {
			s.References[key] = nil
		}
		return original()
	}
	a, err := PrepareBootstrapAdmission(context.Background(), g, raw, s)
	if err != nil || registryChecks != 9 || referenceChecks != 20 {
		t.Fatal("callback changed captured owners", registryChecks, referenceChecks, err)
	}
	prepared := a.(*preparedBootstrapAdmission)
	if len(MissingBootstrapAdapters(prepared.sources)) != 0 {
		t.Fatal("prepared admission retained mutable tables")
	}
}
