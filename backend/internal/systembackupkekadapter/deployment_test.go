package systembackupkekadapter

import (
	"context"
	"database/sql"
	"testing"
	"time"

	admission "clawreef/internal/systembackupkekadmission"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

type bootstrapSourceFixture struct{}

func (bootstrapSourceFixture) BootstrapAdmissionInput(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig, reg.Snapshot) (reg.AdmissionInput, error) {
	return reg.AdmissionInput{}, nil
}

type mutationSourceFixture struct{}

func (mutationSourceFixture) MutationAdmissionInput(context.Context, sec.ConfigMutationResourceInput, reg.Snapshot) (reg.AdmissionInput, error) {
	return reg.AdmissionInput{}, nil
}

type capabilityPreparationFixture struct{}

func (capabilityPreparationFixture) PrepareCapabilities(context.Context, reg.Binding) (admission.Capabilities, error) {
	return admission.Capabilities{}, nil
}

func TestWireServicesPinsSQLOriginalReaderDatabase(t *testing.T) {
	db, other := new(sql.DB), new(sql.DB)
	bootstrap := sec.ConfigBootstrapService{DB: db}
	mutation := sec.ConfigMutationService{DB: db}
	original := InstallationPreparation{Issuer: make([]byte, 32), Capabilities: capabilityPreparationFixture{}, Now: time.Now}
	for _, tc := range []struct {
		name   string
		reader OriginalReader
		accept bool
	}{
		{"value-same-db", SQLOriginalReader{DB: db}, true},
		{"pointer-same-db", &SQLOriginalReader{DB: db}, true},
		{"value-other-db", SQLOriginalReader{DB: other}, false},
		{"pointer-other-db", &SQLOriginalReader{DB: other}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original.Reader = tc.reader
			b, m, err := WireServices(bootstrap, mutation, bootstrapSourceFixture{}, mutationSourceFixture{}, original)
			if (err == nil) != tc.accept {
				t.Fatalf("wire result: %v", err)
			}
			if tc.accept && (b.KEK == nil || m.KEK == nil) {
				t.Fatal("KEK preparation not installed")
			}
		})
	}
}

func TestWireServicesPinsConcreteCapabilityReaderToOriginalDatabase(t *testing.T) {
	db, other := new(sql.DB), new(sql.DB)
	for _, capDB := range []*sql.DB{db, other} {
		original := InstallationPreparation{Reader: SQLOriginalReader{DB: db}, Issuer: make([]byte, 32), Capabilities: &SQLProviderCapabilityPreparation{db: capDB}, Now: time.Now}
		_, _, err := WireServices(sec.ConfigBootstrapService{DB: db}, sec.ConfigMutationService{DB: db}, bootstrapSourceFixture{}, mutationSourceFixture{}, original)
		if (err == nil) != (capDB == db) {
			t.Fatal("provider capability reader escaped original database pin", err)
		}
	}
}
