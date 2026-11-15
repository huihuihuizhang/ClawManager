package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
)

func TestOriginalFirstAdoptionRejectsUnsupportedSourceBeforeProvider(t *testing.T) {
	for _, mode := range []string{"tenant", "tenant_namespace", "changed_pin", "invalid_policy", "supported"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Clean(t.TempDir())
			selection := OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion,
				Policy: c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}}
			switch mode {
			case "tenant":
				selection.TenantPro = []OriginalTenantProSelection{{Source: domain.SourceInstance{ID: 2}}}
			case "tenant_namespace":
				selection.TenantNamespaces = []originalMaintenanceKubernetesCensus{{Namespace: "validation-user-1"}}
			case "invalid_policy":
				selection.Policy.LockTTL = 0
			}
			raw, err := canonical(selection)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(directory, "selection.json")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			pin := BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
			if mode == "changed_pin" {
				pin.SHA256 = strings.Repeat("a", 64)
			}
			absent := BootstrapSourceFilePin{File: filepath.Join(directory, "absent.json"), SHA256: strings.Repeat("b", 64)}
			in := OriginalFirstAdoptionProductionInputs{Version: "original-first-adoption-production-inputs.v1",
				WriterSelection: pin, MinIORecoveryDescriptor: absent, Head1Directory: directory, WarmDirectory: directory,
				CaptureSeconds: 60, RecoverySeconds: 60}
			in.History.BusinessSourceSelection = absent
			// No DB, Kubernetes client or provider exists: reaching an owner or
			// committing operation instead of the file preflight cannot pass.
			for _, metadataSQL := range []bool{false, true} {
				receipt, err := (&Installer{}).runOriginalFirstAdoptionProductionForSQLProfile(context.Background(), []byte("password"), []byte("recovery"), nil, EnrollmentPin{}, in, metadataSQL)
				want := "original_writer_support_preflight"
				if mode == "supported" {
					want = "recovery_descriptor_input_preflight"
				}
				var failure OriginalFirstAdoptionProductionFailure
				if err == nil || !errors.As(err, &failure) || failure.Stage != want || receipt.Stage != want || receipt.HoldVerified || receipt.AdoptionCommitted || receipt.ProviderResult != nil || receipt.ProviderResultFile.File != "" {
					t.Fatalf("preflight stage = %q, want %q; error = %v", receipt.Stage, want, err)
				}
				if mode == "tenant" || mode == "tenant_namespace" {
					var source OriginalWriterSourceFailure
					if !errors.As(err, &source) || source.Dependency != "tenant_pro_original_native_stop_recovery_owner_required" {
						t.Fatal("lost native refusal", err)
					}
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != "selection.json" {
				t.Fatal("preflight wrote an output", err)
			}
		})
	}
}
