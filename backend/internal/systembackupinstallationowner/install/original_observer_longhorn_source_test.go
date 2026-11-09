package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
)

func TestOriginalObserverTenantSourceExactSignedJoin(t *testing.T) {
	instance := domain.SourceInstance{ID: 7, UserID: 1, Generation: 3, Namespace: "test-user-1", Pod: "original-pod", Mode: "pro", OS: "linux", Status: "running"}
	identity := kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: "source", UID: "pvc-uid", PVName: "pv", PVUID: "pv-uid", SHA256: strings.Repeat("b", 64)}
	source := originalObserverLonghornSource{Namespace: instance.Namespace, NamespaceUID: "tenant-uid", Source: identity, Handle: "volume", AccessMode: corev1.ReadWriteOnce,
		ProviderNamespace: "longhorn-system", ProviderUID: "longhorn-uid", SnapshotClass: "snapshot-class", SnapshotClassUID: "snapshot-class-uid", SnapshotClassSHA256: strings.Repeat("c", 64),
		CloneClass: "clone-class", CloneClassUID: "clone-class-uid", CloneClassSHA256: strings.Repeat("d", 64)}
	// Grant identity uses the existing source struct's json.Marshal bytes, not
	// the canonical container document's field order.
	sourceRaw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := quiesce.LonghornExt4SourceCoordinates{Binding: quiesce.ObservationBinding{Namespace: instance.Namespace, NamespaceUID: "tenant-uid"},
		PVCName: identity.Name, PVCUID: identity.UID, PVUID: identity.PVUID, VolumeHandle: source.Handle, LonghornNamespace: source.ProviderNamespace, ProviderNamespaceUID: source.ProviderUID, OriginalSourceSHA256: hash(sourceRaw)}
	// Use the actual canonical material wire projection before testing the
	// production join; malformed JSON is not an identity failure fixture.
	raw, err := canonical(map[string]any{"Discovery": map[string]any{"PersistentMounts": map[string]any{"Version": "original-instance-persistent-mounts.v1", "RunningTenantPro": []originalObserverTenantMount{{Source: instance, NamespaceUID: "tenant-uid", Identity: identity}}}, "LonghornSources": map[string]originalObserverLonghornSource{"instance_7_workspace": source}}})
	var material originalObserverLonghornMaterial
	if err != nil || json.Unmarshal(raw, &material) != nil {
		t.Fatal("canonical signed-material fixture", err)
	}
	if got, actual, err := matchOriginalObserverTenantSource(material, coordinate, []domain.SourceInstance{instance}); err != nil || got.Identity != identity || actual != instance {
		t.Fatal("exact original source / mount / backend join", err)
	}
	for name, change := range map[string]func(*quiesce.LonghornExt4SourceCoordinates){
		"namespace":           func(c *quiesce.LonghornExt4SourceCoordinates) { c.Binding.Namespace = "test-user-2" },
		"namespace-uid":       func(c *quiesce.LonghornExt4SourceCoordinates) { c.Binding.NamespaceUID = "replaced" },
		"pvc":                 func(c *quiesce.LonghornExt4SourceCoordinates) { c.PVCUID = "replaced" },
		"pv":                  func(c *quiesce.LonghornExt4SourceCoordinates) { c.PVUID = "replaced" },
		"handle":              func(c *quiesce.LonghornExt4SourceCoordinates) { c.VolumeHandle = "another" },
		"resource-namespace":  func(c *quiesce.LonghornExt4SourceCoordinates) { c.LonghornNamespace = "another" },
		"resource-uid":        func(c *quiesce.LonghornExt4SourceCoordinates) { c.ProviderNamespaceUID = "replaced" },
		"original-source-sha": func(c *quiesce.LonghornExt4SourceCoordinates) { c.OriginalSourceSHA256 = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := coordinate
			change(&changed)
			if _, _, err := matchOriginalObserverTenantSource(material, changed, []domain.SourceInstance{instance}); err == nil {
				t.Fatal("changed selected source matched signed material")
			}
		})
	}
	for _, change := range []func(*domain.SourceInstance){func(s *domain.SourceInstance) { s.ID++ }, func(s *domain.SourceInstance) { s.Generation++ }, func(s *domain.SourceInstance) { s.Pod = "replaced" }, func(s *domain.SourceInstance) { s.Status = "stopped" }} {
		current := instance
		change(&current)
		if _, _, err := matchOriginalObserverTenantSource(material, coordinate, []domain.SourceInstance{current}); err == nil {
			t.Fatal("different current original instance inherited signed mount")
		}
	}
	material.Discovery.PersistentMounts.RunningTenantPro = append(material.Discovery.PersistentMounts.RunningTenantPro, material.Discovery.PersistentMounts.RunningTenantPro[0])
	if _, _, err := matchOriginalObserverTenantSource(material, coordinate, []domain.SourceInstance{instance}); err == nil {
		t.Fatal("ambiguous duplicate mount was accepted")
	}
}

func TestOriginalObserverTenantSourceRequiresActualV2Consumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, prepared, _, _ := newActualBootstrapSourceV2MaterialConsumer(t, ctx, 0)
	registry := BootstrapSourceRegistryFiles{RecordFile: prepared.base.files[0].path, RecordSHA256: prepared.base.files[0].sha, SignatureFile: prepared.base.files[1].path}
	pin := func(file string) BootstrapSourceFilePin {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
	}
	refs := &OriginalObserverLonghornSourceRegistry{Registry: registry, CaptureConsumer: pin(fixture.source.sourceFile), CaptureConsumerPin: pin(fixture.source.sourcePinFile)}
	writes, signs := fixture.f.s.writes, fixture.f.signs.Load()
	defer func() {
		if fixture.f.s.writes != writes || fixture.f.signs.Load() != signs {
			t.Fatal("source association refusal mutated SQL or invoked signer")
		}
	}()
	// The original authenticated issuer/consumer fixture is real, but deliberately
	// has no tenant PersistentMounts. A valid signature alone cannot grant one.
	before := fixture.apiCalls.Load()
	if callback, err := fixture.f.i.originalObserverLonghornTenantCheck(ctx, fixture.f.password, fixture.f.enrollment, refs); err == nil || callback != nil {
		t.Fatal("signed association without a selected tenant mount was accepted")
	}
	if fixture.apiCalls.Load() <= before {
		t.Fatal("fixture failed before reaching actual consumer enrollment authentication")
	}
	wrong := *refs
	wrong.Registry.SignatureFile = filepath.Join(t.TempDir(), "wrong.signature")
	if err := os.WriteFile(wrong.Registry.SignatureFile, make([]byte, 64), 0600); err != nil {
		t.Fatal(err)
	}
	before = fixture.apiCalls.Load()
	if callback, err := fixture.f.i.originalObserverLonghornTenantCheck(ctx, fixture.f.password, fixture.f.enrollment, &wrong); err == nil || callback != nil {
		t.Fatal("wrong signature accepted")
	}
	if fixture.apiCalls.Load() <= before {
		t.Fatal("wrong-signature case failed before authenticated consumer read")
	}
}
