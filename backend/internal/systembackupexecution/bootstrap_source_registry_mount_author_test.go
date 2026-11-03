package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	"k8s.io/client-go/kubernetes/fake"
)

func mountAuthorNative(instance b.InstanceIdentity, spec b.RuntimeWriterSpec) bootstrapSourceNativeWriter {
	return bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, RuntimePodID: 8, PID: 99, Port: 19001, Namespace: spec.RuntimeNamespace(), Pod: spec.RuntimePod(), PodUID: spec.UID, Deployment: "runtime", DeploymentUID: "deployment-original", ReplicaSetUID: "rs-original", ServiceAccountUID: "sa-original", NodeUID: "node-original", Gateway: "gw-original", Endpoint: "https://192.0.2.1:9000", AgentEpoch: "agent-original", State: "running"}
}

func TestOriginalMountAuthorUsesActualNativeProjectionWithBBuilder(t *testing.T) {
	cfg, instance, spec, layout, _, objects := originalMountInputFixture(t)
	native := mountAuthorNative(instance, spec)
	specs, err := originalMountNativeSpecs([]b.InstanceIdentity{instance}, []bootstrapSourceNativeWriter{native})
	if err != nil || len(specs) != 1 || specs[0].Runtime.AgentEpoch != native.AgentEpoch || specs[0].Runtime.RuntimePodID != native.RuntimePodID || specs[0].Runtime.GatewayPID != native.PID || specs[0].UID != native.PodUID || specs[0].RestartRef != "" || specs[0].Backup.OperationID != "" {
		t.Fatal("native comparison misbound or invented stop authority", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := fake.NewSimpleClientset(objects...)
	raw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, []b.InstanceIdentity{instance}, specs, []InstancePersistentMountLayout{layout})
	var scope productionPersistentMountScope
	if err != nil || json.Unmarshal(raw, &scope) != nil || scope.validate() != nil || len(scope.Mounts) != 1 || scope.Mounts[0].UserID != instance.UserID || scope.Mounts[0].PodUID != native.PodUID {
		t.Fatal("actual B builder not reached with exact native inputs", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("authoring mutated cluster")
		}
	}
}

func TestOriginalMountAuthorRefusesStoppedMissingAndForeignNative(t *testing.T) {
	_, instance, spec, _, _, _ := originalMountInputFixture(t)
	for _, fault := range []string{"stopped", "owner", "generation", "epoch", "missing", "extra", "duplicate", "runtime-id"} {
		t.Run(fault, func(t *testing.T) {
			selected := instance
			native := []bootstrapSourceNativeWriter{mountAuthorNative(instance, spec)}
			switch fault {
			case "stopped":
				selected.Status = "stopped"
			case "owner":
				native[0].UserID++
			case "generation":
				native[0].Generation++
			case "epoch":
				native[0].AgentEpoch = ""
			case "missing":
				native = nil
			case "extra":
				native = append(native, native[0])
				native[1].InstanceID++
			case "duplicate":
				native = append(native, native[0])
			case "runtime-id":
				native[0].RuntimePodID = 0
			}
			out, err := originalMountNativeSpecs([]b.InstanceIdentity{selected}, native)
			if err == nil || out != nil {
				t.Fatal("incomplete native comparison exported")
			}
			if fault == "stopped" && !errors.Is(err, c.ErrSourceRecoveryStoppedWitnessRequired) {
				t.Fatal("stopped original witness requirement lost")
			}
		})
	}
}

func TestOriginalMountAuthorLayoutsArePinnedSelectionOnly(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "layouts.json")
	_, _, _, layout, _, _ := originalMountInputFixture(t)
	selection := OriginalInstanceMountLayoutSelection{Version: OriginalInstanceMountLayoutSelectionVersion, Layouts: []InstancePersistentMountLayout{layout}}
	raw, err := ce.Canonical(selection)
	if err != nil || os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := readOriginalMountLayouts(file, hash(raw)); err != nil {
		t.Fatal("valid directory selection refused", err)
	}
	if _, err := readOriginalMountLayouts(file, hash([]byte("different"))); err == nil {
		t.Fatal("unmatched layout pin accepted")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture")
	}
	fields["ObservedPodUID"] = "caller-fact"
	injected, _ := ce.Canonical(fields)
	if os.WriteFile(file, injected, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := readOriginalMountLayouts(file, hash(injected)); err == nil {
		t.Fatal("caller identity promoted into original observation")
	}
}

func TestOriginalMountAuthorRequiresRealInstallerAndBoundedContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, caller := range []context.Context{nil, context.Background(), ctx} {
		if _, err := ProduceOriginalInstanceMountMaterials(caller, nil, nil, install.EnrollmentPin{}, "caller-selection", "caller-hash", "caller-layouts", "caller-hash", dir); err == nil {
			t.Fatal("declaration-only caller exported materials")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("unauthenticated action left output", err)
	}
}

func TestOriginalMountAuthorProtectsFinalMaterialAndGrantPaths(t *testing.T) {
	for _, fault := range []string{"none", "materials", "metadata", "facts", "credential"} {
		cfg := DeploymentConfig{}
		materials := productionCaptureMaterials{Discovery: &productionSourceDiscovery{}}
		selection := install.BootstrapSourceAuthoringSelection{}
		switch fault {
		case "materials":
			cfg.CaptureModules = &ProductionCaptureReference{Path: "new-template"}
		case "metadata":
			materials.Discovery.GrantFile = "new-selection"
		case "facts":
			selection.PartsFile = "new-template"
		case "credential":
			selection.Connections = []install.BootstrapSourceConnection{{Credential: install.BootstrapSourceFilePin{File: "new-selection"}}}
		}
		err := checkOriginalMountAuthoringAliases("new-template", "new-selection", "original-selection", "original-layouts", selection, cfg, materials)
		if (err == nil) != (fault == "none") {
			t.Fatal("reserved output path accepted", fault, err)
		}
	}
}
