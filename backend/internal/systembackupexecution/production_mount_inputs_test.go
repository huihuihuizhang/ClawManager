package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func originalMountInputFixture(t *testing.T) (DeploymentConfig, b.InstanceIdentity, b.RuntimeWriterSpec, InstancePersistentMountLayout, *corev1.Pod, []runtime.Object) {
	t.Helper()
	cfg, instance, pod, mapping, _, objects := persistentMountFixture(t, "pvc")
	cfg.NamespaceUID = "namespace-original"
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "primary", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.Workspace.Claim}}})
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "primary", MountPath: "/workspaces", SubPath: "installations/original"})
	objects = append(objects, pod, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: "namespace-original"}})
	spec := b.RuntimeWriterSpec{Source: instance, Kind: "gateway", UID: string(pod.UID), Runtime: b.RuntimeLocator{Version: "runtime-locator.v2", Namespace: cfg.Namespace, Pod: pod.Name}}
	layout := InstancePersistentMountLayout{InstanceID: instance.ID, MountID: mapping.MountID, Container: mapping.Container, Volume: mapping.Volume, MountPath: mapping.MountPath, DataPath: mapping.DataPath}
	return cfg, instance, spec, layout, pod, objects
}

func TestOriginalInstanceMountBuilderDerivesPinsWithOnlyGET(t *testing.T) {
	cfg, instance, spec, layout, pod, objects := originalMountInputFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := fake.NewSimpleClientset(objects...)
	before := pod.DeepCopy()
	raw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, []b.InstanceIdentity{instance}, []b.RuntimeWriterSpec{spec}, []InstancePersistentMountLayout{layout})
	var scope productionPersistentMountScope
	if err != nil || decodeMetadataCanonical(raw, &scope) != nil || scope.validate() != nil || len(scope.Mounts) != 1 {
		t.Fatal("original scope not generated", err)
	}
	m := scope.Mounts[0]
	if m.UserID != instance.UserID || m.Generation != instance.Generation || m.PodUID != string(pod.UID) || m.PodSpecSHA256 != kube.ContentHash(pod.Spec) || m.VolumeSourceSHA256 != kube.ContentHash(pod.Spec.Volumes[0].VolumeSource) || !reflect.DeepEqual(pod, before) {
		t.Fatal("builder changed/misbound original source")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("authoring helper mutated cluster")
		}
	}
}

func TestOriginalInstanceMountBuilderRejectsIncompleteAndStoppedInputsBeforeGET(t *testing.T) {
	for _, fault := range []string{"unbounded", "expired", "stopped", "owner", "generation", "unknown-instance", "duplicate-instance", "duplicate-spec", "foreign-layout", "pro", "windows"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, spec, layout, _, objects := originalMountInputFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			instances, specs, layouts := []b.InstanceIdentity{instance}, []b.RuntimeWriterSpec{spec}, []InstancePersistentMountLayout{layout}
			switch fault {
			case "unbounded":
				ctx = context.Background()
			case "expired":
				cancel()
			case "stopped":
				instances[0].Status = "stopped"
				specs[0].Source = instances[0]
				specs[0].Kind = "stopped"
			case "owner":
				specs[0].Source.UserID++
			case "generation":
				specs[0].Source.Generation++
			case "unknown-instance":
				specs[0].Source.ID++
			case "duplicate-instance":
				instances = append(instances, instance)
				specs = append(specs, spec)
			case "duplicate-spec":
				instances = append(instances, instance)
				instances[1].ID++
				specs = append(specs, spec)
			case "foreign-layout":
				layouts[0].InstanceID++
			case "pro":
				instances[0].Mode = "pro"
			case "windows":
				instances[0].OS = "windows"
			}
			client := fake.NewSimpleClientset(objects...)
			raw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, instances, specs, layouts)
			var diagnostic *InstanceMountInputError
			if err == nil || raw != nil || len(client.Actions()) != 0 || !errors.As(err, &diagnostic) {
				t.Fatal("invalid source read resources or returned partial data", err)
			}
			if fault == "stopped" && (!errors.Is(err, c.ErrSourceRecoveryStoppedWitnessRequired) || diagnostic.InstanceID != instance.ID) {
				t.Fatal("stopped witness diagnostic lost")
			}
		})
	}
}

func TestOriginalInstanceMountBuilderDetectsDriftAndMissingCoverage(t *testing.T) {
	for _, fault := range []string{"missing-layout", "duplicate-layout", "unknown-volume", "pod-replaced", "pod-spec-drift", "namespace-tail", "missing-primary", "empty-extra-spec-drift", "node-replaced", "pvc-replaced"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, spec, layout, pod, objects := originalMountInputFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			layouts := []InstancePersistentMountLayout{layout}
			switch fault {
			case "missing-layout":
				layouts = nil
			case "duplicate-layout":
				layouts = append(layouts, layout)
			case "unknown-volume":
				layouts[0].Volume = "missing"
			case "missing-primary":
				pod.Spec.Containers[0].VolumeMounts = pod.Spec.Containers[0].VolumeMounts[:1]
			case "empty-extra-spec-drift":
				layouts = nil
				pod.Spec.Containers[0].VolumeMounts = pod.Spec.Containers[0].VolumeMounts[1:]
				pod.Spec.Volumes = pod.Spec.Volumes[1:]
			case "node-replaced":
				objects[0].(*corev1.Node).UID = "replacement"
			case "pvc-replaced":
				objects[1].(*corev1.PersistentVolumeClaim).UID = "replacement"
			}
			client := fake.NewSimpleClientset(objects...)
			calls, nsCalls := 0, 0
			client.PrependReactor("get", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
				calls++
				value := pod.DeepCopy()
				if fault == "pod-replaced" {
					value.UID = "replacement"
				}
				if fault == "pod-spec-drift" && calls >= 3 || fault == "empty-extra-spec-drift" && calls >= 2 {
					value.Spec.Containers[0].Image = "changed"
				}
				return true, value, nil
			})
			client.PrependReactor("get", "namespaces", func(a ktesting.Action) (bool, runtime.Object, error) {
				nsCalls++
				if fault == "namespace-tail" && nsCalls == 3 {
					return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: "replacement"}}, nil
				}
				return false, nil, nil
			})
			raw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, []b.InstanceIdentity{instance}, []b.RuntimeWriterSpec{spec}, layouts)
			if err == nil || raw != nil {
				t.Fatal("drift/omission returned unsigned candidate", fault)
			}
		})
	}
}

func TestOriginalInstanceMountScopeRejectsOwnerGenerationAndForeignRows(t *testing.T) {
	for _, fault := range []string{"owner", "generation", "foreign", "duplicate", "missing", "stopped"} {
		t.Run(fault, func(t *testing.T) {
			_, instance, _, mapping, _, _ := persistentMountFixture(t, "pvc")
			scope := &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}
			switch fault {
			case "owner":
				mapping.UserID++
				scope.Mounts[0] = mapping
			case "generation":
				mapping.Generation++
				scope.Mounts[0] = mapping
			case "foreign":
				scope.Mounts[0].InstanceID++
			case "duplicate":
				scope.Mounts = append(scope.Mounts, mapping)
			case "missing":
				scope = nil
			case "stopped":
				instance.Status = "stopped"
			}
			out, err := persistentMountsForInstances(scope, []b.InstanceIdentity{instance})
			if out != nil || err == nil {
				t.Fatal("invalid original SQL projection matched scope")
			}
		})
	}
}

func TestBootstrapSourcePartsIncludesEveryDeclaredInstanceMount(t *testing.T) {
	_, source, _, _, operations := productionModuleFixture(t)
	_, instance, _, mapping, _, _ := persistentMountFixture(t, "pvc")
	source.Instances = []b.InstanceIdentity{instance}
	source.TeamFacts.Teams = nil
	x := &bootstrapSourceRegistryReader{materials: productionCaptureMaterials{Operations: operations, Discovery: &productionSourceDiscovery{PersistentMounts: &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}}}}
	parts, err := x.deriveParts(&bootstrapSourceSQLFacts{inventory: source}, nil)
	if err != nil {
		t.Fatal("complete registered parts rejected", err)
	}
	counts := map[string]int{}
	for _, part := range parts {
		counts[part.Part]++
	}
	if counts["instance_7_extra"] != 1 || counts["instance_7_workspace"] != 1 || counts[b.UsersInstancesDatabasePart] != 1 {
		t.Fatal("part missing or duplicate", counts)
	}
	x.materials.Discovery.PersistentMounts.Mounts[0].Generation++
	if parts, err := x.deriveParts(&bootstrapSourceSQLFacts{inventory: source}, nil); err == nil || parts != nil {
		t.Fatal("registry adopted stale instance generation")
	}
}

func TestOriginalInstanceMountPinChecksRejectDriftWithoutGrantingAuthority(t *testing.T) {
	for _, fault := range []string{"none", "pod", "source", "node", "owner"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, pod, mapping, _, objects := persistentMountFixture(t, "pvc")
			scope := &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}
			objects = append(objects, pod)
			switch fault {
			case "pod":
				pod.UID = "replacement"
			case "source":
				pod.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "replacement"
			case "node":
				objects[0].(*corev1.Node).UID = "replacement"
			case "owner":
				instance.UserID++
			}
			client := fake.NewSimpleClientset(objects...)
			err := checkInstancePersistentMountPins(context.Background(), client, cfg, instance, pod, scope)
			if (err == nil) != (fault == "none") {
				t.Fatal("pin result", fault, err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("pin check wrote resource")
				}
			}
		})
	}
}

func TestOriginalMountInputDiagnosticAndEveryFieldChangesSignedScope(t *testing.T) {
	_, _, _, mapping, _, _ := persistentMountFixture(t, "pvc")
	materials := productionCaptureMaterials{Discovery: &productionSourceDiscovery{PersistentMounts: &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}}}
	before, _ := sourceMetadataScope(materials)
	raw, _ := json.Marshal(materials)
	for _, field := range []string{"UserID", "Generation", "InstanceID", "DataPath", "PodUID", "PodSpecSHA256", "NodeUID", "VolumeSourceSHA256"} {
		var changed productionCaptureMaterials
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		v := reflect.ValueOf(&changed.Discovery.PersistentMounts.Mounts[0]).Elem().FieldByName(field)
		if v.Kind() == reflect.String {
			v.SetString(v.String() + "changed")
		} else {
			v.SetInt(v.Int() + 1)
		}
		after, err := sourceMetadataScope(changed)
		if err != nil || after == before {
			t.Fatal("scope omitted original input", field)
		}
	}
	err := mountInputError("sql_mount_owner_generation_mismatch", 7, "extra")
	var diagnostic *InstanceMountInputError
	if !errors.Is(err, d.ErrNotReady) || !errors.As(err, &diagnostic) || diagnostic.InstanceID != 7 || diagnostic.MountID != "extra" {
		t.Fatal("stable nonsecret diagnostic lost")
	}
}

func TestOriginalInstanceMountBuilderSeparatesUsersOnSharedRuntime(t *testing.T) {
	cfg, instance, spec, layout, _, objects := originalMountInputFixture(t)
	other, otherSpec, otherLayout := instance, spec, layout
	other.ID, other.UserID, other.Generation, other.Workspace = 8, 3, 4, "/workspaces/3/8"
	otherSpec.Source = other
	otherLayout.InstanceID, otherLayout.DataPath = 8, "/persist/3/8"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, err := BuildOriginalInstanceMountScope(ctx, fake.NewSimpleClientset(objects...), cfg, []b.InstanceIdentity{instance, other}, []b.RuntimeWriterSpec{spec, otherSpec}, []InstancePersistentMountLayout{otherLayout, layout})
	var scope productionPersistentMountScope
	if err != nil || json.Unmarshal(raw, &scope) != nil || len(scope.Mounts) != 2 || scope.Mounts[0].InstanceID != 7 || scope.Mounts[1].UserID != 3 || scope.Mounts[1].Generation != 4 {
		t.Fatal("shared Pod lost individual owner/generation binding", err)
	}
	otherLayout.DataPath = layout.DataPath
	if raw, err := BuildOriginalInstanceMountScope(ctx, fake.NewSimpleClientset(objects...), cfg, []b.InstanceIdentity{instance, other}, []b.RuntimeWriterSpec{spec, otherSpec}, []InstancePersistentMountLayout{layout, otherLayout}); err == nil || raw != nil {
		t.Fatal("different instances adopted the same physical extra root")
	}
}

func TestOriginalInstanceMountObservationProjectionIsDiagnosticAndRedacted(t *testing.T) {
	cfg, instance, spec, _, pod, _ := originalMountInputFixture(t)
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "PRIVATE_ENV", Value: "PRIVATE_PASSWORD"}}
	pod.Spec.Containers[0].Args = []string{"PRIVATE_ARGUMENT"}
	spec.Endpoint = "https://PRIVATE_ENDPOINT"
	row := projectInstanceMountObservation(instance, spec, pod, cfg, nil)
	raw, err := json.Marshal(row)
	if err != nil || strings.Contains(string(raw), "PRIVATE_") || row.InstanceID != instance.ID || row.UserID != instance.UserID || row.Generation != instance.Generation || row.PodSpecSHA256 != kube.ContentHash(pod.Spec) || row.RuntimeBindingSHA256 != kube.ContentHash(spec) || len(row.Mounts) != 2 || len(row.Issues) != 1 || row.Issues[0].Code != "original_mount_scope_required" {
		t.Fatal("diagnostic leaked sensitive material or lost owner scope", string(raw), err)
	}
	instance.Status = "stopped"
	stopped := projectInstanceMountObservation(instance, b.RuntimeWriterSpec{}, nil, cfg, nil)
	if stopped.RuntimePod != "" || len(stopped.Mounts) != 0 || len(stopped.Issues) != 1 || stopped.Issues[0].Code != "stopped_original_snapshot_and_witness_required" {
		t.Fatal("stopped instance derived a current runtime mount")
	}
}

func TestOriginalInstanceMountObservationRequiresOriginalAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	service := &DeploymentService{}
	got, err := service.ObserveInstanceMountInputs(ctx)
	if err == nil || got.Version != "" || got.Instances != nil || got.DiagnosticOnly {
		t.Fatal("diagnostic bypassed original source/deployment checks")
	}
}

func TestOriginalInstanceMountSequenceRechecksSelectedPins(t *testing.T) {
	cfg, _, _, mapping, _, objects := persistentMountFixture(t, "pvc")
	_, _, pod, _, _, _ := persistentMountFixture(t, "pvc")
	cfg.NamespaceUID = "namespace-original"
	objects = append(objects, pod, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: "namespace-original"}})
	sequence := &OriginalCaptureSequence{core: cfg}
	material := productionCaptureMaterials{Discovery: &productionSourceDiscovery{PersistentMounts: &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}}}
	client := fake.NewSimpleClientset(objects...)
	if err := sequence.observeMappings(context.Background(), client, material); err != nil {
		t.Fatal("selected metadata pins", err)
	}
	material.Discovery.PersistentMounts.Mounts[0].PodUID = "replacement"
	if err := sequence.observeMappings(context.Background(), client, material); err == nil {
		t.Fatal("finalizer accepted changed source pin")
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" {
			t.Fatal("pin recheck performed mutations")
		}
	}
}
