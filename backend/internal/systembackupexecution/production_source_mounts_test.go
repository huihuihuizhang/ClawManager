package systembackupexecution

import (
	"context"
	"reflect"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Only metadata GETs are modelled. These are not source-authority, actual
// stop/restore, mountability or storage tests; no fake "Passed" enters production.
func persistentMountFixture(t *testing.T, storage string) (DeploymentConfig, b.InstanceIdentity, *corev1.Pod, productionPersistentMountBinding, productionInstanceMount, []runtime.Object) {
	t.Helper()
	cfg := runtimeDeploymentFixture(t)
	cfg.Workspace.Node = "node-1"
	cfg.Security.NodeUIDs = map[string]string{"node-1": "node-uid"}
	instance := b.InstanceIdentity{ID: 7, UserID: 2, Generation: 3, Mode: "lite", OS: "linux", Type: "openclaw", Status: "running", Workspace: "/workspaces/2/7"}
	volume := corev1.Volume{Name: "extra", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "extra-data"}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}}
	objects := []runtime.Object{node}
	switch storage {
	case "pvc":
		claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: "extra-data", UID: "extra-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "extra-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
		pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "extra-pv", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: cfg.Namespace, Name: claim.Name, UID: claim.UID}, PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "fixture.invalid", VolumeHandle: "fixture"}}}}
		cfg.Security.Volumes = append(cfg.Security.Volumes, kube.MountIdentity{Volume: "extra", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)})
		objects = append(objects, claim, pv)
	case "hostpath":
		directory := corev1.HostPathDirectory
		volume.VolumeSource = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data/agents", Type: &directory}}
	case "nfs":
		cfg.Workspace.NFS = &NFSWorkspace{Server: "nfs.internal", Export: "/data"}
		cfg.Workspace.SubPath = "installations/original"
		volume.VolumeSource = corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: cfg.Workspace.NFS.Server, Path: cfg.Workspace.NFS.Export}}
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: "runtime", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node-1", Volumes: []corev1.Volume{volume}, Containers: []corev1.Container{{Name: "agent", VolumeMounts: []corev1.VolumeMount{{Name: "extra", MountPath: "/persist", SubPath: "installations/original"}}}}}}
	mapping := productionPersistentMountBinding{InstanceID: 7, UserID: 2, Generation: 3, MountID: "extra", Container: "agent", Volume: "extra", MountPath: "/persist", DataPath: "/persist/2/7", Namespace: cfg.Namespace, Pod: pod.Name, PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec), Node: node.Name, NodeUID: string(node.UID), VolumeSourceSHA256: kube.ContentHash(volume.VolumeSource)}
	base := productionInstanceMount{InstanceID: 7, MountID: "workspace"}
	return cfg, instance, pod, mapping, base, objects
}

func TestPersistentMountMetadataResolvesOnlyExactPinnedSource(t *testing.T) {
	for _, storage := range []string{"pvc", "hostpath", "nfs"} {
		t.Run(storage, func(t *testing.T) {
			cfg, instance, pod, mapping, base, objects := persistentMountFixture(t, storage)
			before := pod.DeepCopy()
			if (&productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}).validate() != nil {
				t.Fatal("fixture mapping rejected")
			}
			client := fake.NewSimpleClientset(objects...)
			got, identity, err := resolvePersistentMount(context.Background(), client, cfg, instance, pod, mapping, base)
			if err != nil || !got.DataOnly || got.MountID != "extra" || got.SubPath != "installations/original/2/7" || got.NodeName != "node-1" || !reflect.DeepEqual(before, pod) {
				t.Fatal("exact mount resolution failed or mutated source", err)
			}
			if (identity != nil) != (storage == "pvc") {
				t.Fatal("wrong identity kind")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("metadata resolver mutated resources")
				}
			}
		})
	}
}

func TestPersistentMountMetadataRejectsDriftAndUnscopedRoots(t *testing.T) {
	for _, fault := range []string{"namespace", "instance", "pod-uid", "spec", "node-uid", "staging-node", "non-linux", "node-deleted", "claim-replaced", "claim-unbound", "block-claim", "pv-replaced", "claim-owner", "missing-pin", "source-hash", "container", "whole-volume", "subpath-expr", "nested-overlay", "nested-ancestor", "unsupported-volume", "ambiguous-volume"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, pod, mapping, base, objects := persistentMountFixture(t, "pvc")
			switch fault {
			case "namespace":
				mapping.Namespace = "foreign"
			case "instance":
				mapping.InstanceID++
			case "pod-uid":
				pod.UID = "replacement"
			case "spec":
				pod.Spec.Containers[0].Image = "changed"
			case "node-uid":
				objects[0].(*corev1.Node).UID = "replacement"
			case "staging-node":
				cfg.Workspace.Node = "other-node"
				cfg.Security.NodeUIDs["other-node"] = "other-uid"
			case "non-linux":
				objects[0].(*corev1.Node).Labels[corev1.LabelOSStable] = "windows"
			case "node-deleted":
				now := metav1.Now()
				objects[0].(*corev1.Node).DeletionTimestamp = &now
			case "claim-replaced":
				objects[1].(*corev1.PersistentVolumeClaim).UID = "replacement"
			case "claim-unbound":
				objects[1].(*corev1.PersistentVolumeClaim).Status.Phase = corev1.ClaimPending
			case "block-claim":
				mode := corev1.PersistentVolumeBlock
				objects[1].(*corev1.PersistentVolumeClaim).Spec.VolumeMode = &mode
			case "pv-replaced":
				objects[2].(*corev1.PersistentVolume).UID = "replacement"
			case "claim-owner":
				objects[2].(*corev1.PersistentVolume).Spec.ClaimRef.UID = types.UID("foreign")
			case "missing-pin":
				cfg.Security.Volumes = nil
			case "source-hash":
				mapping.VolumeSourceSHA256 = mapping.PodSpecSHA256
			case "container":
				mapping.Container = "missing"
			case "whole-volume":
				mapping.DataPath = "/persist"
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = ""
			case "subpath-expr":
				pod.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(UNRESOLVED)"
			case "nested-overlay":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: mapping.DataPath + "/nested"})
			case "nested-ancestor":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: "/persist/2"})
			case "ambiguous-volume":
				directory := corev1.HostPathDirectory
				pod.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/foreign", Type: &directory}
			case "unsupported-volume":
				pod.Spec.Volumes[0].VolumeSource = corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
			}
			// For topology faults authorize the new source shape, so the resolver
			// must reject the unsafe topology rather than only its old digest.
			if fault == "whole-volume" || fault == "subpath-expr" || fault == "nested-overlay" || fault == "nested-ancestor" || fault == "unsupported-volume" || fault == "ambiguous-volume" {
				mapping.PodSpecSHA256 = kube.ContentHash(pod.Spec)
				mapping.VolumeSourceSHA256 = kube.ContentHash(pod.Spec.Volumes[0].VolumeSource)
			}
			got, pin, err := resolvePersistentMount(context.Background(), fake.NewSimpleClientset(objects...), cfg, instance, pod, mapping, base)
			if err == nil || !reflect.DeepEqual(got, productionInstanceMount{}) || pin != nil {
				t.Fatal("unsafe metadata produced a partial mount", fault)
			}
		})
	}
}

func TestPersistentMountNFSRetainsOriginalStagingPlacement(t *testing.T) {
	cfg, instance, pod, mapping, base, objects := persistentMountFixture(t, "nfs")
	cfg.Workspace.Node = "staging-node"
	cfg.Security.NodeUIDs["staging-node"] = "staging-uid"
	got, _, err := resolvePersistentMount(context.Background(), fake.NewSimpleClientset(objects...), cfg, instance, pod, mapping, base)
	if err != nil || got.NodeName != "staging-node" || mapping.Node != "node-1" {
		t.Fatal("NFS rewrote source identity or escaped staging placement", err)
	}
}

func TestPersistentMountCoverageIncludesSidecarsAndRejectsMissingMappings(t *testing.T) {
	_, instance, pod, mapping, _, _ := persistentMountFixture(t, "pvc")
	if checkPersistentMountCoverage(instance, pod, nil) == nil {
		t.Fatal("unregistered side mount silently omitted")
	}
	if checkPersistentMountCoverage(instance, pod, []productionPersistentMountBinding{mapping}) != nil {
		t.Fatal("registered side mount rejected")
	}
	for _, fault := range []string{"sidecar", "init-writer", "ephemeral", "block", "unknown-storage", "temporary-overlay", "stale-mapping", "duplicate-path"} {
		t.Run(fault, func(t *testing.T) {
			p := pod.DeepCopy()
			declarations := []productionPersistentMountBinding{mapping}
			switch fault {
			case "sidecar":
				p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "tool", VolumeMounts: []corev1.VolumeMount{{Name: "extra", MountPath: "/tool-data"}}})
			case "init-writer":
				p.Spec.InitContainers = []corev1.Container{{Name: "init", VolumeMounts: []corev1.VolumeMount{{Name: "extra", MountPath: "/tool-data"}}}}
			case "ephemeral":
				p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{}}
			case "block":
				p.Spec.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: "extra", DevicePath: "/dev/raw"}}
			case "unknown-storage":
				p.Spec.Volumes[0].VolumeSource = corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "unknown"}}
			case "temporary-overlay":
				p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "temp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
				p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "temp", MountPath: instance.Workspace + "/hidden"})
			case "stale-mapping":
				declarations[0].Volume = "missing"
			case "duplicate-path":
				p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, p.Spec.Containers[0].VolumeMounts[0])
			}
			if checkPersistentMountCoverage(instance, p, declarations) == nil {
				t.Fatal("incomplete coverage accepted", fault)
			}
		})
	}
}

func TestPersistentMountOverlapRejectsPhysicalAliases(t *testing.T) {
	for _, storage := range []string{"pvc", "hostpath", "nfs"} {
		_, _, pod, _, base, _ := persistentMountFixture(t, storage)
		base.Source, base.NodeName, base.SubPath = pod.Spec.Volumes[0], "node-1", "tenant/7"
		other := base
		other.InstanceID, other.MountID, other.SubPath = 8, "extra", "tenant/8"
		if overlappingInstanceMounts([]productionInstanceMount{base, other}) {
			t.Fatal("disjoint roots rejected")
		}
		for _, overlap := range []string{"tenant/7", "tenant/7/nested", "tenant", "."} {
			other.SubPath = overlap
			if !overlappingInstanceMounts([]productionInstanceMount{base, other}) {
				t.Fatal("overlap accepted", storage, overlap)
			}
		}
	}
}

func TestPersistentMountScopeRejectsAmbiguousOrUnsafeOwnerInputs(t *testing.T) {
	for _, fault := range []string{"nil", "version", "primary", "duplicate", "unknown-id", "root", "escape", "foreign-subtree", "unbound-pod", "unbound-node", "missing-source-hash", "oversized-part"} {
		t.Run(fault, func(t *testing.T) {
			_, _, _, mapping, _, _ := persistentMountFixture(t, "pvc")
			scope := &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}
			switch fault {
			case "nil":
				scope = nil
			case "version":
				scope.Version = "future"
			case "primary":
				scope.Mounts[0].MountID = "workspace"
			case "duplicate":
				scope.Mounts = append(scope.Mounts, mapping)
			case "unknown-id":
				scope.Mounts[0].InstanceID = 0
			case "root":
				scope.Mounts[0].MountPath = "/"
			case "escape":
				scope.Mounts[0].DataPath = "/persist/../escape"
			case "foreign-subtree":
				scope.Mounts[0].DataPath = "/persist-other/user"
			case "unbound-pod":
				scope.Mounts[0].PodUID = ""
			case "unbound-node":
				scope.Mounts[0].NodeUID = ""
			case "missing-source-hash":
				scope.Mounts[0].VolumeSourceSHA256 = ""
			case "oversized-part":
				scope.Mounts[0].MountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			if scope.validate() == nil {
				t.Fatal("invalid original scope accepted", fault)
			}
		})
	}
}

func TestPersistentMountPreflightRefusesMissingAndStoppedSourceWithoutActions(t *testing.T) {
	for _, fault := range []string{"missing-scope", "stopped", "pro"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, _, _, _, _ := persistentMountFixture(t, "pvc")
			cfg.CaptureScope = "six-part"
			service := &DeploymentService{Config: cfg, captureMaterials: &productionCaptureMaterials{Discovery: &productionSourceDiscovery{PersistentMounts: &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{}}}}}
			switch fault {
			case "missing-scope":
				service.captureMaterials.Discovery.PersistentMounts = nil
			case "stopped":
				instance.Status = "stopped"
			case "pro":
				instance.Mode = "pro"
			}
			client := fake.NewSimpleClientset()
			if service.checkRuntimeWorkspace(context.Background(), client, []b.InstanceIdentity{instance}) == nil || len(client.Actions()) != 0 {
				t.Fatal("unsupported source touched resources or opened admission")
			}
		})
	}
}
