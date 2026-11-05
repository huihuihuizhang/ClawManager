package systembackupexecution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func inlineNFSFixture(t *testing.T) (WorkspaceCapture, b.InstanceIdentity, *fake.Clientset) {
	t.Helper()
	var random [8]byte
	if _, e := rand.Read(random[:]); e != nil {
		t.Fatal(e)
	}
	suffix := hex.EncodeToString(random[:])
	ns, service, podName, claimName, pvName, nodeName := "storage-"+suffix, "service-"+suffix, "pod-"+suffix, "claim-"+suffix, "pv-"+suffix, "node-"+suffix
	uid := func(name string) types.UID { return types.UID(name + "-uid") }
	provider := &OriginalNFSProvider{Namespace: ns, NamespaceUID: string(uid(ns)), Service: service, ServiceUID: string(uid(service)), EndpointsUID: string(uid("ep")), Pod: podName, PodUID: string(uid(podName)), Claim: claimName, ClaimUID: string(uid(claimName)), PV: pvName, PVUID: string(uid(pvName)), Node: nodeName, NodeUID: string(uid(nodeName)), ExportMountPath: "/exports-" + suffix}
	pv := &core.PersistentVolume{ObjectMeta: meta.ObjectMeta{Name: pvName, UID: uid(pvName)}, Spec: core.PersistentVolumeSpec{ClaimRef: &core.ObjectReference{Namespace: ns, Name: claimName, UID: uid(claimName)}, PersistentVolumeSource: core.PersistentVolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/srv/storage-" + suffix}}}}
	provider.PVSpec = pv.Spec.DeepCopy()
	objects := fake.NewSimpleClientset(
		&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns, UID: uid(ns)}},
		&core.Service{ObjectMeta: meta.ObjectMeta{Name: service, Namespace: ns, UID: uid(service)}, Spec: core.ServiceSpec{ClusterIP: "10.97.1.2", Selector: map[string]string{"source": "export-" + suffix}}},
		&core.Endpoints{ObjectMeta: meta.ObjectMeta{Name: service, Namespace: ns, UID: uid("ep")}, Subsets: []core.EndpointSubset{{Addresses: []core.EndpointAddress{{IP: "10.2.1.5", TargetRef: &core.ObjectReference{Kind: "Pod", Namespace: ns, Name: podName, UID: uid(podName)}}}}}},
		&core.Pod{ObjectMeta: meta.ObjectMeta{Name: podName, Namespace: ns, UID: uid(podName), Labels: map[string]string{"source": "export-" + suffix}}, Spec: core.PodSpec{NodeName: nodeName, Containers: []core.Container{{Name: "exporter", VolumeMounts: []core.VolumeMount{{Name: "data", MountPath: provider.ExportMountPath}}}}, Volumes: []core.Volume{{Name: "data", VolumeSource: core.VolumeSource{PersistentVolumeClaim: &core.PersistentVolumeClaimVolumeSource{ClaimName: claimName}}}}}, Status: core.PodStatus{PodIP: "10.2.1.5"}},
		&core.PersistentVolumeClaim{ObjectMeta: meta.ObjectMeta{Name: claimName, Namespace: ns, UID: uid(claimName)}, Spec: core.PersistentVolumeClaimSpec{VolumeName: pvName}, Status: core.PersistentVolumeClaimStatus{Phase: core.ClaimBound}}, pv,
		&core.Node{ObjectMeta: meta.ObjectMeta{Name: nodeName, UID: uid(nodeName)}})
	workspace := WorkspaceCapture{NFS: &NFSWorkspace{Server: "10.97.1.2", Export: "/", Provider: provider, OriginalPaths: []OriginalNFSInstancePath{{InstanceID: 7, UserID: 3, Generation: 2, SubPath: "users/3/instances/7"}}}, Node: "stage-" + suffix}
	instance := b.InstanceIdentity{ID: 7, UserID: 3, Generation: 2, Workspace: "/work/users/3/instances/7", Namespace: "consumer-" + suffix}
	return workspace, instance, objects
}

func TestOriginalInlineNFSUsesActualSQLSubPathWithoutInstallationRename(t *testing.T) {
	for round := 0; round < 8; round++ {
		cfg, instance, client := inlineNFSFixture(t)
		if !cfg.validSource("installation_random") {
			t.Fatal("original scoped NFS shape rejected")
		}
		if instance.Namespace == cfg.NFS.Provider.Namespace {
			t.Fatal("fixture must cover cross-namespace provider")
		}
		if e := cfg.NFS.recheckOriginalProvider(context.Background(), client); e != nil {
			t.Fatal(e)
		}
		s := &DeploymentService{Config: DeploymentConfig{Workspace: cfg, RuntimeSources: &RuntimeSourceConfig{WorkspaceRoot: "/work"}}}
		got, e := productionInstanceSubPath(s, instance)
		if e != nil || got != "users/3/instances/7" {
			t.Fatalf("actual consumer path %q %v", got, e)
		}
		r := kube.JobRequest{Identity: kube.Identity{Namespace: instance.Namespace, Name: "capture-one", Owner: "owner-one"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "capture", Command: []string{"/worker", "capture"}, Source: core.Volume{Name: "data", VolumeSource: core.VolumeSource{NFS: &core.NFSVolumeSource{Server: cfg.NFS.Server, Path: cfg.NFS.Export}}}, SourceSubPath: got, StagingClaim: "stage", DeadlineSeconds: 120, NodeName: cfg.Node}
		job, e := kube.Job(r)
		if e != nil {
			t.Fatal(e)
		}
		if job.Spec.Template.Spec.Volumes[0].NFS == nil || !job.Spec.Template.Spec.Volumes[0].NFS.ReadOnly || job.Spec.Template.Spec.Containers[0].VolumeMounts[0].SubPath != got || !job.Spec.Template.Spec.Containers[0].VolumeMounts[0].ReadOnly {
			t.Fatal("worker did not keep NFS/subpath/read-only binding")
		}
		for _, a := range client.Actions() {
			if a.GetVerb() != "get" {
				t.Fatal("provider identity check mutated API")
			}
		}
	}
}

func TestOriginalInlineNFSRejectsSQLIdentityPathAndOverlapDrift(t *testing.T) {
	for _, fault := range []string{"instance", "user", "generation", "path", "root", "parent-overlap", "escape"} {
		t.Run(fault, func(t *testing.T) {
			cfg, instance, _ := inlineNFSFixture(t)
			switch fault {
			case "instance":
				instance.ID++
			case "user":
				instance.UserID++
			case "generation":
				instance.Generation++
			case "path":
				instance.Workspace = "/work/foreign/data"
			case "root":
				cfg.NFS.OriginalPaths[0].SubPath = ""
			case "parent-overlap":
				cfg.NFS.OriginalPaths = append(cfg.NFS.OriginalPaths, OriginalNFSInstancePath{InstanceID: 8, UserID: 3, Generation: 1, SubPath: "users/3"})
			case "escape":
				cfg.NFS.OriginalPaths[0].SubPath = "../foreign"
			}
			if _, e := originalNFSInstanceSubPath(cfg, "/work", instance); e == nil {
				t.Fatal("foreign/expanded SQL source accepted")
			}
		})
	}
}

func TestOriginalInlineNFSSameNamesDifferentNativeUIDOrPVSpecRefuse(t *testing.T) {
	for _, fault := range []string{"namespace", "service", "endpoint", "pod", "claim", "pv", "node", "pv-spec"} {
		t.Run(fault, func(t *testing.T) {
			cfg, _, client := inlineNFSFixture(t)
			p := cfg.NFS.Provider
			switch fault {
			case "namespace":
				p.NamespaceUID += "replaced"
			case "service":
				p.ServiceUID += "replaced"
			case "endpoint":
				p.EndpointsUID += "replaced"
			case "pod":
				p.PodUID += "replaced"
			case "claim":
				p.ClaimUID += "replaced"
			case "pv":
				p.PVUID += "replaced"
			case "node":
				p.NodeUID += "replaced"
			case "pv-spec":
				p.PVSpec.HostPath.Path += "/foreign"
			}
			if e := cfg.NFS.recheckOriginalProvider(context.Background(), client); e == nil {
				t.Fatal("same-name replacement or volume remap accepted")
			}
		})
	}
}
