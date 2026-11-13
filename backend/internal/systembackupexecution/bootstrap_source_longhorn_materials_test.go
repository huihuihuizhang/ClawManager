package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func longhornAuthorFixture() (*productionMetadataClients, DeploymentConfig, *productionPersistentMountScope, map[string]originalLonghornSource) {
	labels := map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1", "instance-id": "2"}
	controller := true
	objects := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-system", UID: "system-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-user-1", UID: "tenant-uid", Labels: map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1"}}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "longhorn-system", UID: "provider-uid"}},
	}
	for _, node := range []string{"node1", "node2"} {
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: node, UID: types.UID(node + "-uid")}, Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}})
	}
	volume := func(ns, name string, mode corev1.PersistentVolumeAccessMode) kube.MountIdentity {
		c := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name + "-uid")},
			Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pvc-" + name, AccessModes: []corev1.PersistentVolumeAccessMode{mode}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
		v := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: c.Spec.VolumeName, UID: types.UID(name + "-pv-uid")}, Spec: corev1.PersistentVolumeSpec{
			AccessModes: c.Spec.AccessModes, ClaimRef: &corev1.ObjectReference{Namespace: ns, Name: name, UID: c.UID},
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "pvc-" + name, FSType: "ext4"}}}}
		objects = append(objects, c, v)
		return kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: name, UID: string(c.UID), PVName: v.Name, PVUID: string(v.UID), SHA256: kube.ContentHash(v.Spec)}
	}
	tenant, shared := volume("test-user-1", "pro", corev1.ReadWriteOnce), volume("test-system", "shared", corev1.ReadWriteMany)
	pod := func(ns, name, node, claim, mount string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name + "-uid")},
			Spec: corev1.PodSpec{NodeName: node, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}},
				Containers: []corev1.Container{{Name: "runtime", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: mount}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "runtime", Ready: true, ContainerID: "containerd://" + strings.Repeat("a", 64), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	}
	pro := pod("test-user-1", "pro-pod", "node1", "pro", "/config")
	pro.Labels = labels
	pro.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "pro-rs", UID: "rs-uid", Controller: &controller}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "pro", Namespace: pro.Namespace, UID: "deployment-uid"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "pro-rs", Namespace: pro.Namespace, UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Template: dep.Spec.Template}}
	mount := runningTenantProMount{Source: b.InstanceIdentity{ID: 2, UserID: 1, Generation: 0, Mode: "pro", Backend: "desktop", OS: "linux", Status: "running", Pod: pro.Name, Namespace: pro.Namespace, Workspace: "/config"},
		NamespaceUID: "tenant-uid", PodUID: string(pro.UID), PodSpecSHA256: kube.ContentHash(pro.Spec), ReplicaSetUID: string(rs.UID), Deployment: dep.Name, DeploymentUID: string(dep.UID), Identity: tenant}
	provider := pod("longhorn-system", "share-manager-pvc-shared", "node2", "unused", "/export")
	provider.OwnerReferences = []metav1.OwnerReference{{APIVersion: "longhorn.io/v1beta2", Kind: "ShareManager", Name: "pvc-shared", UID: "manager-uid", Controller: &controller}}
	objects = append(objects, pro, dep, rs, provider, pod("test-system", "app-1", "node1", "shared", "/workspaces"), pod("test-system", "app-2", "node2", "shared", "/workspaces"))
	custom := []*unstructured.Unstructured{{Object: map[string]any{"apiVersion": "longhorn.io/v1beta2", "kind": "Volume", "metadata": map[string]any{"name": "pvc-shared", "namespace": "longhorn-system", "uid": "volume-uid"}, "status": map[string]any{"shareState": "running", "shareEndpoint": "nfs://10.0.0.20/pvc-shared"}}},
		{Object: map[string]any{"apiVersion": "longhorn.io/v1beta2", "kind": "ShareManager", "metadata": map[string]any{"name": "pvc-shared", "namespace": "longhorn-system", "uid": "manager-uid"}}}}
	clients := &productionMetadataClients{API: fake.NewSimpleClientset(objects...), Dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), custom[0], custom[1])}
	cfg := DeploymentConfig{Namespace: "test-system", NamespaceUID: "system-uid", InstallationID: "test-installation", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"node1": "node1-uid", "node2": "node2-uid"}},
		RuntimeSources: &RuntimeSourceConfig{SharedObserver: &FormalSharedRuntimeObserverConfig{Endpoints: map[string]q.ProofEndpoint{"node1": {URL: "https://10.0.0.1:19443/shared-runtime-lifecycle/v1", ServerURI: "spiffe://test/node1"}, "node2": {URL: "https://10.0.0.2:19443/shared-runtime-lifecycle/v1", ServerURI: "spiffe://test/node2"}}}}}
	sources := map[string]originalLonghornSource{}
	for part, pin := range map[string]kube.MountIdentity{"instance_2_workspace": tenant, "instance_1_workspace": shared, "instance_7_workspace": shared} {
		ns, nsUID, mode := cfg.Namespace, cfg.NamespaceUID, corev1.ReadWriteMany
		if pin == tenant {
			ns, nsUID, mode = pro.Namespace, "tenant-uid", corev1.ReadWriteOnce
		}
		sources[part] = originalLonghornSource{Namespace: ns, NamespaceUID: nsUID, Source: pin, Handle: pin.PVName, AccessMode: mode, ProviderNamespace: "longhorn-system", ProviderUID: "provider-uid"}
	}
	return clients, cfg, &productionPersistentMountScope{Version: persistentMountScopeVersion, RunningTenantPro: []runningTenantProMount{mount}}, sources
}

func TestOriginalLonghornHoldAuthorReadsRWOAndCompleteRWXClientsWithoutTask(t *testing.T) {
	clients, cfg, scope, sources := longhornAuthorFixture()
	out, err := observeOriginalLonghornHoldMaterials(context.Background(), clients, cfg, scope, sources, "spiffe://selected/recovery")
	if err != nil || len(out.Sources) != 2 || len(out.Clients) != 2 {
		t.Fatal("missing original provider/client or shared source not deduplicated", out, err)
	}
	for _, s := range out.Sources {
		if s.Claim != (q.LonghornExt4Claim{}) || s.Attempt != 0 || s.Binding.OperationID != "" || s.Binding.ReservationID != "" || s.Binding.InventorySHA256 != "" || s.Binding.Generation != 0 || s.Binding.FenceEpoch != 0 || !s.Binding.ExpiresAt.IsZero() {
			t.Fatal("installation material manufactured task authority", s)
		}
		if s.Binding.Namespace == "test-user-1" && (s.ProviderNamespace != "test-user-1" || s.ProviderPodName != "pro-pod" || s.MountPoint != "/config") {
			t.Fatal("tenant source inherited provider/runtime identity", s)
		}
	}
	for _, c := range out.Clients {
		if c.PodUID != "" || c.PodName != "" || c.ContainerID != "" || c.Attempt != 0 || c.Claim != (q.LonghornExt4Claim{}) || c.MountPoint != "/workspaces" || c.NFSSource != "10.0.0.20:/pvc-shared" {
			t.Fatal("RWX template is bound to a fake task/client", c)
		}
	}
	for _, a := range clients.API.(*fake.Clientset).Actions() {
		if a.GetVerb() != "get" && a.GetVerb() != "list" {
			t.Fatal("material author mutated source", a)
		}
	}
	for _, a := range clients.Dynamic.(*dynamicfake.FakeDynamicClient).Actions() {
		if a.GetVerb() != "get" {
			t.Fatal("material author mutated provider", a)
		}
	}
}

func TestOriginalLonghornHoldAuthorRejectsSourceProviderAndClientDrift(t *testing.T) {
	for _, fault := range []string{"node", "missing-node-endpoint", "tenant-pod", "claim", "pv", "provider-owner", "provider-process", "ambiguous-client-mount", "missing-tenant", "unknown-mode", "detached-share"} {
		t.Run(fault, func(t *testing.T) {
			clients, cfg, scope, sources := longhornAuthorFixture()
			ctx := context.Background()
			api := clients.API
			switch fault {
			case "detached-share":
				resource := clients.Dynamic.Resource(schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}).Namespace("longhorn-system")
				v, _ := resource.Get(ctx, "pvc-shared", metav1.GetOptions{})
				v.Object["status"] = map[string]any{"state": "detached", "shareState": "stopped"}
				_, _ = resource.Update(ctx, v, metav1.UpdateOptions{})
			case "node":
				v, _ := api.CoreV1().Nodes().Get(ctx, "node1", metav1.GetOptions{})
				v.UID = "replacement"
				_, _ = api.CoreV1().Nodes().Update(ctx, v, metav1.UpdateOptions{})
			case "missing-node-endpoint":
				delete(cfg.RuntimeSources.SharedObserver.Endpoints, "node1")
			case "tenant-pod":
				v, _ := api.CoreV1().Pods("test-user-1").Get(ctx, "pro-pod", metav1.GetOptions{})
				v.UID = "replacement"
				_, _ = api.CoreV1().Pods(v.Namespace).Update(ctx, v, metav1.UpdateOptions{})
			case "claim":
				v, _ := api.CoreV1().PersistentVolumeClaims("test-user-1").Get(ctx, "pro", metav1.GetOptions{})
				v.UID = "replacement"
				_, _ = api.CoreV1().PersistentVolumeClaims(v.Namespace).Update(ctx, v, metav1.UpdateOptions{})
			case "pv":
				v, _ := api.CoreV1().PersistentVolumes().Get(ctx, "pvc-pro", metav1.GetOptions{})
				v.Spec.CSI.VolumeHandle = "replacement"
				_, _ = api.CoreV1().PersistentVolumes().Update(ctx, v, metav1.UpdateOptions{})
			case "provider-owner", "provider-process":
				v, _ := api.CoreV1().Pods("longhorn-system").Get(ctx, "share-manager-pvc-shared", metav1.GetOptions{})
				if fault == "provider-owner" {
					v.OwnerReferences[0].UID = "replacement"
				} else {
					v.Status.ContainerStatuses[0].State.Running = nil
				}
				_, _ = api.CoreV1().Pods(v.Namespace).Update(ctx, v, metav1.UpdateOptions{})
			case "ambiguous-client-mount":
				v, _ := api.CoreV1().Pods("test-system").Get(ctx, "app-1", metav1.GetOptions{})
				v.Name = "app-3"
				v.UID = "new-pod"
				v.Spec.Containers[0].VolumeMounts[0].MountPath = "/another-root"
				_, _ = api.CoreV1().Pods(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
			case "missing-tenant":
				scope.RunningTenantPro = nil
			case "unknown-mode":
				v := sources["instance_2_workspace"]
				v.AccessMode = corev1.ReadOnlyMany
				sources["instance_2_workspace"] = v
			}
			_, err := observeOriginalLonghornHoldMaterials(ctx, clients, cfg, scope, sources, "spiffe://selected/recovery")
			if err == nil {
				t.Fatal("changed native source accepted")
			}
			if fault == "detached-share" {
				var failure *WriterAPIReadFailure
				if !errors.As(err, &failure) || failure.Step != "longhorn_share_manager_state" || failure.Reason != "validation" {
					t.Fatal("detached shared volume lacks a stable refusal reason")
				}
			}
		})
	}
}

func TestOriginalLonghornHoldAuthorDetectsProviderEndpointChangeBetweenReads(t *testing.T) {
	clients, cfg, scope, sources := longhornAuthorFixture()
	ctx := context.Background()
	before, err := observeOriginalLonghornHoldMaterials(ctx, clients, cfg, scope, sources, "spiffe://selected/recovery")
	if err != nil {
		t.Fatal(err)
	}
	r := clients.Dynamic.Resource(schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}).Namespace("longhorn-system")
	v, _ := r.Get(ctx, "pvc-shared", metav1.GetOptions{})
	v.Object["status"].(map[string]any)["shareEndpoint"] = "nfs://10.0.0.21/pvc-shared"
	if _, err = r.Update(ctx, v, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := observeOriginalLonghornHoldMaterials(ctx, clients, cfg, scope, sources, "spiffe://selected/recovery")
	if err != nil || reflect.DeepEqual(before, after) {
		t.Fatal("paired mount author cannot detect endpoint drift", err)
	}
}

func TestOriginalLonghornRecoveryPeerRequiresActualPinnedClientPKI(t *testing.T) {
	dir, now := t.TempDir(), time.Now().UTC()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "original"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	want := "spiffe://test.invalid/system-backup/test-installation/namespace/system-uid/controller-service-account/controller-uid"
	uri, _ := url.Parse(want)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	write := func(name, kind string, raw []byte) (string, string) {
		p := filepath.Join(dir, name)
		value := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw})
		if err := os.WriteFile(p, value, 0600); err != nil {
			t.Fatal(err)
		}
		return p, hash(value)
	}
	o := &FormalSharedRuntimeObserverConfig{}
	o.CAFile, o.CASHA256 = write("ca.pem", "CERTIFICATE", caDER)
	o.CertificateFile, o.CertificateSHA256 = write("client.pem", "CERTIFICATE", der)
	o.KeyFile, o.KeySHA256 = write("client-key.pem", "PRIVATE KEY", keyDER)
	cfg := DeploymentConfig{TrustDomain: "test.invalid", InstallationID: "test-installation", NamespaceUID: "system-uid", RuntimeSources: &RuntimeSourceConfig{SharedObserver: o}}
	m := productionCaptureMaterials{Discovery: &productionSourceDiscovery{ControllerServiceAccountUID: "controller-uid"}}
	got, err := originalLonghornRecoveryURI(cfg, m, now)
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	for _, fault := range []string{"expired", "wrong-controller", "wrong-pin", "wrong-key"} {
		t.Run(fault, func(t *testing.T) {
			copyCfg, copyM, copyO := cfg, m, *o
			copyCfg.RuntimeSources = &RuntimeSourceConfig{SharedObserver: &copyO}
			d := *m.Discovery
			copyM.Discovery = &d
			stamp := now
			switch fault {
			case "expired":
				stamp = now.Add(2 * time.Hour)
			case "wrong-controller":
				d.ControllerServiceAccountUID = "foreign"
			case "wrong-pin":
				copyO.CertificateSHA256 = strings.Repeat("b", 64)
			case "wrong-key":
				_, other, _ := ed25519.GenerateKey(rand.Reader)
				raw, _ := x509.MarshalPKCS8PrivateKey(other)
				copyO.KeyFile, copyO.KeySHA256 = write("other-key.pem", "PRIVATE KEY", raw)
			}
			if _, err := originalLonghornRecoveryURI(copyCfg, copyM, stamp); err == nil {
				t.Fatal("unqualified recovery peer accepted")
			}
		})
	}
}
