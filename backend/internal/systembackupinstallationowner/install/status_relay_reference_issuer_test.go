package install

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// Actual original IssueCapture/ImportCapture then distinct issuer, real native
// mTLS, original enrollment/admin/head SQL model and finite Kubernetes model.
// It creates no task/Job, no fake prepared relay check and no complete bootstrap.
func TestStatusRelayReferenceIssuerUsesOriginalEnrollmentAndCurrentTLS(t *testing.T) {
	f := newAuthorityFixture(t)
	d, requests := statusRelayTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	target := f.i.plan.Target
	d.Controller = BootstrapSourceController{Namespace: target.Namespace, NamespaceUID: target.NamespaceUID, Deployment: "relay-controller", DeploymentUID: "relay-deployment-uid", ReplicaSet: "relay-controller-rs", ReplicaSetUID: "relay-rs-uid", Pod: "relay-controller-pod", PodUID: "relay-pod-uid", ServiceAccount: "relay-controller", ServiceAccountUID: "relay-sa-uid"}
	u, e := url.Parse(d.Endpoint)
	if e != nil {
		t.Fatal(e)
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil {
		t.Fatal(e)
	}
	controller := true
	one := int32(1)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: d.Controller.Pod, Namespace: target.Namespace, UID: "relay-pod-uid", ResourceVersion: "31", Labels: map[string]string{"app": "relay-transport"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: d.Controller.ReplicaSet, UID: "relay-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: d.Controller.ServiceAccount, NodeName: "node", Containers: []corev1.Container{{Name: d.Container, Image: "explicit-component-image"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: u.Hostname(), ContainerStatuses: []corev1.ContainerStatus{{Name: d.Container, ImageID: d.ContainerImageID, ContainerID: "containerd://relay-current", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}}}
	podRaw, e := json.Marshal(pod.Spec)
	if e != nil {
		t.Fatal(e)
	}
	d.PodSpecSHA256 = hash(podRaw)
	client := f.i.kube.(*fake.Clientset)
	for _, object := range []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: d.Controller.ServiceAccount, Namespace: target.Namespace, UID: "relay-sa-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: d.Controller.Deployment, Namespace: target.Namespace, UID: "relay-deployment-uid"}, Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: d.Controller.ServiceAccount}}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: d.Controller.ReplicaSet, Namespace: target.Namespace, UID: "relay-rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: d.Controller.Deployment, UID: "relay-deployment-uid", Controller: &controller}}}},
		pod,
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: d.Service, Namespace: target.Namespace, UID: "service-uid", ResourceVersion: "41"}, Spec: corev1.ServiceSpec{ClusterIP: u.Hostname(), Selector: map[string]string{"app": "relay-transport"}, Ports: []corev1.ServicePort{{Name: "relay", Protocol: corev1.ProtocolTCP, Port: int32(port)}}}},
		&corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: d.Service, Namespace: target.Namespace, UID: "endpoint-uid", ResourceVersion: "51"}, Subsets: []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: u.Hostname(), TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: d.Controller.Pod, UID: "relay-pod-uid"}}}, Ports: []corev1.EndpointPort{{Name: "relay", Protocol: corev1.ProtocolTCP, Port: int32(port)}}}}},
	} {
		if e := client.Tracker().Add(object); e != nil {
			t.Fatal(e)
		}
	}
	coreRaw, e := json.Marshal(map[string]any{"schema_version": "system-backup-public-deployment.v1", "installation_id": target.InstallationID, "namespace": target.Namespace, "namespace_uid": target.NamespaceUID, "control_url": strings.TrimSuffix(d.Endpoint, "/relay"), "runtime_sources": map[string]any{}})
	if e != nil || os.WriteFile(d.Deployment.File, coreRaw, 0600) != nil {
		t.Fatal("original component core")
	}
	d.Deployment.SHA256 = hash(coreRaw)
	directory := t.TempDir()
	definitionFile := filepath.Join(directory, "relay-definition.json")
	definition, e := canonical(d)
	if e != nil || os.WriteFile(definitionFile, definition, 0600) != nil {
		t.Fatal(e)
	}
	ref, e := StatusRelayReferenceIdentity(definition, hash(definition))
	if e != nil {
		t.Fatal(e)
	}
	// Choose this NEW actual reference before the original capture is signed.
	var values map[string]any
	if json.Unmarshal(f.config.CanonicalJSON(), &values) != nil {
		t.Fatal("config")
	}
	for _, value := range values["references"].([]any) {
		item := value.(map[string]any)
		if item["purpose"] == "status_relay" {
			item["identity_hash"], item["version"] = ref.IdentityHash, ref.Version
		}
	}
	configRaw, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	f.config, e = sec.DecodeBootstrapConfig(configRaw)
	if e != nil {
		t.Fatal(e)
	}
	f.grant.ConfigSHA256 = f.config.SHA256()
	grantRaw, _ := json.Marshal(f.grant)
	f.record.ConfigSHA256, f.record.GrantSHA256 = f.config.SHA256(), hash(grantRaw)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(f.config.CanonicalJSON(), &fields)
	f.record.RegistrySetSHA256, f.record.ReferenceSetSHA256 = hash(fields["registries"]), hash(fields["references"])
	if os.WriteFile(f.files.ConfigFile, f.config.CanonicalJSON(), 0600) != nil {
		t.Fatal("config file")
	}
	f.files.ConfigFileSHA256 = hash(f.config.CanonicalJSON())
	offline, e := ReadPrivateFile(f.files.GrantFile, 16384)
	var grantFile sec.BootstrapGrantFile
	if e != nil || decodeExact(offline, &grantFile) != nil {
		t.Fatal(e)
	}
	grantFile.Grant = f.grant
	offline, e = canonical(grantFile)
	if e != nil || os.WriteFile(f.files.GrantFile, offline, 0600) != nil {
		t.Fatal(e)
	}
	f.files.GrantFileSHA256 = hash(offline)
	selection := bootstrapSourceRegistryFixtureSelection(t, f)
	pack := issueFixture(t, f, ctx)
	if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e != nil {
		t.Fatal(e)
	}
	writes, signs := f.s.writes, f.signs.Load()
	signed, e := f.i.IssueStatusRelayReference(ctx, f.password, f.enrollment, pack, hash(pack), definitionFile, hash(definition), selection, f.files, f.key)
	if e != nil || !ed25519.Verify(f.i.public, append([]byte(statusRelayReferenceDomain), signed.Record...), signed.Signature) {
		t.Fatal("distinct original relay issue", e)
	}
	var record statusRelayReferenceRecord
	if decodeExact(signed.Record, &record) != nil || record.Reference != ref || record.NativeIdentitySHA256 == "" || f.s.writes != writes || f.signs.Load() != signs || requests.Load() != 0 {
		t.Fatal("source association changed SQL/task/provider work")
	}
	revoked, e := f.i.IssueRevocation(ctx, f.password, f.enrollment, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := f.i.ImportRevocation(ctx, f.password, f.enrollment, revoked, hash(revoked)); e != nil {
		t.Fatal(e)
	}
	if _, e := f.i.IssueStatusRelayReference(ctx, f.password, f.enrollment, pack, hash(pack), definitionFile, hash(definition), selection, f.files, f.key); e == nil {
		t.Fatal("revoked original source issued new relay reference")
	}
}
