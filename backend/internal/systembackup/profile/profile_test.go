package profile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func fixture(t *testing.T) (*Driver, control.Task, plan) {
	t.Helper()
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	d := &Driver{Config: Config{ID: "fixture", Namespace: "source", TargetNamespace: "cm-drill-target", WorkerImage: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", ControlURL: "https://127.0.0.1:9443/worker/v1", PolicyVersion: "policy-v1", KeyVersion: "key-v1", SignerID: "signer-v1", TargetStorageClass: "fixture", TargetStorageSize: "1Gi", Staging: map[string]Claim{"source": {"stage", "uid-stage"}, "cm-drill-target": {"stage", "uid-target-stage"}}, Evidence: Claim{"evidence", "uid-evidence"}, MaxFiles: 100, MaxFileBytes: 4096, MaxArchiveBytes: 8192, MaxCompressedBytes: 16384, Source: worker.DatabaseSpec{Name: "source", Address: "127.0.0.1:3306", ServerUUID: "source-uuid", RootCA: []byte("test-ca"), TLSServerName: "localhost", MaxRows: 100, MaxMemoryBytes: 1 << 20}, Target: worker.DatabaseSpec{Name: "cm_drill_target", ServerUUID: "target-uuid"}}, Keys: artifact.SecretKeys{"key-v1": make([]byte, 32)}, Staging: root}
	task := control.Task{ID: "sb-fixture", ProfileRevision: d.Metadata().Revision, Request: control.Request{Kind: "backup", Profile: "fixture"}, Deadline: time.Now().Add(time.Minute).UnixMilli()}
	p := plan{Version: "kubernetes-linux.v1", Task: task.ID, Revision: task.ProfileRevision, Deadline: task.Deadline, Users: 1, Identity: flow.Identity{Task: task.ID, Attempt: task.ID + "-capture", Generation: 1, Phase: "capture"}, Nodes: map[string]string{"node": "node-uid"}}
	return d, task, p
}
func TestBindFreezesAllAdaptersAndRejectsChangedRevision(t *testing.T) {
	d, task, p := fixture(t)
	if e := d.Config.Validate(); e != nil {
		t.Fatal(e)
	}
	w, e := d.newWork(context.Background(), task, p, "database", "capture-database", "source")
	if e != nil {
		t.Fatal(e)
	}
	p.Work = []work{w}
	raw, _ := json.Marshal(p)
	x, e := d.Bind(context.Background(), task, raw)
	if e != nil || len(x.Writers) != 1 || len(x.Capture) != 1 || x.Publish == nil || x.Cleanup == nil {
		t.Fatal("unbound execution", e)
	}
	d.Config.PolicyVersion = "changed"
	if _, e = d.Bind(context.Background(), task, raw); e == nil {
		t.Fatal("new configuration adopted old plan")
	}
}
func TestCaptureBundleRejectsSubstitutionAndAuthenticatesCiphertext(t *testing.T) {
	d, task, p := fixture(t)
	ctx := context.Background()
	if e := d.Staging.Mkdir(task.ID, 0700); e != nil {
		t.Fatal(e)
	}
	root, e := d.Staging.OpenRoot(task.ID)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	w, e := d.newWork(ctx, task, p, "database", "capture-database", "source")
	if e != nil {
		t.Fatal(e)
	}
	p.Work = []work{w}
	key, e := d.Keys.Unwrap(ctx, w.Invocation.Request.Binding, w.Key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	receipt, e := staging.SealFile(ctx, root, w.Invocation.Request.ArtifactName, key, w.Invocation.Request.Binding, func(out io.Writer) error { _, e := io.WriteString(out, "isolated encrypted fixture"); return e })
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(receipt)
	hash, _ := w.Invocation.Hash()
	parts := []flow.Part{{ID: w.ID, Checkpoint: hash, SealedRef: string(raw)}}
	aw, e := d.newWork(ctx, task, p, "assets", "capture-assets", "source")
	if e != nil {
		t.Fatal(e)
	}
	aw.LocalAssets = true
	p.Work = append(p.Work, aw)
	ak, e := d.Keys.Unwrap(ctx, aw.Invocation.Request.Binding, aw.Key)
	if e != nil {
		t.Fatal(e)
	}
	ar, e := staging.SealFile(ctx, root, aw.Invocation.Request.ArtifactName, ak, aw.Invocation.Request.Binding, func(out io.Writer) error { _, e := io.WriteString(out, "isolated asset fixture"); return e })
	clear(ak)
	if e != nil {
		t.Fatal(e)
	}
	ab, _ := json.Marshal(ar)
	parts = append(parts, flow.Part{ID: aw.ID, Checkpoint: kube.ContentHash(aw), SealedRef: string(ab)})
	b, e := d.bundle(ctx, task, p, parts)
	if e != nil || len(b.Parts) != 2 || b.Parts[0].ID != "database" || b.Contract == nil || !b.Contract.Assets {
		t.Fatal("bundle assembly", e)
	}
	parts[0].Checkpoint = strings.Repeat("0", 64)
	if _, e = d.bundle(ctx, task, p, parts); e == nil {
		t.Fatal("accepted substituted invocation")
	}
	parts[0].Checkpoint = hash
	p.Work[0].Key.Ciphertext[0] ^= 1
	if _, e = d.bundle(ctx, task, p, parts); e == nil {
		t.Fatal("accepted changed wrapped key")
	}
}
func TestBuildSchedulesPinnedWorkerBeforeDelayedVolumeBinding(t *testing.T) {
	d, task, p := fixture(t)
	w, e := d.newWork(context.Background(), task, p, "instance-1", "capture-workspace", "source")
	if e != nil {
		t.Fatal(e)
	}
	w.Node = "node"
	w.Source = &corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source-data"}}}
	w.SubPath = "users/1"
	c := collector{d: d, t: task, p: p, w: w}
	job, cm, e := c.build(w)
	if e != nil || cm.Immutable == nil || !*cm.Immutable {
		t.Fatal(e)
	}
	spec := job.Spec.Template.Spec
	if spec.NodeName != "" || spec.Affinity == nil || spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Values[0] != "node" {
		t.Fatal("scheduler bypass would deadlock WFFC")
	}
	for _, m := range spec.Containers[0].VolumeMounts {
		if m.Name == "staging" && m.SubPath != task.ID {
			t.Fatal("shared unscoped staging")
		}
	}
	w.Invocation.Request.Deadline = time.Now().Add(-time.Minute)
	c.w = w
	if _, _, e = c.build(w); e != nil {
		t.Fatal("expired immutable request cannot be reconstructed for cleanup", e)
	}
}
func TestNodeReplacementAndUnregisteredProofEndpointAreExcluded(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "foreign", UID: "foreign-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
	d := &Driver{Client: client, Proof: &quiesce.ProofClient{Endpoints: map[string]quiesce.ProofEndpoint{"node": {URL: "https://fixture"}}}}
	nodes, e := d.nodes(context.Background())
	if e != nil || len(nodes) != 1 || nodes["node"] != "node-uid" {
		t.Fatal(nodes, e)
	}
}
func TestSharedRootsRejectDifferentBackingAndCopiedPVCNames(t *testing.T) {
	d, _, _ := fixture(t)
	client := fake.NewSimpleClientset()
	d.Client = client
	ctx := context.Background()
	for _, v := range []struct{ ns, name, uid, path string }{{"control", "stage", "control-stage", "/stage"}, {"control", "evidence", "control-evidence", "/evidence"}, {"source", "stage", "uid-stage", "/stage"}, {"cm-drill-target", "stage", "uid-target-stage", "/stage"}, {"cm-drill-target", "evidence", "uid-evidence", "/evidence"}} {
		pvName := v.ns + "-" + v.name
		_, e := client.CoreV1().PersistentVolumeClaims(v.ns).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: v.name, Namespace: v.ns, UID: types.UID(v.uid)}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pvName, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}, metav1.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		_, e = client.CoreV1().PersistentVolumes().Create(ctx, &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: pvName, UID: types.UID(pvName)}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: v.name, Namespace: v.ns, UID: types.UID(v.uid)}, PersistentVolumeSource: corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "isolated", Path: v.path}}}}, metav1.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := client.CoreV1().Pods("control").Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: "control", UID: "controller-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "controller", VolumeMounts: []corev1.VolumeMount{{Name: "stage", MountPath: "/staging"}, {Name: "evidence", MountPath: "/evidence"}}}}, Volumes: []corev1.Volume{{Name: "stage", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "stage"}}}, {Name: "evidence", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "evidence"}}}}}}, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	check := func() error {
		return d.VerifyControllerRoots(ctx, "control", "controller", "controller-uid", "/staging", "/evidence")
	}
	if e = check(); e != nil {
		t.Fatal(e)
	}
	pv, _ := client.CoreV1().PersistentVolumes().Get(ctx, "source-stage", metav1.GetOptions{})
	pv.Spec.NFS.Path = "/different"
	client.CoreV1().PersistentVolumes().Update(ctx, pv, metav1.UpdateOptions{})
	if check() == nil {
		t.Fatal("different backing accepted")
	}
}
func TestCapabilitiesRequireAuthenticatedCompleteLiveResponse(t *testing.T) {
	mode := "good"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClawManager-Control-Token") != "fixture-token" {
			w.WriteHeader(403)
			return
		}
		var request struct{ Version, PodUID, Nonce string }
		json.NewDecoder(r.Body).Decode(&request)
		if mode == "missing" {
			w.WriteHeader(404)
			return
		}
		if mode == "stale" {
			request.PodUID = "old-pod"
		}
		json.NewEncoder(w).Encode(struct {
			Version, PodUID, Nonce                                           string
			GenerationFence, ProcessTreeStop, IdempotentCreate, UIDIsolation bool
		}{request.Version, request.PodUID, request.Nonce, true, mode != "partial", true, true})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, e := NewCapabilityClient(ca, "fixture-token")
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.Agent(context.Background(), server.URL, "pod"); e != nil {
		t.Fatal(e)
	}
	for _, m := range []string{"missing", "stale", "partial"} {
		mode = m
		if client.Agent(context.Background(), server.URL, "pod") == nil {
			t.Fatal("accepted", m)
		}
	}
}
func TestOverlappingBackingPaths(t *testing.T) {
	if !sameBacking("a", corev1.Volume{VolumeSource: corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nfs", Path: "/export"}}}, "b", corev1.Volume{VolumeSource: corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nfs", Path: "/export/user"}}}) || overlaps("/export/a", "/export/ab") {
		t.Fatal("incorrect overlap")
	}
}

func TestDeploymentWriterCannotPauseUnrelatedWorkload(t *testing.T) {
	controller := true
	ctx := context.Background()
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "source", UID: "deployment-uid"}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "source-rs", Namespace: "source", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "source", UID: deployment.UID, Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source-pod", Namespace: "source", UID: "pod-uid", Labels: map[string]string{"app": "source"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}}
	d := &Driver{Client: fake.NewSimpleClientset(rs)}
	f := frozenInstance{Deployment: deployment}
	if !d.deploymentOwns(ctx, f, pod) {
		t.Fatal("valid owner chain rejected")
	}
	pod.OwnerReferences[0].UID = "replaced-rs"
	if d.deploymentOwns(ctx, f, pod) {
		t.Fatal("replacement ReplicaSet accepted")
	}
	pod.OwnerReferences[0].UID = rs.UID
	f.Deployment = f.Deployment.DeepCopy()
	f.Deployment.UID = "unrelated-deployment"
	if d.deploymentOwns(ctx, f, pod) {
		t.Fatal("selector match substituted for owner identity")
	}
}
