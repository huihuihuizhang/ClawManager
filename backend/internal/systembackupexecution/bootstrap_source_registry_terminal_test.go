package systembackupexecution

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Composition and rejection regressions only. No prepared identity or positive
// observation is fabricated here; a full V2 issuer/native fixture is separate.
func TestBootstrapSourceRegistryTerminalComposition(t *testing.T) {
	dir := t.TempDir()
	capture := install.NewCaptureSigningConsumer(filepath.Join(dir, "capture.json"), filepath.Join(dir, "capture.sha256"))
	files := install.BootstrapSourceRegistryFiles{RecordFile: filepath.Join(dir, "source.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(dir, "source.sig")}
	r, err := NewBootstrapSourceRegistryTerminalResource(capture, files)
	if err != nil {
		t.Fatal(err)
	}
	resources := r.TerminalResources()
	if len(resources) != 2 || resources["registry:parts"] != r || resources["registry:source_writers"] != r {
		t.Fatal("registry keys must share the same concrete owner")
	}
	binding, err := r.BindingSHA256()
	if err != nil {
		t.Fatal(err)
	}
	changed := files
	changed.SignatureFile = filepath.Join(dir, "other.sig")
	other, err := NewBootstrapSourceRegistryTerminalResource(capture, changed)
	if err != nil {
		t.Fatal(err)
	}
	otherBinding, _ := other.BindingSHA256()
	if binding == otherBinding {
		t.Fatal("signature coordinate omitted from original binding")
	}
	otherCapture := install.NewCaptureSigningConsumer(filepath.Join(dir, "other-capture.json"), filepath.Join(dir, "capture.sha256"))
	other, err = NewBootstrapSourceRegistryTerminalResource(otherCapture, files)
	if err != nil {
		t.Fatal(err)
	}
	otherBinding, _ = other.BindingSHA256()
	if binding == otherBinding {
		t.Fatal("original capture coordinate omitted from binding")
	}
	if _, err := NewBootstrapSourceRegistryTerminalResource(nil, files); err == nil {
		t.Fatal("nil original source accepted")
	}
	if _, err := r.Prepare(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil {
		t.Fatal("legacy preparation accepted")
	}
	if _, err := r.PrepareTerminalResource(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil {
		t.Fatal("unbounded unauthenticated caller accepted")
	}
}

func TestBootstrapSourceRegistryTerminalCannotPromoteDeadlineData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &bootstrapSourceRegistryTerminalCheck{ctx: ctx, dependencyStart: time.Now().Add(-time.Second), dependencyUntil: time.Now().Add(time.Second)}
	s.origin = s
	if err := s.LockReferences(ctx, nil); err == nil || !s.failed.Load() || s.DependencyDeadline() != nil {
		t.Fatal("comparison times admitted a check without its original identity/transaction")
	}
	copySource := &bootstrapSourceRegistryTerminalCheck{ctx: ctx, dependencyUntil: time.Now().Add(time.Second)}
	copySource.origin = copySource
	// Do not copy a mutex/atomic-bearing object; construct the same illegal
	// detached origin relationship a copied handle would have.
	detached := &bootstrapSourceRegistryTerminalCheck{origin: copySource, ctx: ctx, dependencyUntil: copySource.dependencyUntil}
	if detached.DependencyDeadline() != nil || !copySource.failed.Load() || copySource.DependencyDeadline() != nil {
		t.Fatal("detached getter failed to poison the original")
	}
}

// An actual GET result must join the same complete LIST census by all projected
// fields, including process/container identities, UID, RV and owner chain.
func TestBootstrapSourceNativeReadJoinsExactCensusObject(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: "source", UID: types.UID("pod-1"), ResourceVersion: "17", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "runtime-rs", UID: types.UID("rs-1")}}}, Spec: corev1.PodSpec{NodeName: "node-1"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "agent", Ready: true, ContainerID: "container-1", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	projected, err := projectWriterAPIObject("Pod", pod)
	if err != nil {
		t.Fatal(err)
	}
	census := &observedWriterAPI{objects: []observedWriterAPIObject{projected}}
	if !matchesBootstrapWriterObject(census, "Pod", pod) {
		t.Fatal("same actual object rejected")
	}
	for _, mode := range []string{"uid", "version", "owner", "process", "readiness", "spec"} {
		t.Run(mode, func(t *testing.T) {
			changed := pod.DeepCopy()
			switch mode {
			case "uid":
				changed.UID = "replacement"
			case "version":
				changed.ResourceVersion = "18"
			case "owner":
				changed.OwnerReferences[0].UID = "other-rs"
			case "process":
				changed.Status.ContainerStatuses[0].ContainerID = "container-2"
			case "readiness":
				changed.Status.ContainerStatuses[0].Ready = false
			case "spec":
				changed.Spec.ServiceAccountName = "other-reader"
			}
			if matchesBootstrapWriterObject(census, "Pod", changed) {
				t.Fatal("GET joined a different census object")
			}
		})
	}
	replicas := int32(1)
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: "source", UID: "deployment-1", ResourceVersion: "19"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}}
	d, err := projectWriterAPIObject("Deployment", deployment)
	if err != nil {
		t.Fatal(err)
	}
	census.objects = append(census.objects, d)
	if !matchesBootstrapWriterObject(census, "Deployment", deployment) || matchesBootstrapWriterObject(nil, "Pod", pod) {
		t.Fatal("census kind/missing-set handling")
	}
}
