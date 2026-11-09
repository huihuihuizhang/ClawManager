package systembackupexecution

import (
	"context"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTenantRecoveryProbeWithoutForwardCaptureMaterials(t *testing.T) {
	ctx := context.Background()
	spec := b.RuntimeWriterSpec{Kind: "deployment", Name: "original", UID: "deployment-uid",
		Source: b.InstanceIdentity{ID: 7, UserID: 1, Generation: 3, Namespace: "test-user-1", Mode: "pro", OS: "linux", Status: "running"}}
	for _, stale := range []*productionCaptureMaterials{nil, {Version: "stale-forward"}} {
		client := fake.NewSimpleClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: spec.Name, Namespace: spec.Source.Namespace, UID: "deployment-uid"},
			Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"instance": "7"}}}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-pod", Namespace: spec.Source.Namespace, Labels: map[string]string{"instance": "7"}}, Spec: corev1.PodSpec{NodeName: "node"}},
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
		service := &DeploymentService{Config: DeploymentConfig{Namespace: "test-system"}, captureMaterials: stale,
			Runtime: &PublicCapture{Owner: &PublicJobOwner{Client: client}}}
		service.Config.Security.NodeUIDs = map[string]string{"node": "node-uid"}
		controls := c.RuntimeControlConfig{DeploymentChecks: map[string]c.ReadinessProbe{}}
		if err := service.attachTenantProRuntimeControls(&controls); err != nil || controls.RecoveryDeploymentCheck == nil || controls.TenantProSourceCheck != nil || len(controls.DeploymentChecks) != 0 {
			t.Fatal("recovery probe requires forward materials or admitted discovery", err)
		}
		probe := controls.RecoveryDeploymentCheck
		if err := probe(ctx, d.Authority{}, spec); err != nil {
			t.Fatal("original recovery probe failed", err)
		}
		for _, change := range []func(*b.RuntimeWriterSpec){func(s *b.RuntimeWriterSpec) { s.UID = "replacement" }, func(s *b.RuntimeWriterSpec) { s.Source.Namespace = "unrelated-user-1" }, func(s *b.RuntimeWriterSpec) { s.Name = "another" }} {
			changed := spec
			change(&changed)
			if probe(ctx, d.Authority{}, changed) == nil {
				t.Fatal("different deployment inherited the original probe")
			}
		}
		_, err := client.AutoscalingV2().HorizontalPodAutoscalers(spec.Source.Namespace).Create(ctx, &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "hpa", Namespace: spec.Source.Namespace},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: spec.Name}}}, metav1.CreateOptions{})
		if err != nil || probe(ctx, d.Authority{}, spec) == nil {
			t.Fatal("HPA fencing check was bypassed", err)
		}
		service.Runtime = nil
		if probe(ctx, d.Authority{}, spec) == nil {
			t.Fatal("missing actual runtime client was accepted")
		}
	}
}
