package systembackupexecution

import (
	"context"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTenantSourceMountUsesOriginalNodeAcrossStop(t *testing.T) {
	for _, scenario := range []string{"original-node", "replaced-pod", "changed-placement", "replaced-node", "source-stopped", "foreign-frozen-instance", "foreign-frozen-claim"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original", Namespace: "test-user-1", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "tenant-node"}}
			pin := runningTenantProMount{Source: b.InstanceIdentity{ID: 7, UserID: 1, Generation: 2, Mode: "pro", OS: "linux", Status: "running", Namespace: pod.Namespace, Pod: pod.Name, Workspace: "/workspace"},
				NamespaceUID: "namespace-uid", PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec), ReplicaSetUID: "rs-uid", Deployment: "original", DeploymentUID: "deployment-uid",
				Identity: kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: "source", UID: "pvc-uid", PVName: "pv", PVUID: "pv-uid", SHA256: strings.Repeat("a", 64)}}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "tenant-node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}}
			cfg := DeploymentConfig{Namespace: "test-system", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"tenant-node": "node-uid", "shared-node": "shared-uid"}}}
			cfg.Workspace.Node = "shared-node"
			var previous *productionInstanceMount
			if scenario == "source-stopped" || strings.HasPrefix(scenario, "foreign-") {
				previous = &productionInstanceMount{InstanceID: pin.Source.ID, MountID: "workspace", NodeName: node.Name, Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pin.Identity.Name, ReadOnly: true}}}}
			}
			switch scenario {
			case "replaced-pod":
				pod.UID = "replacement"
			case "changed-placement":
				pod.Spec.NodeName = "shared-node"
			case "replaced-node":
				node.UID = "replacement"
			case "foreign-frozen-instance":
				previous.InstanceID++
			case "foreign-frozen-claim":
				previous.Source.PersistentVolumeClaim.ClaimName = "another"
			}
			client := fake.NewSimpleClientset(pod, node)
			if scenario == "source-stopped" {
				if err := client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
				client.ClearActions()
			}
			name, err := tenantSourceMountNode(ctx, client, cfg, pin, previous)
			if scenario == "original-node" || scenario == "source-stopped" {
				if err != nil || name != "tenant-node" {
					t.Fatal("original placement lost", name, err)
				}
			} else if err == nil {
				t.Fatal("changed source identity accepted", name)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("placement read issued mutation", action.GetVerb())
				}
				if scenario == "source-stopped" && action.GetResource().Resource == "pods" {
					t.Fatal("held check rediscovered original Pod")
				}
			}
		})
	}
}
