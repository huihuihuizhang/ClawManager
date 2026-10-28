package profile

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/control"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func appFakeClient() *fake.Clientset {
	return fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
}
func installAppFixture(t *testing.T, d *Driver) control.AppProcess {
	t.Helper()
	ctx := context.Background()
	replicas := int32(1)
	controller := true
	image := "app@sha256:" + strings.Repeat("a", 64)
	a := ApplicationDeployment{Namespace: "source", Name: "app", UID: "app-uid", Container: "app", Image: image}
	d.Config.Applications = []ApplicationDeployment{a}
	d.Config.Assets = assets.Inventory{Namespace: "source"}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: a.Name, Namespace: a.Namespace, UID: "app-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "platform"}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1, UpdatedReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "app-rs", Namespace: a.Namespace, UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: a.Name, UID: dep.UID, Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: a.Namespace, UID: "pod-uid", Labels: map[string]string{"app": "platform"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "app", Image: image, Env: []corev1.EnvVar{{Name: "CLAWMANAGER_BACKUP_CONTROL_CONFIG", Value: "/config/control.json"}}}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "containerd://original", ImageID: "sha256:app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	if _, e := d.Client.AppsV1().Deployments(a.Namespace).Create(ctx, dep, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Client.AppsV1().ReplicaSets(a.Namespace).Create(ctx, rs, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Client.CoreV1().Pods(a.Namespace).Create(ctx, pod, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	node, e := d.Client.CoreV1().Nodes().Get(ctx, "node", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	p, e := control.IdentifyApplication(pod, node, "app")
	if e != nil {
		t.Fatal(e)
	}
	db := sql.OpenDB(inventoryConnector{t: t, users: 1, apps: []control.AppProcess{p}})
	t.Cleanup(func() { db.Close() })
	d.Store = control.SQLStore{DB: db}
	return p
}
func TestCoverageRejectsContainerRestartAndMissingReplica(t *testing.T) {
	d, _, _ := fixture(t)
	// Reuse the discovery fixture's fake cluster, without any live connection.
	d.Client = appFakeClient()
	installAppFixture(t, d)
	if _, e := d.applicationCoverage(context.Background()); e != nil {
		t.Fatal(e)
	}
	pod, _ := d.Client.CoreV1().Pods("source").Get(context.Background(), "app-1", metav1.GetOptions{})
	pod.Status.ContainerStatuses[0].ContainerID = "containerd://restarted"
	d.Client.CoreV1().Pods("source").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
	if _, e := d.applicationCoverage(context.Background()); e == nil {
		t.Fatal("restarted process inherited old registration")
	}
}
