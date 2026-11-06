package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFreshAppDatabaseBindsActualWorkloadAndRefusesRetarget(t *testing.T) {
	ctx := context.Background()
	const ns = "isolated"
	one := int32(1)
	ready := true
	tcp := corev1.ProtocolTCP
	port, portName := int32(3306), "mysql"
	newWorkload := func(name string, env []corev1.EnvVar) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) {
		label := map[string]string{"app": name}
		spec := corev1.PodSpec{Containers: []corev1.Container{{Name: name, Env: env}}}
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name + "-uid"), Generation: 1},
			Spec:   appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: label}, Template: corev1.PodTemplateSpec{Spec: spec}},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}}
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs", Namespace: ns, UID: types.UID(name + "-rs-uid"), OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "Deployment", Name: name, UID: dep.UID, Controller: &ready}}}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-pod", Namespace: ns, UID: types.UID(name + "-pod-uid"), Labels: label, OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &ready}}}, Spec: spec, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: name, Ready: true, ContainerID: "containerd://" + name, ImageID: "immutable-image", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
		return dep, rs, pod
	}
	app, appRS, appPod := newWorkload("app", []corev1.EnvVar{
		{Name: "DB_HOST", Value: "db"}, {Name: "DB_PORT", Value: "3306"}, {Name: "DB_NAME", Value: "appdb"}, {Name: "DB_USER", Value: "business"},
		{Name: "DB_TLS_CA_FILE", Value: "/mysql-ca/ca.pem"}, {Name: "DB_TLS_CA_SHA256", Value: "ca-pin"}, {Name: "DB_TLS_SERVER_NAME", Value: "db.isolated.svc"},
		{Name: "DB_PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "business"}, Key: "password"}}},
	})
	db, dbRS, dbPod := newWorkload("db", []corev1.EnvVar{{Name: "MYSQL_DATABASE", Value: "appdb"}, {Name: "MYSQL_USER", Value: "business"}})
	dbPod.Status.PodIP = "10.2.0.17"
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns, UID: "db-service-uid"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP,
		ClusterIP: "10.3.0.17", Selector: map[string]string{"app": "db"}, Ports: []corev1.ServicePort{{Name: portName, Port: port, Protocol: tcp, TargetPort: intstr.FromInt32(port)}}}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "db-slice", Namespace: ns, UID: "db-slice-uid", Labels: map[string]string{"kubernetes.io/service-name": "db"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "db", UID: service.UID}}}, Ports: []discoveryv1.EndpointPort{{Name: &portName, Protocol: &tcp, Port: &port}},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{dbPod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: ns, Name: dbPod.Name, UID: dbPod.UID}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "business", Namespace: ns, UID: "secret-uid", ResourceVersion: "1"}, Data: map[string][]byte{"password": []byte("fixture-secret")}}
	client := fake.NewSimpleClientset(app, appRS, appPod, db, dbRS, dbPod, service, slice, secret)
	input := FreshInstallationIdentityInputs{OriginalEnrollmentInputs: OriginalEnrollmentInputs{Namespace: ns, DatabaseTLSServerName: "db.isolated.svc", DatabaseCA: BootstrapSourceFilePin{SHA256: "ca-pin"}},
		AppDeployment: app.Name, AppDeploymentUID: string(app.UID), ExpectedDatabase: "appdb", UseAppDatabaseSecret: true}
	target, err := observeFreshAppDatabase(ctx, client, input)
	if err != nil || target.Address != "10.3.0.17:3306" || target.DBPodUID != string(dbPod.UID) {
		t.Fatal("exact App/MySQL target did not bind", err)
	}
	secretPin, password, err := readFreshAppDatabaseSecret(ctx, client, ns, target)
	if err != nil || string(password) != "fixture-secret" || !sameFreshAppDatabaseSecret(ctx, client, input, target, secretPin) {
		t.Fatal("exact App password Secret did not bind", err)
	}
	clear(password)
	secret.Data["password"] = []byte("rotated-fixture")
	if _, err := client.CoreV1().Secrets(ns).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if sameFreshAppDatabaseSecret(ctx, client, input, target, secretPin) {
		t.Fatal("rotated App password was accepted")
	}
	changedRef := appPod.DeepCopy()
	changedRef.Spec.Containers[0].Env[7].ValueFrom.SecretKeyRef.Key = "other-key"
	if _, err := client.CoreV1().Pods(ns).Update(ctx, changedRef, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := observeFreshAppDatabase(ctx, client, input); err == nil {
		t.Fatal("different App Pod password reference was accepted")
	}
	other := appPod.DeepCopy()
	other.Spec.Containers[0].Env[0].Value = "db.other.svc"
	if _, err := client.CoreV1().Pods(ns).Update(ctx, other, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := observeFreshAppDatabase(ctx, client, input); err == nil {
		t.Fatal("ready App Pod with a foreign DB host was accepted")
	}
	if _, err := client.CoreV1().Pods(ns).Update(ctx, appPod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	slice.Endpoints[0].TargetRef.Namespace = "other"
	if _, err := client.DiscoveryV1().EndpointSlices(ns).Update(ctx, slice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := observeFreshAppDatabase(ctx, client, input); err == nil {
		t.Fatal("foreign database endpoint was accepted")
	}
}

func TestFreshAppDatabaseDSNRefusesAnotherValidAddressOrAccount(t *testing.T) {
	target := freshAppDatabase{Address: "10.3.0.17:3306", Database: "appdb", User: "business"}
	file := filepath.Join(t.TempDir(), "test.dsn")
	for _, tc := range []struct {
		dsn          string
		business, ok bool
	}{
		{"business:fixture@tcp(10.3.0.17:3306)/appdb", true, true},
		{"bootstrap:fixture@tcp(10.3.0.17:3306)/appdb", false, true},
		{"business:fixture@tcp(10.3.0.18:3306)/appdb", true, false},
		{"business:fixture@tcp(db.other.svc:3306)/appdb", true, false},
		{"other:fixture@tcp(10.3.0.17:3306)/appdb", true, false},
	} {
		if err := os.WriteFile(file, []byte(tc.dsn), 0600); err != nil {
			t.Fatal(err)
		}
		err := checkFreshAppDatabaseDSN(BootstrapSourceFilePin{File: file, SHA256: hash([]byte(tc.dsn))}, target, tc.business)
		if (err == nil) != tc.ok {
			t.Fatal("unexpected DSN target result", err)
		}
	}
}
