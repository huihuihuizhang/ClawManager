package systembackupminioauthority

import (
	"context"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func recoveryAPIModel(t *testing.T) (*fake.Clientset, Target, Provider) {
	t.Helper()
	f := newSeptemberRecordFixture(t)
	target, p := f.grant.Target, f.grant.Provider
	yes := true
	one := int32(1)
	meta := func(id ObjectIdentity) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: id.Name, Namespace: target.Namespace, UID: types.UID(id.UID), ResourceVersion: "17", Generation: 1}
	}
	owner := func(kind string, id ObjectIdentity) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: id.Name, UID: types.UID(id.UID), Controller: &yes}}
	}
	pod := &corev1.Pod{ObjectMeta: meta(p.Pod), Spec: corev1.PodSpec{NodeName: p.Node, ServiceAccountName: p.ServiceAccount.Name, Containers: []corev1.Container{{Name: p.Container, Image: "original-image", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "original-credentials"}}}}}}, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "original-data"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: p.Container, Ready: true, ImageID: p.ImageID, ContainerID: "containerd://old", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	pod.OwnerReferences = owner("ReplicaSet", p.ReplicaSet)
	deployment := &appsv1.Deployment{ObjectMeta: meta(p.Deployment), Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: meta(p.ReplicaSet)}
	rs.OwnerReferences = owner("Deployment", p.Deployment)
	return fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: target.Namespace, UID: types.UID(target.NamespaceUID)}}, deployment, rs, pod,
		&corev1.ServiceAccount{ObjectMeta: meta(p.ServiceAccount)}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: p.Node, UID: types.UID(p.NodeUID)}}, &corev1.Service{ObjectMeta: meta(p.Service)},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "original-credentials", Namespace: target.Namespace, UID: "credential-uid", ResourceVersion: "17"}, Data: map[string][]byte{"credential": []byte("synthetic-not-a-real-secret")}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "original-data", Namespace: target.Namespace, UID: "claim-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-volume"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "original-volume", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "original-data", Namespace: target.Namespace, UID: "claim-uid"}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}},
	), target, p
}
func recoverySuccessorModel(t *testing.T, k *fake.Clientset, target Target, p Provider) ObjectIdentity {
	t.Helper()
	ctx := context.Background()
	pod, e := k.CoreV1().Pods(target.Namespace).Get(ctx, p.Pod.Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pod = pod.DeepCopy()
	pod.Name = "restored-pod"
	pod.UID = "restored-pod-uid"
	pod.Status.ContainerStatuses[0].ContainerID = "containerd://new"
	if _, e = k.CoreV1().Pods(target.Namespace).Create(ctx, pod, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	return ObjectIdentity{pod.Name, string(pod.UID)}
}
func TestMinIORecoveryNativeResourceModelOnlyPodAndCIDChange(t *testing.T) {
	k, target, p := recoveryAPIModel(t)
	ctx := context.Background()
	before, e := CollectMinIORecoveryResources(ctx, k, target, p, p.Pod, "containerd://old")
	if e != nil {
		t.Fatal(e)
	}
	next := recoverySuccessorModel(t, k, target, p)
	after, e := CollectMinIORecoveryResources(ctx, k, target, p, next, "containerd://new")
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("only Pod/CID succession changed stable resources", e)
	}
	if len(before.Materials) != 1 || len(before.Storage) != 2 {
		t.Fatal("original credentials or bound storage omitted")
	}
	if _, e = CollectMinIORecoveryResources(ctx, k, target, p, next, "containerd://wrong"); e == nil {
		t.Fatal("wrong actual runtime CID accepted")
	}
	if _, e = CollectMinIORecoveryResources(ctx, k, target, p, ObjectIdentity{next.Name, "foreign"}, "containerd://new"); e == nil {
		t.Fatal("wrong native Pod UID accepted")
	}
}
func TestMinIORecoveryNativeResourceModelRejectsCredentialAndStorageDrift(t *testing.T) {
	for _, scenario := range []string{"credential-uid", "credential-version", "credential-data", "claim-spec", "node", "replicaset", "deployment"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			k, target, p := recoveryAPIModel(t)
			before, e := CollectMinIORecoveryResources(ctx, k, target, p, p.Pod, "containerd://old")
			if e != nil {
				t.Fatal(e)
			}
			next := recoverySuccessorModel(t, k, target, p)
			switch scenario {
			case "credential-uid", "credential-version", "credential-data":
				secret, e := k.CoreV1().Secrets(target.Namespace).Get(ctx, "original-credentials", metav1.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				switch scenario {
				case "credential-uid":
					secret.UID = "foreign"
				case "credential-version":
					secret.ResourceVersion = "18"
				case "credential-data":
					secret.Data["credential"] = []byte("changed")
				}
				if _, e = k.CoreV1().Secrets(target.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); e != nil {
					t.Fatal(e)
				}
			case "claim-spec":
				claim, e := k.CoreV1().PersistentVolumeClaims(target.Namespace).Get(ctx, "original-data", metav1.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				claim.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany}
				if _, e = k.CoreV1().PersistentVolumeClaims(target.Namespace).Update(ctx, claim, metav1.UpdateOptions{}); e != nil {
					t.Fatal(e)
				}
			case "node", "replicaset":
				pod, e := k.CoreV1().Pods(target.Namespace).Get(ctx, next.Name, metav1.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				if scenario == "node" {
					pod.Spec.NodeName = "other"
				} else {
					pod.OwnerReferences[0].UID = "foreign"
				}
				if _, e = k.CoreV1().Pods(target.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
					t.Fatal(e)
				}
			case "deployment":
				deployment, e := k.AppsV1().Deployments(target.Namespace).Get(ctx, p.Deployment.Name, metav1.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				deployment.UID = "foreign"
				if _, e = k.AppsV1().Deployments(target.Namespace).Update(ctx, deployment, metav1.UpdateOptions{}); e != nil {
					t.Fatal(e)
				}
			}
			after, e := CollectMinIORecoveryResources(ctx, k, target, p, next, "containerd://new")
			if e == nil && reflect.DeepEqual(before, after) {
				t.Fatal("native resource drift accepted")
			}
		})
	}
}
func TestMinIORecoveryStandardSATokenMountNormalizationIsNarrow(t *testing.T) {
	expiry := int64(3607)
	readonly := true
	spec := corev1.PodSpec{NodeName: "original", Containers: []corev1.Container{{Name: "minio", Image: "fixed", VolumeMounts: []corev1.VolumeMount{{Name: "kube-api-access-old", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: readonly}}}}, Volumes: []corev1.Volume{{Name: "kube-api-access-old", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
		{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: &expiry}},
		{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}}},
		{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.namespace"}}}}},
	}}}}}}
	first, e := stableRecoveryPodSpec(spec)
	if e != nil {
		t.Fatal(e)
	}
	copy := spec.DeepCopy()
	copy.Volumes[0].Name = "kube-api-access-new"
	copy.Containers[0].VolumeMounts[0].Name = "kube-api-access-new"
	after, e := stableRecoveryPodSpec(*copy)
	if e != nil || !reflect.DeepEqual(first, after) {
		t.Fatal("standard generated name was not normalized", e)
	}
	copy = spec.DeepCopy()
	copy.Volumes[0].Projected.Sources[0].Secret = &corev1.SecretProjection{}
	if _, e = stableRecoveryPodSpec(*copy); e == nil {
		t.Fatal("multiple projected API union alternatives accepted")
	}
	copy = spec.DeepCopy()
	copy.Volumes[0].Projected.Sources[1].ConfigMap.Name = "other-ca"
	if _, e = stableRecoveryPodSpec(*copy); e == nil {
		t.Fatal("CA source change accepted")
	}
	copy = spec.DeepCopy()
	copy.Containers[0].VolumeMounts[0].ReadOnly = false
	if _, e = stableRecoveryPodSpec(*copy); e == nil {
		t.Fatal("writable service account mount accepted")
	}
	copy = spec.DeepCopy()
	copy.Containers[0].Image = "different"
	after, e = stableRecoveryPodSpec(*copy)
	if e == nil && reflect.DeepEqual(first, after) {
		t.Fatal("application image normalized")
	}
}

// Exact native integer comparison, independent of whether an actual cluster
// would accept either deliberately large grace value in this API model.
func TestMinIORecoveryNativeResourceHashPreservesExactIntegers(t *testing.T) {
	ctx := context.Background()
	k, target, p := recoveryAPIModel(t)
	pod, e := k.CoreV1().Pods(target.Namespace).Get(ctx, p.Pod.Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	first := int64(9007199254740992)
	pod.Spec.TerminationGracePeriodSeconds = &first
	if _, e = k.CoreV1().Pods(target.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	before, e := CollectMinIORecoveryResources(ctx, k, target, p, p.Pod, "containerd://old")
	if e != nil {
		t.Fatal(e)
	}
	second := int64(9007199254740993)
	pod.Spec.TerminationGracePeriodSeconds = &second
	if _, e = k.CoreV1().Pods(target.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	after, e := CollectMinIORecoveryResources(ctx, k, target, p, p.Pod, "containerd://old")
	if e != nil {
		t.Fatal(e)
	}
	if before.PodSpecSHA256 == after.PodSpecSHA256 {
		t.Fatal("distinct exact native integers collapsed")
	}
}
