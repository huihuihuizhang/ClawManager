package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestMinIOPermissionOriginalOwnerSignatureAndCurrentHead(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := minioPermissionConfiguration{Version: "minio-publication-permission-source.v1", Installation: "installation", Namespace: "scope", NamespaceUID: "namespace-uid", Issuer: public, MinimumEpoch: 2, Grant: minioPermissionObject{"grant", "grant-uid"}, Head: minioPermissionObject{"head", "head-uid"}, Engine: minioPermissionObject{"engine", "engine-uid"}, ObserverCredentialSHA256: hash([]byte("credential")), ObserverAccountSHA256: hash([]byte("account")), ObserverPolicySHA256: hash([]byte("policy")), ObserverPolicyName: "observer"}
	grant := minioPermissionGrant{Version: "minio-permission-grant.v1", Installation: cfg.Installation, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, ConfigSHA256: hash([]byte("config")), Profile: minioPermissionProfile, Epoch: 2, NotBefore: now.Add(-time.Second), Until: now.Add(time.Minute), Provider: minioPermissionProvider{Endpoint: "https://minio.scope.svc", DeploymentID: "deployment"}}
	engine := minioPermissionEngine{Version: "minio-owner-configuration-observation.v1", Installation: cfg.Installation, Endpoint: grant.Provider.Endpoint, DeploymentID: "deployment", ServerVersion: minioPermissionVersion, ServerCommit: minioPermissionCommit, SourceMethod: "minio-admin-v3/get-config-kv:identity+policy", NativeResponseSHA256: hash([]byte("original-get-response")), ObservedAt: now.Add(-time.Second), Until: now.Add(20 * time.Second)}
	grantRaw, _ := ce.Canonical(grant)
	engineRaw, _ := ce.Canonical(engine)
	cfg.GrantSHA256 = hash(grantRaw)
	head := minioPermissionHead{Version: "minio-permission-head.v1", Installation: cfg.Installation, State: "active", GrantSHA256: cfg.GrantSHA256, EngineSHA256: hash(engineRaw), Epoch: 2, NotBefore: grant.NotBefore, Until: grant.Until}
	headRaw, _ := ce.Canonical(head)
	object := func(ref minioPermissionObject, domain string, raw []byte) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: cfg.Namespace, UID: types.UID(ref.UID), ResourceVersion: "7"}, Data: map[string]string{"record.json": string(raw)}, BinaryData: map[string][]byte{"signature": ed25519.Sign(key, append([]byte(domain), raw...))}}
	}
	grantCM := object(cfg.Grant, minioPermissionOwnerDomain, grantRaw)
	headCM := object(cfg.Head, minioPermissionHeadDomain, headRaw)
	engineCM := object(cfg.Engine, minioPermissionEngineDomain, engineRaw)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(cfg.NamespaceUID)}}
	raw, _ := ce.Canonical(cfg)
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewMinIOPublicationPermissionReader(MinIOPublicationPermissionInput{path, hash(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid-source-only", "revoked-head", "wrong-namespace-uid", "wrong-object-uid", "invalid-signature", "expired", "replayed-epoch"} {
		t.Run(scenario, func(t *testing.T) {
			g, h, e, n := grantCM.DeepCopy(), headCM.DeepCopy(), engineCM.DeepCopy(), ns.DeepCopy()
			at := now
			switch scenario {
			case "revoked-head":
				changed := head
				changed.State = "revoked"
				body, _ := ce.Canonical(changed)
				h = object(cfg.Head, minioPermissionHeadDomain, body)
			case "wrong-namespace-uid":
				n.UID = "substitution"
			case "wrong-object-uid":
				g.UID = "substitution"
			case "invalid-signature":
				e.BinaryData["signature"][0] ^= 1
			case "expired":
				at = now.Add(30 * time.Second)
			case "replayed-epoch":
				changed := head
				changed.Epoch = 1
				body, _ := ce.Canonical(changed)
				h = object(cfg.Head, minioPermissionHeadDomain, body)
			}
			client := fake.NewSimpleClientset(g, h, e, n)
			observed, err := reader.originalOwner(context.Background(), client, at)
			if (err == nil) != (scenario == "valid-source-only") {
				t.Fatalf("original owner source result: %v", err)
			}
			if err == nil && observed.stamp == "" {
				t.Fatal("original source stamp missing")
			}
		})
	}
}

func TestMinIOPermissionKubernetesCompletePagination(t *testing.T) {
	cfg := minioPermissionConfiguration{Namespace: "scope", NamespaceUID: "namespace-uid"}
	p := minioPermissionProvider{Deployment: minioPermissionObject{"minio", "deployment-uid"}, ReplicaSet: minioPermissionObject{"minio-rs", "rs-uid"}, Pod: minioPermissionObject{"minio-pod", "pod-uid"}, Service: minioPermissionObject{"minio", "service-uid"}, ServiceAccount: minioPermissionObject{"minio", "sa-uid"}, Container: "minio", ImageID: "sha256:image", Node: "node", NodeUID: "node-uid"}
	metadata := func(name, uid string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: cfg.Namespace, UID: types.UID(uid), ResourceVersion: "8"}
	}
	truth := true
	replicas := int32(1)
	owner := func(kind string, ref minioPermissionObject) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: ref.Name, UID: types.UID(ref.UID), Controller: &truth}}
	}
	for _, scenario := range []string{"complete-two-pages", "repeated-cursor", "changed-list-rv", "terminating-endpoint", "substituted-target", "missing-final-page"} {
		t.Run(scenario, func(t *testing.T) {
			d := &appsv1.Deployment{ObjectMeta: metadata(p.Deployment.Name, p.Deployment.UID), Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "minio"}}}}
			rs := &appsv1.ReplicaSet{ObjectMeta: metadata(p.ReplicaSet.Name, p.ReplicaSet.UID)}
			rs.OwnerReferences = owner("Deployment", p.Deployment)
			pod := &corev1.Pod{ObjectMeta: metadata(p.Pod.Name, p.Pod.UID), Spec: corev1.PodSpec{ServiceAccountName: p.ServiceAccount.Name, NodeName: p.Node}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: p.Container, ImageID: p.ImageID, ContainerID: "runtime://container", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			pod.OwnerReferences = owner("ReplicaSet", p.ReplicaSet)
			pod.Labels = map[string]string{"app": "minio"}
			svc := &corev1.Service{ObjectMeta: metadata(p.Service.Name, p.Service.UID), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "minio"}}}
			client := fake.NewSimpleClientset(d, rs, pod, svc, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(cfg.NamespaceUID), ResourceVersion: "8"}}, &corev1.ServiceAccount{ObjectMeta: metadata(p.ServiceAccount.Name, p.ServiceAccount.UID)}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: p.Node, UID: types.UID(p.NodeUID), ResourceVersion: "8"}})
			pages := 0
			client.PrependReactor("list", "endpointslices", func(action ktesting.Action) (bool, runtime.Object, error) {
				pages++
				list := &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{ResourceVersion: "19"}}
				if pages == 1 {
					list.Continue = "next"
					return true, list, nil
				}
				if scenario == "missing-final-page" {
					return true, nil, minioPermissionFailure("fixture-unavailable-page")
				}
				if scenario == "repeated-cursor" {
					list.Continue = "next"
				}
				if scenario == "changed-list-rv" {
					list.ResourceVersion = "20"
				}
				slice := discoveryv1.EndpointSlice{ObjectMeta: metadata("endpoint", "endpoint-uid"), AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &truth}, Addresses: []string{"10.0.0.1"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: p.Pod.Name, Namespace: cfg.Namespace, UID: types.UID(p.Pod.UID)}}}}
				slice.Labels = map[string]string{"kubernetes.io/service-name": p.Service.Name}
				slice.OwnerReferences = owner("Service", p.Service)
				if scenario == "terminating-endpoint" {
					slice.Endpoints[0].Conditions.Terminating = &truth
				}
				if scenario == "substituted-target" {
					slice.Endpoints[0].TargetRef.UID = "substitution"
				}
				list.Items = []discoveryv1.EndpointSlice{slice}
				return true, list, nil
			})
			stamp, err := minioPermissionKubernetes(context.Background(), client, cfg, p)
			if (err == nil) != (scenario == "complete-two-pages") {
				t.Fatalf("bounded endpoint pagination: %v", err)
			}
			if err == nil && (pages != 2 || stamp == "") {
				t.Fatal("did not consume the complete endpoint list")
			}
		})
	}
}
