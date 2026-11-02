package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"golang.org/x/crypto/bcrypt"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Reuses D's independently frozen strict database/sql connector, not D's
// producer or a substitute installer. The tests call A New/Enroll and the
// complete C producer; every native permission GET is real local TLS/SigV4.
type minioProducerComponent struct {
	installer                                                              *install.Installer
	enrollment                                                             install.EnrollmentPin
	model                                                                  *producerComponentSQL
	kube                                                                   *fake.Clientset
	definition                                                             install.MinIOPermissionDefinition
	definitionFile, definitionSHA, privateFile, directory, output          string
	password, key                                                          []byte
	headCreated, ownerTailReached                                          atomic.Bool
	created, preNative, postNative, postBucketPasses, selfReads, helpReads atomic.Int64
	scenario                                                               string
}

func newMinIOProducerComponent(t *testing.T, ctx context.Context, scenario string) *minioProducerComponent {
	t.Helper()
	f := &minioProducerComponent{scenario: scenario}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.directory = filepath.Join(dir, "new-owner-output")
	if err := os.Mkdir(f.directory, 0700); err != nil {
		t.Fatal(err)
	}
	f.output = filepath.Join(f.directory, "minio-permission.source.json")
	write := func(name string, raw []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key, f.password = key, []byte("original-minio-component-admin-password")
	t.Cleanup(func() { clear(f.key); clear(f.password) })
	f.privateFile = write("original-enrolled.private", key)
	now := time.Now().UTC().Truncate(time.Microsecond)
	stored, err := bcrypt.GenerateFromPassword(f.password, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	f.model = &producerComponentSQL{account: "original_installer@localhost", server: "12345678-1234-1234-1234-123456789abc", database: "original_minio_source", username: "original-minio-admin", stored: string(stored), userID: 41, afterSourceWindow: now.Add(70 * time.Second)}
	db := sql.OpenDB(producerComponentConnector{model: f.model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	plan := install.Plan{SchemaVersion: install.PlanVersion, EnrollmentName: "original-minio-enrollment", EnrollmentID: "original-minio-enrollment-1", IssuerID: "original-minio-issuer-1", EnrollmentRevision: 1, Target: owner.Target{InstallationID: "installation_minio_component", ServerUUID: f.model.server, Database: f.model.database, DatabaseAccount: "original_runtime@localhost", ClusterID: "original-cluster-uid", Namespace: "original-minio-scope", NamespaceUID: "original-scope-uid"}, InstallerDatabaseAccount: f.model.account, LocalAdminUsername: f.model.username, OwnerUsername: "original-owner", OwnerUID: "original-owner-uid", OwnerGroups: []string{"system:authenticated", "system:masters"}, IssuerPublicKeySHA256: hash(public), KubernetesAPI: "https://kubernetes.original.invalid", KubernetesCASHA256: hash([]byte("original-kubernetes-ca")), DatabaseCASHA256: hash([]byte("original-database-ca")), DatabaseTLSServerName: "database.original.invalid"}
	// Complete disabled ConfigValues from the original public contract. This
	// is independent of a future active config or a future publication task.
	configRaw := componentConfigValues(t)
	config, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]sec.BootstrapSecretRef{}
	for _, ref := range config.References() {
		refs[ref.Purpose] = ref
	}
	native := minioPermissionFixture(t)
	for n := range native.uses {
		u := &native.uses[n]
		u.root, u.staging = plan.Target.InstallationID+"/", plan.Target.InstallationID+"_staging/"
		if u.principal.Purpose == "catalog_read" || u.principal.Purpose == "catalog_append" {
			u.root, u.staging = plan.Target.InstallationID+"/catalog/", ""
		}
		u.principal.IdentityHash, u.principal.RefVersion = refs[u.principal.Purpose].IdentityHash, refs[u.principal.Purpose].Version
		u.credential.NotBefore, u.credential.Until = now.Add(-time.Minute), now.Add(5*time.Minute)
		rules, e := minioPermissionObjectRulesV2(u.principal.Purpose, u.bucket, u.root, u.staging)
		if e != nil {
			t.Fatal(e)
		}
		u.principal.PolicySHA256 = minioProducerComponentPolicy(t, native, u.principal.PolicyName, rules)
	}
	native.configuration.ObserverPolicySHA256 = minioProducerComponentPolicy(t, native, native.configuration.ObserverPolicyName, minioPermissionObserverRulesV2(native.uses))
	observer := native.reader.credential
	// The old HTTP-only fixture's observer secret is shorter
	// than the real credential-file minimum; this complete producer must load
	// an actual admissible private credential, not bypass that decoder.
	observer.SecretKey = "original-observer-component-secret"
	observer.NotBefore, observer.Until = now.Add(-time.Minute), now.Add(5*time.Minute)
	// Transport is the exact native source shape, with signatures independently
	// verified for all six real request credentials. No Passed/oracle hook.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.model.openTx.Load() != 0 {
			t.Error("native network I/O under original SQL lock")
		}
		if r.Method != http.MethodGet {
			t.Error("permission producer mutated native target")
			http.Error(w, "method", 405)
			return
		}
		post := f.headCreated.Load()
		if post {
			f.postNative.Add(1)
		} else {
			f.preNative.Add(1)
		}
		var caller *minioPermissionUse
		for n := range native.uses {
			u := &native.uses[n]
			if minioPermissionFixtureSignature(r, u.credential.AccessKey, u.credential.SecretKey) {
				caller = u
				break
			}
		}
		isObserver := minioPermissionFixtureSignature(r, observer.AccessKey, observer.SecretKey)
		if isObserver {
			caller = &minioPermissionUse{principal: minioPermissionPrincipal{PolicyName: native.configuration.ObserverPolicyName}, credential: observer}
		}
		if caller == nil {
			t.Error("invalid actual native SigV4")
			http.Error(w, "signature", 403)
			return
		}
		if r.URL.Path == "/minio/admin/v3/accountinfo" && r.URL.RawQuery == "" {
			f.selfReads.Add(1)
			policy := native.responses["policy:"+caller.principal.PolicyName].(map[string]any)["Policy"]
			_ = json.NewEncoder(w).Encode(map[string]any{"AccountName": caller.credential.AccessKey, "Policy": policy, "Server": map[string]any{"Type": 3}, "Buckets": nil})
			return
		}
		if r.URL.Path == minioEffectiveOwnerGuardPath && r.URL.Query().Get("subSys") == "policy_plugin" && r.URL.Query().Get("key") == "" && len(r.URL.Query()) == 2 {
			f.helpReads.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(minioEffectiveGuardFixtureError())
			return
		}
		if !isObserver {
			t.Error("ordinary role used as native observer")
			http.Error(w, "observer", 403)
			return
		}
		responseKey := ""
		switch r.URL.Path {
		case "/minio/admin/v3/info":
			if r.URL.RawQuery != "metrics=false" {
				t.Error("info query")
			}
			responseKey = "server"
		case "/minio/admin/v3/user-info":
			responseKey = "user:" + r.URL.Query().Get("accessKey")
		case "/minio/admin/v3/info-canned-policy":
			if r.URL.Query().Get("v") != "2" {
				t.Error("policy version")
			}
			responseKey = "policy:" + r.URL.Query().Get("name")
		case "/artifacts", "/catalog":
			if r.URL.RawQuery == "policy=" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchBucketPolicy</Code></Error>`))
				return
			}
			if r.URL.RawQuery == "versioning=" {
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
				if post && r.URL.Path == "/catalog" && f.postBucketPasses.Add(1) == 2 && scenario == "post-commit-original-sql-window" {
					f.ownerTailReached.Store(true)
					f.model.clockBeyondOriginalWindow.Store(true)
				}
				return
			}
		}
		response := native.responses[responseKey]
		if response == nil {
			t.Error("unexpected native source request")
			http.Error(w, "missing", 404)
			return
		}
		if post && scenario == "post-commit-native-generation" && r.URL.Path == "/minio/admin/v3/user-info" {
			// Still a valid enabled original user/policy in BOTH tail passes;
			// only actual current native generation differs from pre-commit.
			changed := map[string]any{}
			for k, v := range response.(map[string]any) {
				changed[k] = v
			}
			changed["updatedAt"] = now.Add(time.Second)
			response = changed
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	p := minioPermissionProvider{Endpoint: server.URL, Region: "us-east-1", CAFile: write("minio-ca.pem", ca), CASHA256: hash(ca), SPKISHA256: hash(server.Certificate().RawSubjectPublicKeyInfo), DeploymentID: "deployment", Deployment: minioPermissionObject{"minio", "minio-deployment-uid"}, ReplicaSet: minioPermissionObject{"minio-rs", "minio-rs-uid"}, Pod: minioPermissionObject{"minio-pod", "minio-pod-uid"}, Service: minioPermissionObject{"minio", "minio-service-uid"}, ServiceAccount: minioPermissionObject{"minio", "minio-sa-uid"}, Container: "minio", ImageID: "sha256:original-image", Node: "original-node", NodeUID: "original-node-uid"}
	credentialFiles, credentialPins := map[string]string{}, map[string]string{}
	for _, u := range native.uses {
		raw, _ := json.Marshal(u.credential)
		credentialFiles[u.principal.Purpose] = write(u.principal.Purpose+".credential", raw)
		credentialPins[u.principal.Purpose] = hash(raw)
	}
	observerRaw, _ := json.Marshal(observer)
	target := PublicationTargetMaterials{Version: publicationTargetVersion, InstallationID: plan.Target.InstallationID, Endpoint: p.Endpoint, Region: p.Region, Bucket: "artifacts", Root: plan.Target.InstallationID + "/", RemoteStagingRoot: plan.Target.InstallationID + "_staging/", ReadIdentityHash: refs["artifact_read"].IdentityHash, ReadRefVersion: refs["artifact_read"].Version, WriteIdentityHash: refs["artifact_write"].IdentityHash, WriteRefVersion: refs["artifact_write"].Version, DeleteIdentityHash: refs["artifact_delete"].IdentityHash, DeleteRefVersion: refs["artifact_delete"].Version, CAIdentityHash: hash([]byte("original-minio-ca-identity")), CARefVersion: "original-ca-1", CAFile: p.CAFile, CASHA256: p.CASHA256, ReadCredentialFile: credentialFiles["artifact_read"], ReadCredentialSHA256: credentialPins["artifact_read"], WriteCredentialFile: credentialFiles["artifact_write"], WriteCredentialSHA256: credentialPins["artifact_write"], DeleteCredentialFile: credentialFiles["artifact_delete"], DeleteCredentialSHA256: credentialPins["artifact_delete"]}
	catalog := PublicationCatalogMaterials{Version: publicationCatalogMaterialsVersion, InstallationID: target.InstallationID, Endpoint: p.Endpoint, Region: p.Region, Bucket: "catalog", Root: plan.Target.InstallationID + "/catalog/", ReadIdentityHash: refs["catalog_read"].IdentityHash, ReadRefVersion: refs["catalog_read"].Version, AppendIdentityHash: refs["catalog_append"].IdentityHash, AppendRefVersion: refs["catalog_append"].Version, CAIdentityHash: target.CAIdentityHash, CARefVersion: target.CARefVersion, CAFile: p.CAFile, CASHA256: p.CASHA256, ReadCredentialFile: credentialFiles["catalog_read"], ReadCredentialSHA256: credentialPins["catalog_read"], AppendCredentialFile: credentialFiles["catalog_append"], AppendCredentialSHA256: credentialPins["catalog_append"]}
	catalogRaw, _ := json.Marshal(catalog)
	target.CatalogMaterialsFile, target.CatalogMaterialsSHA256 = write("catalog.json", catalogRaw), hash(catalogRaw)
	targetRaw, _ := json.Marshal(target)
	g := minioPermissionGrant{Version: "minio-permission-grant.v1", Installation: plan.Target.InstallationID, Namespace: plan.Target.Namespace, NamespaceUID: plan.Target.NamespaceUID, ConfigSHA256: hash(configRaw), Profile: minioPermissionProfileV2, Epoch: 1, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute), Provider: p}
	for _, u := range native.uses {
		g.Principals = append(g.Principals, u.principal)
	}
	grantRaw, _ := ce.Canonical(g)
	var exportedGrant install.MinIOPermissionGrant
	if err := json.Unmarshal(grantRaw, &exportedGrant); err != nil {
		t.Fatal(err)
	}
	f.definition = install.MinIOPermissionDefinition{Version: install.MinIOPermissionDefinitionVersion, ConfigFile: write("config.json", configRaw), ConfigSHA256: hash(configRaw), TargetFile: write("target.json", targetRaw), TargetSHA256: hash(targetRaw), GrantName: "original-minio-permission-grant", HeadName: "original-minio-permission-head", Grant: exportedGrant, ObserverCredentialFile: write("observer.credential", observerRaw), ObserverCredentialSHA256: hash(observerRaw), ObserverAccountSHA256: hash([]byte(observer.AccessKey)), ObserverPolicyName: native.configuration.ObserverPolicyName, ObserverPolicySHA256: native.configuration.ObserverPolicySHA256}
	definitionRaw, _ := ce.Canonical(f.definition)
	f.definitionFile, f.definitionSHA = write("definition.json", definitionRaw), hash(definitionRaw)
	f.kube = minioProducerComponentKubernetes(t, f, plan, p)
	planRaw, _ := ce.Canonical(plan)
	f.installer, err = install.New(db, f.kube, planRaw, hash(planRaw), public, hash(public))
	if err != nil {
		t.Fatal("actual A constructor", err)
	}
	enrolled, err := f.installer.Enroll(ctx, f.password)
	if err != nil {
		t.Fatal("actual A enrolled operator", err)
	}
	f.enrollment = enrolled.Pin
	return f
}

func minioProducerComponentPolicy(t *testing.T, f *minioPermissionNativeFixture, name string, rules []minioPermissionRule) string {
	t.Helper()
	statements := []json.RawMessage{}
	for _, rule := range rules {
		actions, resources := append([]string(nil), rule.Actions...), append([]string(nil), rule.Resources...)
		sort.Strings(actions)
		sort.Strings(resources)
		raw, _ := ce.Canonical(map[string]any{"Effect": "Allow", "Action": actions, "Resource": resources})
		statements = append(statements, raw)
	}
	sort.Slice(statements, func(i, j int) bool { return string(statements[i]) < string(statements[j]) })
	raw, err := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		t.Fatal(err)
	}
	f.responses["policy:"+name].(map[string]any)["Policy"] = json.RawMessage(raw)
	return hash(raw)
}

func minioProducerComponentKubernetes(t *testing.T, f *minioProducerComponent, plan install.Plan, p minioPermissionProvider) *fake.Clientset {
	t.Helper()
	truth, replicas := true, int32(1)
	meta := func(name, uid string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: plan.Target.Namespace, UID: types.UID(uid), ResourceVersion: "original-1"}
	}
	owned := func(kind string, ref minioPermissionObject) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: ref.Name, UID: types.UID(ref.UID), Controller: &truth}}
	}
	d := &appsv1.Deployment{ObjectMeta: meta(p.Deployment.Name, p.Deployment.UID), Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "minio"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: meta(p.ReplicaSet.Name, p.ReplicaSet.UID)}
	rs.OwnerReferences = owned("Deployment", p.Deployment)
	pod := &corev1.Pod{ObjectMeta: meta(p.Pod.Name, p.Pod.UID), Spec: corev1.PodSpec{ServiceAccountName: p.ServiceAccount.Name, NodeName: p.Node}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: p.Container, ImageID: p.ImageID, ContainerID: "runtime://original-minio", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().UTC().Truncate(time.Second))}}}}}}
	pod.OwnerReferences = owned("ReplicaSet", p.ReplicaSet)
	pod.Labels = map[string]string{"app": "minio"}
	svc := &corev1.Service{ObjectMeta: meta(p.Service.Name, p.Service.UID), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "minio"}}}
	k := fake.NewSimpleClientset(d, rs, pod, svc, &corev1.ServiceAccount{ObjectMeta: meta(p.ServiceAccount.Name, p.ServiceAccount.UID)}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: p.Node, UID: types.UID(p.NodeUID), ResourceVersion: "original-1"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(plan.Target.ClusterID), ResourceVersion: "original-1"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: plan.Target.Namespace, UID: types.UID(plan.Target.NamespaceUID), ResourceVersion: "original-1"}})
	k.PrependReactor("create", "selfsubjectreviews", func(ktesting.Action) (bool, kruntime.Object, error) {
		return true, &authnv1.SelfSubjectReview{Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: plan.OwnerUsername, UID: plan.OwnerUID, Groups: plan.OwnerGroups}}}, nil
	})
	k.PrependReactor("create", "selfsubjectaccessreviews", func(a ktesting.Action) (bool, kruntime.Object, error) {
		r := a.(ktesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).Spec.ResourceAttributes
		allowed := r != nil && r.Namespace == plan.Target.Namespace && r.Name == plan.EnrollmentName && r.Resource == "configmaps" && r.Group == "" && (r.Verb == "get" || r.Verb == "create" || r.Verb == "update")
		return true, &authzv1.SelfSubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: !allowed}}, nil
	})
	k.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, kruntime.Object, error) {
		cm := a.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		cm.UID, cm.ResourceVersion = types.UID("actual-created-"+cm.Name), "created-1"
		err := k.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, plan.Target.Namespace)
		if err == nil {
			f.created.Add(1)
			if cm.Name == f.definition.HeadName {
				f.headCreated.Store(true)
			}
		}
		return true, cm, err
	})
	k.PrependReactor("list", "endpointslices", func(ktesting.Action) (bool, kruntime.Object, error) {
		slice := discoveryv1.EndpointSlice{ObjectMeta: meta("original-endpoint", "original-endpoint-uid"), AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &truth}, Addresses: []string{"10.0.0.1"}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: plan.Target.Namespace, Name: p.Pod.Name, UID: types.UID(p.Pod.UID)}}}}
		slice.Labels = map[string]string{"kubernetes.io/service-name": p.Service.Name}
		slice.OwnerReferences = owned("Service", p.Service)
		return true, &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{ResourceVersion: "original-list-1"}, Items: []discoveryv1.EndpointSlice{slice}}, nil
	})
	k.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, kruntime.Object, error) {
		if f.scenario == "post-output-current-owner-head-revoked" && f.headCreated.Load() && !f.ownerTailReached.Load() {
			if _, err := os.Stat(f.output); err == nil {
				obj, err := k.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), plan.Target.Namespace, f.definition.HeadName)
				if err != nil {
					t.Error(err)
					return false, nil, nil
				}
				cm := obj.(*corev1.ConfigMap).DeepCopy()
				var head minioPermissionHead
				if json.Unmarshal([]byte(cm.Data["record.json"]), &head) != nil {
					t.Error("actual head parse")
					return false, nil, nil
				}
				head.State = "revoked"
				raw, _ := ce.Canonical(head)
				cm.Data["record.json"] = string(raw)
				cm.BinaryData["signature"] = ed25519.Sign(f.key, append([]byte(minioPermissionHeadDomain), raw...))
				cm.ResourceVersion = "revoked-2"
				if err := k.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, plan.Target.Namespace); err != nil {
					t.Error(err)
				}
				f.ownerTailReached.Store(true)
			}
		}
		return false, nil, nil
	})
	// Observe every fake API callback, including auth and final consumer GET.
	// This asserts production never performs Kubernetes I/O under its SQL tx.
	k.PrependReactor("*", "*", func(ktesting.Action) (bool, kruntime.Object, error) {
		if f.model.openTx.Load() != 0 {
			t.Error("Kubernetes I/O under original SQL lock")
		}
		return false, nil, nil
	})
	return k
}
