//go:build systembackup_minio_september_native

package systembackupexecution

import (
	mn "clawreef/internal/systembackup/minionative"
	ce "clawreef/internal/systembackupcontrolevidence"
	ev "clawreef/internal/systembackupevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	probe "clawreef/internal/systembackupreferenceprobe"
	"context"
	"encoding/json"
	"errors"
	"io"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	disc "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type r17CompatS3SafeDeleteAudit struct {
	API                                                                     string
	HTTPStatus                                                              int
	VersionPresent                                                          bool
	VersionSHA256, KeySHA256, IssuerAccountSHA256                           string
	QueryVersionCount                                                       int
	QueryVersionValueSHA256                                                 []string
	VersionHeaderPresent, AmzVersionHeaderPresent, ForceDeleteHeaderPresent bool
	VersionHeaderSHA256, AmzVersionHeaderSHA256, ForceDeleteHeaderValue     string
}
type r17CompatS3Audit struct {
	mu      sync.Mutex
	addUser int
	names   map[string]int
	deletes []r17CompatS3SafeDeleteAudit
}

func r17CompatS3AuditStart(t *testing.T) *r17CompatS3Audit {
	t.Helper()
	a := &r17CompatS3Audit{names: map[string]int{}}
	listener, e := net.Listen("tcp", ":18080")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		defer clear(raw)
		var event struct {
			API struct {
				Name       string `json:"name"`
				Object     string `json:"object"`
				StatusCode int    `json:"statusCode"`
			} `json:"api"`
			RequestPath   string            `json:"requestPath"`
			RequestQuery  map[string]string `json:"requestQuery"`
			RequestHeader map[string]string `json:"requestHeader"`
			AccessKey     string            `json:"accessKey"`
		}
		if e == nil && json.Unmarshal(raw, &event) == nil && event.API.Name != "" {
			a.mu.Lock()
			a.names[event.API.Name]++
			if event.RequestPath == "/minio/admin/v3/add-user" || strings.Contains(strings.ToLower(event.API.Name), "adduser") {
				a.addUser++
			}
			if event.API.Name == "DeleteObject" {
				version, present := event.RequestQuery["versionId"]
				entry := r17CompatS3SafeDeleteAudit{API: event.API.Name, HTTPStatus: event.API.StatusCode, VersionPresent: version != "", VersionSHA256: hash([]byte(version)), KeySHA256: hash([]byte(event.API.Object)), IssuerAccountSHA256: hash([]byte(event.AccessKey))}
				if present {
					values := strings.Split(version, ",")
					entry.QueryVersionCount = len(values)
					for _, value := range values {
						entry.QueryVersionValueSHA256 = append(entry.QueryVersionValueSHA256, hash([]byte(value)))
					}
				}
				for name, value := range event.RequestHeader {
					switch {
					case strings.EqualFold(name, "versionId"):
						entry.VersionHeaderPresent = true
						entry.VersionHeaderSHA256 = hash([]byte(value))
					case strings.EqualFold(name, "x-amz-version-id"):
						entry.AmzVersionHeaderPresent = true
						entry.AmzVersionHeaderSHA256 = hash([]byte(value))
					case strings.EqualFold(name, "x-minio-force-delete"):
						entry.ForceDeleteHeaderPresent = true
						if value == "true" || value == "false" {
							entry.ForceDeleteHeaderValue = value
						} else {
							entry.ForceDeleteHeaderValue = "other"
						}
					}
				}
				a.deletes = append(a.deletes, entry)
			}
			a.mu.Unlock()
		}
		w.WriteHeader(200)
	}), ReadHeaderTimeout: time.Second}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return a
}
func (a *r17CompatS3Audit) count() int {
	time.Sleep(400 * time.Millisecond)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addUser
}
func (a *r17CompatS3Audit) apiCount(name string) int {
	time.Sleep(400 * time.Millisecond)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.names[name]
}

// Only Kubernetes read-only resource-chain objects are fake. All TLS, root
// authentication, absence checks, IAM writes and self reads use real MinIO.
func r17CompatS3Kube(p probe.MinIOProvider, image string) *fake.Clientset {
	yes := true
	one := int32(1)
	ns := "owned-native"
	om := func(name, uid string) meta.ObjectMeta {
		return meta.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(uid), ResourceVersion: "1"}
	}
	own := func(kind string, p probe.ObjectPin) []meta.OwnerReference {
		return []meta.OwnerReference{{Kind: kind, Name: p.Name, UID: types.UID(p.UID), Controller: &yes}}
	}
	labels := map[string]string{"app": "owned-native"}
	d := &apps.Deployment{ObjectMeta: om(p.Deployment.Name, p.Deployment.UID), Spec: apps.DeploymentSpec{Replicas: &one, Selector: &meta.LabelSelector{MatchLabels: labels}}}
	rs := &apps.ReplicaSet{ObjectMeta: om(p.ReplicaSet.Name, p.ReplicaSet.UID)}
	rs.OwnerReferences = own("Deployment", p.Deployment)
	pod := &core.Pod{ObjectMeta: om(p.Pod.Name, p.Pod.UID), Spec: core.PodSpec{ServiceAccountName: p.ServiceAccount.Name, NodeName: p.Node}, Status: core.PodStatus{Phase: core.PodRunning, ContainerStatuses: []core.ContainerStatus{{Name: p.Container, Ready: true, ImageID: p.ImageID, ContainerID: "docker://owned-native", State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}}}
	container := core.Container{Name: p.Container, Image: image}
	d.Spec.Template.Spec.Containers = []core.Container{container}
	pod.Spec.Containers = []core.Container{container}
	pod.Labels = labels
	pod.OwnerReferences = own("ReplicaSet", p.ReplicaSet)
	svc := &core.Service{ObjectMeta: om(p.Service.Name, p.Service.UID), Spec: core.ServiceSpec{Selector: labels}}
	ep := disc.EndpointSlice{ObjectMeta: om("owned-endpoints", "owned-endpoints-uid"), AddressType: disc.AddressTypeIPv4, Endpoints: []disc.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: disc.EndpointConditions{Ready: &yes}, TargetRef: &core.ObjectReference{Kind: "Pod", Namespace: ns, Name: p.Pod.Name, UID: types.UID(p.Pod.UID)}}}}
	ep.Labels = map[string]string{"kubernetes.io/service-name": p.Service.Name}
	ep.OwnerReferences = own("Service", p.Service)
	k := fake.NewSimpleClientset(&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns, UID: "owned-namespace-uid", ResourceVersion: "1"}}, d, rs, pod, svc, &core.ServiceAccount{ObjectMeta: om(p.ServiceAccount.Name, p.ServiceAccount.UID)}, &core.Node{ObjectMeta: meta.ObjectMeta{Name: p.Node, UID: types.UID(p.NodeUID), ResourceVersion: "1"}})
	k.PrependReactor("list", "endpointslices", func(kt.Action) (bool, runtime.Object, error) {
		return true, &disc.EndpointSliceList{ListMeta: meta.ListMeta{ResourceVersion: "1"}, Items: []disc.EndpointSlice{ep}}, nil
	})
	return k
}

func TestR17DeleteCompatFinalImageSixRoles(t *testing.T) {
	audit := r17CompatS3AuditStart(t)
	f, proof := loadCOnceNativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var root nativePublicationCredential
	cOnceNativeRead(t, "secrets/root.json", &root)
	n := cOnceNativeClient(t, f, root)
	defer n.close()
	if proof.ImageID != ma.DeleteCompatImageManifest || !ma.MatchesDeleteCompatImageReference(f.MinioImage) {
		t.Fatal("actual final OCI image proof required")
	}
	n.provider.ImageID = proof.ImageID
	rawInfo, infoStatus, e := n.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	var info struct {
		DeploymentID string
	}
	if e != nil || infoStatus != http.StatusOK || minioPermissionUniqueJSON(rawInfo) != nil || json.Unmarshal(rawInfo, &info) != nil || info.DeploymentID == "" {
		t.Fatal("authenticated deployment discovery failed")
	}
	id := info.DeploymentID
	n.provider.DeploymentID = id
	if _, e := n.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile); e != nil {
		t.Fatal("final image server profile failed", e)
	}
	if _, e := n.serverSeptember(ctx); e == nil {
		t.Fatal("final image entered September profile")
	}
	wrongImage := *n
	wrongImage.provider.ImageID = "sha256:52dfd5c0bbd38d3219f2058c7af216d9f9a27a994b7b5baad09bbd38866015ff"
	if _, e := wrongImage.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile); e == nil {
		t.Fatal("old image accepted under new profile")
	}
	if _, e := wrongImage.serverSeptember(ctx); e == nil {
		t.Fatal("new server commit accepted under September with old image pin")
	}
	p := probe.MinIOProvider{Endpoint: f.Endpoint, Region: f.Region, CAFile: f.CAFile, CASHA256: f.CASHA256, SPKISHA256: f.SPKISHA256, DeploymentID: id, Deployment: probe.ObjectPin{"native", "deployment-uid"}, ReplicaSet: probe.ObjectPin{"native-rs", "rs-uid"}, Pod: probe.ObjectPin{"native-pod", "pod-uid"}, Service: probe.ObjectPin{"native", "service-uid"}, ServiceAccount: probe.ObjectPin{"native", "sa-uid"}, Container: "minio", ImageID: proof.ImageID, Node: "owned-node", NodeUID: "node-uid"}
	k := r17CompatS3Kube(p, f.MinioImage)
	cOnceNativeSaveJSON(t, "secrets/helper-root.json", probe.OriginalS3OwnerCredential{AccessKey: root.AccessKey, SecretKey: []byte(root.SecretKey), Version: "owned-native-root.v1", NotBefore: root.NotBefore, Until: root.Until})
	rootPin := probe.FilePin{File: filepath.Join(cOnceNativeRoot, "secrets/helper-root.json"), SHA256: cOnceNativeFileSHA(filepath.Join(cOnceNativeRoot, "secrets/helper-root.json"))}
	principal := func(suffix string) probe.Principal {
		key := nativePublicationCredential{AccessKey: "c1_" + f.Owner + "_" + suffix, SecretKey: cOnceNativeRandom(t, 32), NotBefore: f.NotBefore, Until: f.Until}
		file := "secrets/principal-" + suffix + ".json"
		cOnceNativeSaveJSON(t, file, key)
		return probe.Principal{AccountSHA256: hash([]byte(key.AccessKey)), Credential: probe.FilePin{File: filepath.Join(cOnceNativeRoot, file), SHA256: cOnceNativeFileSHA(filepath.Join(cOnceNativeRoot, file))}}
	}
	valid := principal("a")
	missing, status, e := n.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {"c1_" + f.Owner + "_a"}})
	var fields map[string]string
	_ = json.Unmarshal(missing, &fields)
	names := []string{}
	for key := range fields {
		names = append(names, key)
	}
	sort.Strings(names)
	t.Logf("real missing-user status=%d error=%t keys=%v code=%s resource_match=%t request_id_present=%t host_id_present=%t", status, e != nil, names, fields["Code"], fields["Resource"] == "/minio/admin/v3/user-info", fields["RequestId"] != "", fields["HostId"] != "")
	t.Run("owner_target", func(t *testing.T) {
		if e := probe.ObserveOriginalS3OwnerTarget(ctx, k, "owned-native", "owned-namespace-uid", p, rootPin); e != nil {
			t.Fatal(e)
		}
	})
	beforeCreate := audit.count()
	created := t.Run("create_real_helper", func(t *testing.T) {
		if e := probe.CreateOriginalS3Principal(ctx, k, "owned-native", "owned-namespace-uid", p, rootPin, valid); e != nil {
			t.Error(e)
		}
		body, status, e := n.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {"c1_" + f.Owner + "_a"}})
		var user map[string]json.RawMessage
		_ = json.Unmarshal(body, &user)
		names := []string{}
		for name := range user {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Logf("root_readback status=%d error=%t keys=%v", status, e != nil, names)
		if status != 200 || e != nil {
			t.Error("new account not readable by real root")
		}
		var detail struct {
			Status    string
			UpdatedAt time.Time
			AuthInfo  *struct{ Type, AuthServer, AuthServerUserID string } `json:"userAuthInfo"`
		}
		detailErr := json.Unmarshal(body, &detail)
		t.Logf("root_user status=%s updated_at_zero=%t decode_error=%t", detail.Status, detail.UpdatedAt.IsZero(), detailErr != nil)
		if detail.AuthInfo != nil {
			t.Logf("root_user status=%s auth_type=%s auth_server_empty=%t auth_user_matches=%t", detail.Status, detail.AuthInfo.Type, detail.AuthInfo.AuthServer == "", detail.AuthInfo.AuthServerUserID == "c1_"+f.Owner+"_a")
		}
		var selfKey nativePublicationCredential
		cOnceNativeRead(t, "secrets/principal-a.json", &selfKey)
		self := cOnceNativeClient(t, f, selfKey)
		defer self.close()
		reply, ss, se := self.get(ctx, "/minio/admin/v3/accountinfo", nil)
		var denied struct{ Code string }
		_ = json.Unmarshal(reply, &denied)
		t.Logf("real self credential accountinfo status=%d transport_error=%t code=%s", ss, se != nil, denied.Code)
		var account map[string]json.RawMessage
		_ = json.Unmarshal(reply, &account)
		accountFields := []string{}
		for key := range account {
			accountFields = append(accountFields, key)
		}
		sort.Strings(accountFields)
		var accountName string
		_ = json.Unmarshal(account["AccountName"], &accountName)
		t.Logf("real self account fields=%v uppercase_account_name_matches=%t", accountFields, accountName == selfKey.AccessKey)
	})
	t.Run("one_encrypted_add_user_write", func(t *testing.T) {
		if delta := audit.count() - beforeCreate; delta != 1 {
			t.Errorf("real audit add-user delta=%d want=1", delta)
		}
	})
	t.Run("duplicate_rejected", func(t *testing.T) {
		if !created {
			t.Skip("positive create failed; duplicate discriminator unproven")
		}
		before := audit.count()
		if probe.CreateOriginalS3Principal(ctx, k, "owned-native", "owned-namespace-uid", p, rootPin, valid) == nil {
			t.Error("duplicate accepted")
		}
		if audit.count() != before {
			t.Error("duplicate attempted extra add-user")
		}
	})
	for _, kind := range []string{"namespace", "identity", "wrongroot"} {
		t.Run(kind+"_reject_no_account", func(t *testing.T) {
			v := principal(map[string]string{"namespace": "b", "identity": "c", "wrongroot": "d"}[kind])
			pp := p
			rp := rootPin
			uid := "owned-namespace-uid"
			if kind == "namespace" {
				uid = "wrong-namespace"
			}
			if kind == "identity" {
				pp.DeploymentID = "wrong-server"
			}
			if kind == "wrongroot" {
				bad := probe.OriginalS3OwnerCredential{AccessKey: root.AccessKey, SecretKey: []byte(cOnceNativeRandom(t, 32)), Version: "owned-native-root.v1", NotBefore: root.NotBefore, Until: root.Until}
				cOnceNativeSaveJSON(t, "secrets/wrongroot.json", bad)
				rp = probe.FilePin{File: "/fixture/secrets/wrongroot.json", SHA256: cOnceNativeFileSHA("/fixture/secrets/wrongroot.json")}
			}
			before := audit.count()
			if probe.CreateOriginalS3Principal(ctx, k, "owned-native", uid, pp, rp, v) == nil {
				t.Error("invalid target accepted")
			}
			if audit.count() != before {
				t.Error("rejected target attempted add-user")
			}
			_, status, e := n.get(ctx, "/minio/admin/v3/user-info", url.Values{"accessKey": {"c1_" + f.Owner + "_" + map[string]string{"namespace": "b", "identity": "c", "wrongroot": "d"}[kind]}})
			if status != 404 || e != nil {
				t.Error("rejected account unexpectedly exists")
			}
		})
	}
	t.Run("channel_and_generic_four_real_permissions", func(t *testing.T) {
		if !created {
			t.Skip("requires successful original helper create")
		}
		r17CompatS3Roles(t, ctx, f, p, k, rootPin, n, audit)
	})
	audit.count()
	audit.mu.Lock()
	t.Logf("real MinIO audit add_user_total=%d api_names=%v", audit.addUser, audit.names)
	audit.mu.Unlock()
	t.Run("generated_publication_six_role_readback", func(t *testing.T) {
		r17CompatS3GeneratedPublication(t, ctx, f, p, k, n, audit)
	})
	t.Log("scope: final OCI image, actual MinIO TLS/IAM/S3, modeled Kubernetes resource chain and publication template data")
}

func r17CompatS3Roles(t *testing.T, ctx context.Context, f cOnceNativeFixture, provider probe.MinIOProvider, k *fake.Clientset, rootPin probe.FilePin, n *minioPermissionHTTP, audit *r17CompatS3Audit) {
	dir := "/fixture/roles"
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	bucket := "cn-" + f.Owner[:12]
	upload := "cu-" + f.Owner[:12]
	ca, e := os.ReadFile(f.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	c := probe.S3Profile{Version: "original-six-reference-s3-profile.v1", Installation: "owned-native", Namespace: "owned-native", NamespaceUID: "owned-namespace-uid", Provider: provider, UploadBucket: upload, UploadRoot: "artifact/owned/", UploadStagingRoot: "staging/owned/", Evidence: ev.S3Config{Endpoint: f.Endpoint, Region: f.Region, Bucket: bucket, Root: "evidence", Installation: "owned-native", Identity: hash([]byte("owned-native-evidence")), Version: "fixture-v1", CAPEM: ca, CASHA256: f.CASHA256}}
	statement := func(actions, resources []string) map[string]any {
		sort.Strings(actions)
		sort.Strings(resources)
		return map[string]any{"Effect": "Allow", "Action": actions, "Resource": resources}
	}
	policy := func(st []map[string]any) []byte {
		sort.Slice(st, func(i, j int) bool {
			a, _ := ce.Canonical(st[i])
			b, _ := ce.Canonical(st[j])
			return string(a) < string(b)
		})
		b, e := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": st})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	evidenceARN := "arn:aws:s3:::" + bucket + "/evidence/owned-native/*"
	observerRules := []map[string]any{statement([]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}), statement([]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, []string{"arn:aws:s3:::" + bucket, "arn:aws:s3:::" + upload})}
	purposes := []string{"metadata_observer", "artifact_upload_issuer", "evidence_read", "evidence_write", "evidence_delete", "c1_channel_upstream"}
	policies := [][]byte{policy(observerRules), policy([]map[string]any{statement([]string{"s3:PutObject"}, []string{"arn:aws:s3:::" + upload + "/artifact/owned/*", "arn:aws:s3:::" + upload + "/staging/owned/*"})}), policy([]map[string]any{statement([]string{"s3:GetObjectVersion"}, []string{evidenceARN})}), policy([]map[string]any{statement([]string{"s3:PutObject"}, []string{evidenceARN})}), policy([]map[string]any{statement([]string{"s3:DeleteObjectVersion"}, []string{evidenceARN})})}
	principals := []probe.Principal{}
	keys := []nativePublicationCredential{}
	for i, purpose := range purposes {
		suffix := string(rune('a' + i))
		file := "secrets/principal-" + suffix + ".json"
		path := filepath.Join(cOnceNativeRoot, file)
		if _, e := os.Stat(path); os.IsNotExist(e) {
			cOnceNativeSaveJSON(t, file, nativePublicationCredential{AccessKey: "c1_" + f.Owner + "_" + suffix, SecretKey: cOnceNativeRandom(t, 32), NotBefore: f.NotBefore, Until: f.Until})
		}
		var key nativePublicationCredential
		cOnceNativeRead(t, file, &key)
		keys = append(keys, key)
		principal := probe.Principal{Purpose: purpose, AccountSHA256: hash([]byte(key.AccessKey)), PolicyName: "owned-" + f.Owner[:12] + "-" + suffix, Credential: probe.FilePin{File: path, SHA256: cOnceNativeFileSHA(path)}}
		if i < 5 {
			principal.PolicySHA256 = hash(policies[i])
		}
		principals = append(principals, principal)
		if i > 0 {
			if e := probe.CreateOriginalS3Principal(ctx, k, c.Namespace, c.NamespaceUID, provider, rootPin, principal); e != nil {
				t.Fatalf("real helper role create index=%d: %v", i, e)
			}
		}
	}
	c.Observer = principals[0]
	c.Principals = principals[1:5]
	if e := probe.ValidateS3Profile(c); e != nil {
		t.Fatal("role fixture invalid", e)
	}
	channelPolicy, e := probe.OriginalS3ChannelPolicy(c)
	if e != nil {
		t.Fatal(e)
	}
	policies = append(policies, channelPolicy)
	principals[5].PolicySHA256 = hash(channelPolicy)
	for _, b := range []string{bucket, upload} {
		for _, args := range [][]string{{"mb", "native/" + b}, {"version", "enable", "native/" + b}} {
			if e := nativeInstallWriteOnce(ctx, dir, n, nil, args...); e != nil {
				t.Fatal("real bucket setup", e)
			}
		}
	}
	for i, p := range principals {
		file := filepath.Join(dir, "policy-"+string(rune('a'+i))+".json")
		if e := os.WriteFile(file, policies[i], 0600); e != nil {
			t.Fatal(e)
		}
		beforePolicyWrite := audit.apiCount("AddCannedPolicy")
		createErr := nativeInstallWriteOnce(ctx, dir, n, nil, "admin", "policy", "create", "native", p.PolicyName, file)
		if errors.Is(createErr, install.ErrCommitUnknown) {
			for attempt := 0; attempt < 3 && createErr != nil; attempt++ {
				t.Logf("policy index=%d resolving original pending intent read-only attempt=%d", i, attempt)
				createErr = nativeInstallWriteOnce(ctx, dir, n, nil, "admin", "policy", "create", "native", p.PolicyName, file)
			}
		}
		if delta := audit.apiCount("AddCannedPolicy") - beforePolicyWrite; delta != 1 {
			t.Fatalf("policy index=%d audited AddCannedPolicy delta=%d want=1 no resend", i, delta)
		}
		if e := createErr; e != nil {
			raw, st, ge := n.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {p.PolicyName}, "v": {"2"}})
			var response struct{ Policy json.RawMessage }
			_ = json.Unmarshal(raw, &response)
			var doc map[string]json.RawMessage
			_ = json.Unmarshal(response.Policy, &doc)
			docKeys := []string{}
			for name := range doc {
				docKeys = append(docKeys, name)
			}
			sort.Strings(docKeys)
			var statements []map[string]json.RawMessage
			_ = json.Unmarshal(doc["Statement"], &statements)
			shape := []map[string]any{}
			for _, s := range statements {
				fields := []string{}
				for name := range s {
					fields = append(fields, name)
				}
				sort.Strings(fields)
				var actions []string
				_ = json.Unmarshal(s["Action"], &actions)
				var resources []string
				_ = json.Unmarshal(s["Resource"], &resources)
				shape = append(shape, map[string]any{"fields": fields, "actions": actions, "resource_count": len(resources)})
			}
			t.Logf("real policy readback http=%d transport_error=%t document_fields=%v statement_shape=%v", st, ge != nil, docKeys, shape)
			var outer map[string]json.RawMessage
			_ = json.Unmarshal(raw, &outer)
			outerKeys := []string{}
			for key := range outer {
				outerKeys = append(outerKeys, key)
			}
			sort.Strings(outerKeys)
			var parsed struct {
				PolicyName             string
				Policy                 json.RawMessage
				CreateDate, UpdateDate time.Time
			}
			decodeErr := minioPermissionDecode(raw, &parsed)
			t.Logf("policy strict_decode_error=%t outer_fields=%v policy_name_matches=%t exact_structural_equal=%t sorted_array_equal=%t", decodeErr != nil, outerKeys, parsed.PolicyName == p.PolicyName, sourceGatePolicySame(parsed.Policy, policies[i]), r17CompatS3SortedJSON(parsed.Policy) == r17CompatS3SortedJSON(policies[i]))
			t.Logf("safe policy comparison actual=%s expected=%s", r17CompatS3SafePolicy(parsed.Policy, policies[i]), r17CompatS3SafePolicy(policies[i], policies[i]))
			for attempt := 0; attempt < 3; attempt++ {
				raw, st, ge = n.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {p.PolicyName}, "v": {"2"}})
				var again struct{ Policy json.RawMessage }
				_ = json.Unmarshal(raw, &again)
				t.Logf("policy repeated_read=%d http=%d error=%t structural_equal=%t sorted_array_equal=%t", attempt, st, ge != nil, sourceGatePolicySame(again.Policy, policies[i]), r17CompatS3SortedJSON(again.Policy) == r17CompatS3SortedJSON(policies[i]))
			}
			t.Fatalf("real policy create index=%d: %v", i, e)
		}
		policyReply, ps, pe := n.get(ctx, "/minio/admin/v3/info-canned-policy", url.Values{"name": {p.PolicyName}, "v": {"2"}})
		var policyProof struct{ Policy json.RawMessage }
		_ = json.Unmarshal(policyReply, &policyProof)
		normalized, ne := mn.NormalizeSeptemberMetadataObserverReadback(policyProof.Policy)
		t.Logf("policy proof index=%d http=%d error=%t submitted_sha256=%s readback_sha256=%s metadata_projection=%t normalized_sha256=%s original_pin_matches=%t", i, ps, pe != nil, hash(policies[i]), hash(policyProof.Policy), ne == nil, hash(normalized), ne == nil && hash(normalized) == p.PolicySHA256)
		if e := nativeInstallWriteOnce(ctx, dir, n, nil, "admin", "policy", "attach", "native", p.PolicyName, "--user", keys[i].AccessKey); e != nil {
			t.Fatalf("real policy attach index=%d: %v", i, e)
		}
	}
	material := map[string]any{"schema_version": "system-backup-native-publication-s3.v1", "installation_id": c.Installation, "endpoint": provider.Endpoint, "region": provider.Region, "bucket": upload, "root": c.UploadRoot, "remote_staging_root": c.UploadStagingRoot, "ca_file": provider.CAFile, "ca_sha256": provider.CASHA256, "write_credential_file": principals[1].Credential.File, "write_credential_sha256": principals[1].Credential.SHA256}
	cOnceNativeSaveJSON(t, "roles/upload-material.json", material)
	c.UploadMaterials = probe.FilePin{File: "/fixture/roles/upload-material.json", SHA256: cOnceNativeFileSHA("/fixture/roles/upload-material.json")}
	t.Run("generic_four_exact_observer", func(t *testing.T) {
		if _, e := probe.ObserveS3(ctx, k, c); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("separate_channel_exact_observer", func(t *testing.T) {
		if e := probe.ObserveOriginalS3Channel(ctx, c, principals[5]); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("real_version_list_put_head_and_role_denials", func(t *testing.T) {
		if e := probe.VerifyOriginalS3NativeOperations(ctx, c, principals[5], rootPin); e != nil {
			t.Error(e)
		}
	})
}

func r17CompatS3SortedJSON(raw []byte) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return "invalid"
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
			sort.Slice(x, func(i, j int) bool {
				a, _ := json.Marshal(x[i])
				b, _ := json.Marshal(x[j])
				return string(a) < string(b)
			})
			return x
		case map[string]any:
			for k, v := range x {
				x[k] = walk(v)
			}
			return x
		default:
			return v
		}
	}
	b, _ := ce.Canonical(walk(value))
	return string(b)
}

func r17CompatS3SafePolicy(raw, expected []byte) string {
	var document map[string]json.RawMessage
	var want map[string]json.RawMessage
	_ = json.Unmarshal(raw, &document)
	_ = json.Unmarshal(expected, &want)
	var ws []struct{ Resource []string }
	_ = json.Unmarshal(want["Statement"], &ws)
	resources := []string{}
	for _, s := range ws {
		resources = append(resources, s.Resource...)
	}
	sort.Strings(resources)
	var statements []map[string]json.RawMessage
	_ = json.Unmarshal(document["Statement"], &statements)
	safe := []map[string]any{}
	for _, s := range statements {
		var actions []string
		var effect string
		var rs []string
		_ = json.Unmarshal(s["Action"], &actions)
		_ = json.Unmarshal(s["Effect"], &effect)
		_ = json.Unmarshal(s["Resource"], &rs)
		refs := []string{}
		for _, r := range rs {
			ref := "unknown_sha256_" + hash([]byte(r))
			for i, known := range resources {
				if r == known {
					ref = string(rune('A' + i))
					break
				}
			}
			refs = append(refs, ref)
		}
		safe = append(safe, map[string]any{"Action": actions, "Effect": effect, "ResourceRefs": refs})
	}
	var version string
	_ = json.Unmarshal(document["Version"], &version)
	b, _ := ce.Canonical(map[string]any{"Version": version, "Statement": safe})
	return string(b)
}

func r17CompatS3GeneratedPublication(t *testing.T, ctx context.Context, f cOnceNativeFixture, provider probe.MinIOProvider, k *fake.Clientset, root *minioPermissionHTTP, audit *r17CompatS3Audit) {
	t.Helper()
	profile, ok := ma.NativeProfile(ma.DeleteCompatPermissionProfile)
	if !ok {
		t.Fatal("new profile missing")
	}
	model := newMinioSeptemberTerminalComponent(t, "")
	var definition install.MinIOPermissionDefinition
	raw, e := pinnedDeploymentFile(model.input.DefinitionFile, model.input.DefinitionSHA256, 262144)
	if e != nil || decodePublicationCanonical(raw, &definition) != nil {
		t.Fatal("fixture definition data unavailable", e)
	}
	definition.Version = profile.Definition
	definition.Grant.Profile = profile.Permission
	definition.Grant.Namespace, definition.Grant.NamespaceUID = "owned-native", "owned-namespace-uid"
	definition.Grant.NotBefore, definition.Grant.Until = f.NotBefore, f.Until
	raw, e = ce.Canonical(provider)
	if e != nil || decodePublicationCanonical(raw, &definition.Grant.Provider) != nil {
		t.Fatal("fixture provider data cannot bind", e)
	}
	target, catalog := model.protocol.p.target, model.protocol.p.catalog
	target.Endpoint, target.Region, target.CAFile, target.CASHA256 = f.Endpoint, f.Region, f.CAFile, f.CASHA256
	catalog.Endpoint, catalog.Region, catalog.CAFile, catalog.CASHA256 = f.Endpoint, f.Region, f.CAFile, f.CASHA256
	target.Bucket, catalog.Bucket = "cp-"+f.Owner[:12], "cc-"+f.Owner[:12]
	templateDirectory := firstInstallPrivateDirectory(t)
	write := func(name string, data any) (string, string) {
		file, sha, err := nativeInstallSave(templateDirectory, name, data)
		if err != nil {
			t.Fatal("fixture material write failed", err)
		}
		return file, sha
	}
	target.CatalogMaterialsFile, target.CatalogMaterialsSHA256 = write("compat-catalog.json", catalog)
	definition.TargetFile, definition.TargetSHA256 = write("compat-target.json", target)
	template, templateSHA := write("compat-definition.json", definition)
	admin := MinIONativeAdminFiles{UserFile: "/fixture/secrets/root-user", PasswordFile: "/fixture/secrets/root-password"}
	observed, e := InspectOriginalMinIONativeProvider(ctx, template, templateSHA, admin)
	if e != nil || observed["ServerCommit"] != profile.ServerCommit || observed["ServerVersion"] != profile.ServerVersion || observed["DeploymentID"] != provider.DeploymentID {
		t.Fatal("native installer probe did not observe new server", e)
	}
	directory := firstInstallPrivateDirectory(t)
	out, e := GenerateOriginalMinIONativeMaterials(template, templateSHA, directory)
	if e != nil {
		t.Fatal("new profile material generation failed", e)
	}
	var materials MinIONativeInstallMaterials
	raw, e = pinnedDeploymentFile(out.File, out.SHA256, 262144)
	if e != nil || decodePublicationCanonical(raw, &materials) != nil || len(materials.Roles) != 6 {
		t.Fatal("generated six-role materials unavailable", e)
	}
	for _, bucket := range []string{target.Bucket, catalog.Bucket} {
		for _, args := range [][]string{{"mb", "native/" + bucket}, {"version", "enable", "native/" + bucket}} {
			if e := nativeInstallWriteOnce(ctx, directory, root, nil, args...); e != nil {
				t.Fatal("versioned bucket setup failed", e)
			}
		}
	}
	before := audit.count()
	for _, role := range materials.Roles {
		credential, e := loadNativePublicationCredential(role.CredentialFile, role.CredentialSHA256)
		if e != nil || credential.AccessKey != role.Account {
			t.Fatal("generated role material invalid", role.Purpose)
		}
		if e := nativeInstallWriteOnce(ctx, directory, root, nil, "admin", "policy", "create", "native", role.PolicyName, role.PolicyFile); e != nil {
			t.Fatal("generated native policy creation failed", role.Purpose, e)
		}
		input := []byte(role.Account + "\n" + credential.SecretKey + "\n")
		e = nativeInstallWriteOnce(ctx, directory, root, input, "admin", "user", "add", "native")
		clear(input)
		if e != nil {
			t.Fatal("generated native user creation failed", role.Purpose, e)
		}
		if e := nativeInstallWriteOnce(ctx, directory, root, nil, "admin", "policy", "attach", "native", role.PolicyName, "--user", role.Account); e != nil {
			t.Fatal("generated native policy attachment failed", role.Purpose, e)
		}
	}
	if audit.count()-before != 6 {
		t.Fatal("expected six actual AddUser writes")
	}
	snapshot, e := ObserveOriginalMinIOPermissions(ctx, k, out.DefinitionFile, out.DefinitionSHA256)
	if e != nil || snapshot.Profile != profile.Permission || snapshot.ServerCommit != profile.ServerCommit || snapshot.NativeSourcesSHA256 == "" {
		t.Fatal("actual six-role named/effective readback failed", e)
	}
	p, e := readMinIOPermissionProductionInputs(out.DefinitionFile, out.DefinitionSHA256)
	if e != nil {
		t.Fatal(e)
	}
	defer p.clear()
	nonce := cOnceNativeRandom(t, 32)
	stage := p.target.RemoteStagingRoot + "bootstrap-probes/" + nonce + "/"
	cat := p.catalog.Root + "bootstrap-probes/" + nonce + "/"
	intent := MinIOBootstrapCapabilityIntent{
		Version: profile.Protocol, InstallationID: p.grant.Installation, AuthorityID: "fixture", GrantID: "fixture", Nonce: nonce,
		ArtifactKey: stage + "protocol.bin", ArtifactBadChecksumKey: stage + "reject-checksum.bin",
		CatalogKey: cat + "protocol.json", CatalogBadChecksumKey: cat + "reject-checksum.json",
		NotBefore: f.NotBefore, Until: f.Until,
	}
	file, sha := write("compat-capability.json", intent)
	resource := MinIOBootstrapTerminalResource{
		input: MinIOBootstrapTerminalInput{CapabilityIntentFile: file, CapabilityIntentSHA256: sha},
		grant: ma.SQLGrant{AuthorityID: intent.AuthorityID, GrantID: intent.GrantID, Target: ma.Target{InstallationID: intent.InstallationID},
			PermissionSource: ma.PermissionSource{Profile: profile.Permission}, NotBefore: f.NotBefore, Until: f.Until},
	}
	var inventory []MinIOBootstrapProbeObject
	if e := resource.probeTerminalProtocol(ctx, p, f.Until, &inventory); e != nil {
		t.Fatal("actual original publication protocol failed", e)
	}
	t.Logf("generated publication six-role native source=%s resources=%s", snapshot.NativeSourcesSHA256, snapshot.ResourcesSHA256)
}
