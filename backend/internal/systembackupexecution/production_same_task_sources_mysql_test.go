package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// This extends the ONE original HTTP/queue task, using its existing control
// pool, original source role, claim, runtime custody and writer observations.
// The remote APIs are explicit local TLS protocol fixtures. No Job, KMS use,
// owner-complete evidence, frozen schema approval or readiness is invented.
func (f *dOriginalSixPartTask) installOriginalMetadataSources(ctx context.Context, t *testing.T) *originalSourceMetadataAuthority {
	t.Helper()
	s, owner := f.service, f.owner
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(f.directory, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/skill-bucket/packages/") {
			key := strings.TrimPrefix(r.URL.Path, "/skill-bucket/packages/")
			body, exists := f.objectBodies[key]
			version := "original-six-v1"
			if key == "unreferenced.zip" {
				version = "original-unreferenced-v1"
			}
			if !exists || (r.Method != "GET" && r.Method != "HEAD") || r.URL.Query().Get("versionId") != version || !strings.Contains(r.Header.Get("Authorization"), "Credential=d-object-access/") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			checksum := md5.Sum(body)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("ETag", `"`+hex.EncodeToString(checksum[:])+`"`)
			w.Header().Set("Last-Modified", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			w.Header().Set("x-amz-version-id", version)
			if r.Method == "GET" {
				w.Write(body)
			}
			return
		}
		if r.URL.Path == "/skill-bucket" || r.URL.Path == "/skill-bucket/" {
			if r.Method != "GET" || !strings.Contains(r.Header.Get("Authorization"), "Credential=d-object-access/") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			switch {
			case r.URL.Query().Has("location"):
				fmt.Fprint(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			case r.URL.Query().Has("versioning"):
				fmt.Fprint(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
			case r.URL.Query().Has("versions") && r.URL.Query().Get("prefix") == "packages/":
				fmt.Fprintf(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>skill-bucket</Name><Prefix>packages/</Prefix><IsTruncated>false</IsTruncated><Version><Key>packages/original.zip</Key><VersionId>original-six-v1</VersionId><IsLatest>true</IsLatest><Size>%d</Size></Version><Version><Key>packages/unreferenced.zip</Key><VersionId>original-unreferenced-v1</VersionId><IsLatest>true</IsLatest><Size>%d</Size></Version></ListVersionsResult>`, len(f.objectBodies["original.zip"]), len(f.objectBodies["unreferenced.zip"]))
			default:
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer named-d-metadata-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			if r.Method != "POST" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(authnv1.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: "system:serviceaccount:" + s.Config.Namespace + ":d-metadata", UID: "d-metadata-uid"}}})
		case "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
			if r.Method != "POST" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(authzv1.SelfSubjectRulesReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}, Status: authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, Verbs: []string{"get", "list"}}}}})
		case "/api/v1/namespaces/" + s.Config.Namespace + "/configmaps", "/api/v1/namespaces/" + s.Config.Namespace + "/secrets":
			if r.Method != "GET" || !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList") || r.URL.Query().Get("limit") != "1000" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, Items: []metav1.PartialObjectMetadata{{ObjectMeta: metav1.ObjectMeta{Name: "original", Namespace: s.Config.Namespace, UID: "original-six-resource-uid"}}}})
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := write("original-metadata-ca.pem", ca)
	token := []byte("named-d-metadata-token")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	f.metadataSigner = private
	// Reuse ONLY the pure constructor input templates, never another task or
	// another SQL authority fixture. Worker admission is not called here.
	_, templateSource, _, _, templates := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	json.Unmarshal(templateSource.CaptureMetadata, &metadata)
	caInput, caPin := f.originalPublicCAInput(ctx, t)
	m := productionCaptureMaterials{Version: productionCaptureMaterialsVersion, Revision: "original-six-metadata-r1", InstallationID: s.Config.InstallationID, ControllerOwner: s.Config.ControllerOwner, DeploymentConfigSHA256: s.ConfigDigest, CaptureGrantSHA256: s.Forward.GrantSHA256(), Operations: map[string]productionCaptureOperation{}, SkillBucket: "skill-bucket", SkillPrefix: "packages", MaxObjects: 100, MaxObjectBytes: 1024, MaxObjectTotalBytes: 4096, ResourceTypes: []productionResourceType{{Part: "deployment_resources", Version: "v1", Resource: "configmaps"}, {Part: "secret_bundle", Version: "v1", Resource: "secrets"}}}
	for _, name := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
		op := templates[name]
		op.Workload.Identity.Namespace, op.Workload.Image, op.Workload.StagingClaim, op.Workload.ServiceAccount = s.Config.Namespace, s.Config.WorkerImage, s.Config.StagingClaim, s.Config.Security.ServiceAccountName
		op.Workload.WorkerControl.URL = s.Config.ControlURL
		op.Workload.FormalMaterials.Inputs = []kube.FormalInputMount{caInput}
		op.MountIdentities = []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: op.Workload.FormalMaterials.ConfigMap, UID: name + "-mapping-uid", SHA256: hash([]byte(name))}, caPin}
		if name == "capture-database" {
			op.Request.Database = &f.sourceSpec
		}
		if name == "capture-workspace" {
			op.Request.MaxFiles, op.Request.MaxFileBytes = int64(s.Config.Workspace.MaxFiles), s.Config.Workspace.MaxFileBytes
		}
		m.Operations[name] = op
	}
	for _, object := range []bool{false, true} {
		name, operation := "redis", "capture-source-redis"
		credential := metadataSourceCredential{Username: "d-redis", Password: []byte("named-local-fixture")}
		if object {
			name, operation = "objects", "capture-skill-objects"
			credential = metadataSourceCredential{AccessKey: "d-object-access", SecretKey: []byte("named-local-fixture")}
		}
		raw, _ := json.Marshal(credential)
		mount := worker.FormalSourceMount{Issuer: public, CredentialFile: write("original-"+name+"-credential.json", raw), CredentialSHA256: hash(raw)}
		mapping := &worker.SourceTLSMapping{Address: u.Host, ServerName: u.Hostname(), CAFile: caFile, CASHA256: hash(ca)}
		request := worker.Request{Version: worker.Version, Operation: operation, Deadline: f.input.Authority.DeadlineAt, ArtifactName: name, MaxArchiveBytes: 32 << 20, MaxCompressedBytes: 32 << 20}
		if object {
			mount.Objects, mount.ObjectPrefixes = mapping, []worker.ObjectSourcePrefix{{Bucket: m.SkillBucket, Prefix: m.SkillPrefix + "/"}}
			request.SkillObjects = &worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: f.sourceInventory.Skills.SHA256(), Bucket: m.SkillBucket, Prefix: m.SkillPrefix, MaxObjects: m.MaxObjects, MaxObjectBytes: m.MaxObjectBytes, MaxTotalBytes: m.MaxObjectTotalBytes, MaxIndexBytes: 65536}
		} else {
			mapping.Address = startDMetadataRedisTLS(t, server.TLS)
			mount.Redis, mount.RedisScope, mount.RedisPrefixes = mapping, &worker.RedisSourceBoundary{ID: metadata.Redis.Policy.Source.ID, ServerID: metadata.Redis.ServerID, Database: metadata.Redis.Policy.DB}, append([]string{}, metadata.Redis.Policy.Prefixes...)
			request.SourceRedis = &metadata.Redis
		}
		scopeSHA, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, mount)
		if err != nil {
			t.Fatal("original finite static worker source scope", name, err)
		}
		now := time.Now().UTC()
		record, _ := json.Marshal(worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: s.Config.InstallationID, ConfigSHA256: f.input.Authority.ConfigSHA256, WorkerNamespace: s.Config.Namespace, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, Operation: operation, ScopeSHA256: scopeSHA, CredentialSHA256: mount.CredentialSHA256, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)})
		grantRaw, _ := json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: ed25519.Sign(private, append([]byte(worker.FormalSourceGrantDomain), record...))})
		mount.GrantFile, mount.GrantSHA256 = write("original-"+name+"-grant.json", grantRaw), hash(grantRaw)
		if object {
			m.Objects = mount
		} else {
			m.Redis = mount
		}
	}
	discovery := &productionSourceDiscovery{GrantFile: filepath.Join(f.directory, "original-metadata-grant.json"), GrantSHA256: strings.Repeat("a", 64), Issuer: public, ControllerDeployment: "d-source-controller", ControllerDeploymentUID: "d-controller-uid", ControllerServiceAccount: "d-controller", ControllerServiceAccountUID: "d-controller-sa-uid", SourceAPI: worker.ResourceSourceMount{Server: server.URL, CAFile: caFile, CASHA256: hash(ca), TokenFile: write("original-metadata-token", token)}, SourceAPITokenSHA256: hash(token), SourceAPIServiceAccount: "d-metadata", SourceAPIServiceAccountUID: "d-metadata-uid", Redis: metadata.Redis, ResourceActors: map[string]productionSourceActor{"deployment_resources": {Name: "d-resources", UID: "d-resources-uid"}, "secret_bundle": {Name: "d-secrets", UID: "d-secrets-uid"}}, TeamPlatformUnits: map[string][]string{"deployment/" + s.Config.Writers[0].Namespace + "/" + s.Config.Writers[0].Name: append([]string{}, b.TeamsWorkUnits()...)}}
	for _, instance := range f.sourceInventory.Instances {
		image := "original/" + instance.Type + "@sha256:" + strings.Repeat("a", 64)
		if instance.ID == 9 {
			image = "original/hermes@sha256:" + strings.Repeat("b", 64)
		}
		discovery.RuntimePolicies = append(discovery.RuntimePolicies, worker.RuntimePolicy{Version: "named-original-pro-r1", Image: image, Runtime: scope.Runtime{Type: instance.Type, Mode: instance.Mode, Backend: instance.Backend, Variant: instance.Variant, OS: instance.OS}, Files: metadata.Mounts[0].Policy.Files})
	}
	m.Discovery = discovery
	controller := true
	for _, object := range []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerServiceAccount, Namespace: s.Config.Namespace, UID: types.UID(discovery.ControllerServiceAccountUID)}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.SourceAPIServiceAccount, Namespace: s.Config.Namespace, UID: types.UID(discovery.SourceAPIServiceAccountUID)}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "d-resources", Namespace: s.Config.Namespace, UID: "d-resources-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "d-secrets", Namespace: s.Config.Namespace, UID: "d-secrets-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerDeployment, Namespace: s.Config.Namespace, UID: types.UID(discovery.ControllerDeploymentUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "d-source-rs", Namespace: s.Config.Namespace, UID: "d-source-rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: discovery.ControllerDeployment, UID: types.UID(discovery.ControllerDeploymentUID), Controller: &controller}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "d-source-pod", Namespace: s.Config.Namespace, UID: "d-source-pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "d-source-rs", UID: "d-source-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	} {
		// This is finite named API fixture setup, not controller production writes.
		if err := owner.Client.(*kubefake.Clientset).Tracker().Add(object); err != nil {
			t.Fatal(err)
		}
	}
	s.controllerActor.PodName, s.controllerActor.PodUID, s.controllerActor.ServiceAccountName = "d-source-pod", "d-source-pod-uid", discovery.ControllerServiceAccount
	scopeSHA, err := sourceMetadataScope(m)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, _ := json.Marshal(originalSourceMetadataGrant{Version: sourceMetadataGrantVersion, InstallationID: s.Config.InstallationID, ControllerOwner: s.Config.ControllerOwner, DeploymentConfigSHA256: s.ConfigDigest, CaptureGrantSHA256: s.Forward.GrantSHA256(), ConfigSHA256: f.input.Authority.ConfigSHA256, ScopeSHA256: scopeSHA, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID, ControllerDeployment: discovery.ControllerDeployment, ControllerDeploymentUID: discovery.ControllerDeploymentUID, ControllerServiceAccount: discovery.ControllerServiceAccount, ControllerServiceAccountUID: discovery.ControllerServiceAccountUID, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)})
	grant, _ := json.Marshal(signedSourceMetadataGrant{Record: record, Signature: ed25519.Sign(private, append([]byte(sourceMetadataGrantDomain), record...))})
	write("original-metadata-grant.json", grant)
	discovery.GrantSHA256 = hash(grant)
	material, _ := json.Marshal(m)
	write("capture-materials.json", material)
	if err := s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(material)}}); err != nil {
		t.Fatal("same-task original metadata material loader", err)
	}
	authority, err := s.sourceMetadataAuthority(ctx, owner, f.input)
	if err != nil {
		t.Fatal("same-task signed original source-owner authority", err)
	}
	return authority
}

func (f *dOriginalSixPartTask) checkOriginalMetadataSources(ctx context.Context, t *testing.T) {
	t.Helper()
	authority := f.installOriginalMetadataSources(ctx, t)
	metadata, err := authority.sqlMetadata(ctx, f.sourceInventory)
	if err != nil || len(metadata.Census.Business) != 82 || len(metadata.Census.Control) != 95 || !reflect.DeepEqual(metadata.Schema, *f.sourceSpec.CaptureSchema) || len(metadata.Images) != 2 {
		t.Fatal("same-task original SQL source census/schema/images", len(metadata.Census.Business), len(metadata.Census.Control), err)
	}
	clients, err := authority.openClients(ctx)
	if err != nil {
		t.Fatal("same-task original TLS metadata clients", err)
	}
	defer clients.Close()
	skills, err := authority.skillObjectMetadata(ctx, clients, f.sourceInventory.Skills)
	if err != nil || len(skills.Objects) != 2 || !reflect.DeepEqual(skills.WorkspaceRequiredBlobIDs, []int{18}) {
		t.Fatal("same-task original referenced/unreferenced/versioned/local Skills selection", err)
	}
	reader, err := sh.NewS3VersionReaderWithMetadata(clients.Objects, skills.Bucket, skills.Prefix, skills.UserMetadataAllowlist)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range skills.Objects {
		version, err := reader.OpenVersion(ctx, object.Key, object.VersionID)
		if err != nil {
			t.Fatal("original exact-version source byte read", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(version.Body, skills.MaxObjectBytes+1))
		closeErr := version.Body.Close()
		if readErr != nil || closeErr != nil || version.VersionID != object.VersionID || version.Size != object.Size || hash(body) != hash(f.objectBodies[object.Key]) || int64(len(body)) != object.Size {
			t.Fatal("original exact-version source bytes/metadata changed")
		}
	}
	deployment, secrets, err := authority.resourceMetadata(ctx, clients)
	if err != nil || len(deployment.Selections) != 1 || len(secrets.Selections) != 1 {
		t.Fatal("same-task original finite resource selection", err)
	}
	if _, _, err := f.service.attachProductionSources(f.owner, b.LinuxProfileConfig{}); err == nil {
		t.Fatal("incomplete original CE material enabled the six-worker path")
	}
	var jobs, evidence int
	if f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'", f.publicID).Scan(&jobs) != nil || jobs != 0 || f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", f.publicID).Scan(&evidence) != nil || evidence != 0 {
		t.Fatal("metadata-only source stage dispatched Jobs or invented completion evidence")
	}
	f.installLocalOriginalControlApproval(ctx, t, metadata)
	f.installOriginalFormalMaterials(ctx, t)
	f.composeOriginalPublicRuntime(ctx, t)
}

// Pin the original public control trust anchor as an immutable formal input.
// This manifest binding is not worker or KMS material admission; those still
// require the original independent formal-material setup and live checks.
func (f *dOriginalSixPartTask) originalPublicCAInput(ctx context.Context, t *testing.T) (kube.FormalInputMount, kube.MountIdentity) {
	t.Helper()
	const name = "d-original-kms-ca"
	immutable := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.service.Config.Namespace, UID: "d-original-kms-ca-uid"}, Immutable: &immutable, Data: map[string]string{"ca.pem": string(f.owner.Issuer.ServerRoots)}}
	existing, err := f.owner.Client.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		if string(existing.UID) != string(cm.UID) || !reflect.DeepEqual(existing.Data, cm.Data) {
			t.Fatal("original public CA input replaced")
		}
		cm = existing
	} else if _, err := f.owner.Client.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal("original public CA input", err)
	}
	return kube.FormalInputMount{Volume: "formal-kms-ca", Kind: "ConfigMap", Name: name, Directory: "/run/backup/materials/kms-ca", Items: []corev1.KeyToPath{{Key: "ca.pem", Path: "ca.pem"}}}, kube.MountIdentity{Volume: "formal-kms-ca", Kind: "ConfigMap", Name: name, UID: string(cm.UID), SHA256: kube.ContentHash([]any{cm.Data, cm.BinaryData})}
}
