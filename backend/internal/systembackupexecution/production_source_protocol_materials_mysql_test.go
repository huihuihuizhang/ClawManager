package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/testfixture"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Original signed controller metadata/worker declarations for this independently
// declared source. No task authority or physical witness is manufactured.
func (scenario *sourceProtocolScenario) installMetadata(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) {
	t.Helper()
	s := f.service
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(f.directory, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	server := scenario.server
	u, _ := url.Parse(server.URL)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := write("original-metadata-ca.pem", ca)
	f.resourceSources = map[string]worker.ResourceSourceMount{}
	for part, actor := range map[string]string{"deployment_resources": "d-resources", "secret_bundle": "d-secrets"} {
		f.resourceSources[part] = worker.ResourceSourceMount{Server: server.URL, CAFile: caFile, CASHA256: hash(ca), TokenFile: write("original-"+actor+"-token", []byte("named-"+actor+"-token"))}
	}
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
	metadata.Redis.Policy.Purpose = "functional_test" // Independent declaration before every scope/signature.
	scenario.installPublicCA(f)
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
		request := worker.Request{Version: worker.Version, Operation: operation, Deadline: s.Forward.DeploymentBinding().ExpiresAt, ArtifactName: name, MaxArchiveBytes: 32 << 20, MaxCompressedBytes: 32 << 20}
		if object {
			mount.Objects, mount.ObjectPrefixes = mapping, []worker.ObjectSourcePrefix{{Bucket: m.SkillBucket, Prefix: m.SkillPrefix + "/"}}
			request.SkillObjects = &worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: f.sourceInventory.Skills.SHA256(), Bucket: m.SkillBucket, Prefix: m.SkillPrefix, MaxObjects: m.MaxObjects, MaxObjectBytes: m.MaxObjectBytes, MaxTotalBytes: m.MaxObjectTotalBytes, MaxIndexBytes: 65536}
		} else {
			redis := testfixture.NewRedisProtocol(t, testfixture.RedisScenario{TLS: true, ExpectedUser: "d-redis", ExpectedPassword: "named-local-fixture", ServerID: metadata.Redis.ServerID, Keys: []testfixture.RedisKey{{Key: metadata.Redis.Policy.Prefixes[0] + "original", Type: "string", Dump: []byte("named-local-redis-dump-protocol-bytes"), PTTL: -1}}})
			mapping.Address, mapping.ServerName = redis.Address, "127.0.0.1"
			mapping.CAFile, mapping.CASHA256 = write("original-redis-ca.pem", redis.CAPEM), hash(redis.CAPEM)
			mount.Redis, mount.RedisScope, mount.RedisPrefixes = mapping, &worker.RedisSourceBoundary{ID: metadata.Redis.Policy.Source.ID, ServerID: metadata.Redis.ServerID, Database: metadata.Redis.Policy.DB}, append([]string{}, metadata.Redis.Policy.Prefixes...)
			request.SourceRedis = &metadata.Redis
		}
		scopeSHA, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, mount)
		if err != nil {
			t.Fatal("original finite static worker source scope", name, err)
		}
		now := time.Now().UTC()
		record, _ := json.Marshal(worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: s.Config.InstallationID, ConfigSHA256: hash(f.config), WorkerNamespace: s.Config.Namespace, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, Operation: operation, ScopeSHA256: scopeSHA, CredentialSHA256: mount.CredentialSHA256, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)})
		grantRaw, _ := json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: ed25519.Sign(private, append([]byte(worker.FormalSourceGrantDomain), record...))})
		mount.GrantFile, mount.GrantSHA256 = write("original-"+name+"-grant.json", grantRaw), hash(grantRaw)
		if object {
			m.Objects = mount
		} else {
			m.Redis = mount
		}
	}
	discovery := &productionSourceDiscovery{GrantFile: filepath.Join(f.directory, "original-metadata-grant.json"), GrantSHA256: strings.Repeat("a", 64), Issuer: public, ControllerDeployment: "d-source-controller", ControllerDeploymentUID: "d-controller-uid", ControllerServiceAccount: "d-controller", ControllerServiceAccountUID: "d-controller-sa-uid", SourceAPI: worker.ResourceSourceMount{Server: server.URL, CAFile: caFile, CASHA256: hash(ca), TokenFile: write("original-metadata-token", token)}, SourceAPITokenSHA256: hash(token), SourceAPIServiceAccount: "d-metadata", SourceAPIServiceAccountUID: "d-metadata-uid", Redis: metadata.Redis, ResourceActors: map[string]productionSourceActor{"deployment_resources": {Name: "d-resources", UID: "d-resources-uid"}, "secret_bundle": {Name: "d-secrets", UID: "d-secrets-uid"}}, TeamPlatformUnits: map[string][]string{"deployment/" + s.Config.Writers[0].Namespace + "/" + s.Config.Writers[0].Name: append([]string{}, b.TeamsWorkUnits()...)}}
	for _, declared := range []scope.Runtime{{Type: "openclaw", Mode: "pro", Backend: "desktop", Variant: "linux", OS: "linux"}, {Type: "openclaw", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}} {
		discovery.RuntimePolicies = append(discovery.RuntimePolicies, worker.RuntimePolicy{Version: "independent-source-protocol-r1", Image: "original/openclaw@sha256:" + strings.Repeat("a", 64), Runtime: declared, Files: metadata.Mounts[0].Policy.Files})
	}
	discovery.SecretPolicy = &originalSecretPolicyReference{Protocol: root.SecretCapturePolicyVersion, Path: f.secretPolicyFile, SHA256: f.secretPolicySHA}
	// Independent LOCAL owner declaration, not source UID observations or a
	// positive attestation/recovery/eligibility/verifier claim.
	domainPin, err := originalFailureDomainsPin(f.config)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := ce.Canonical(originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: f.service.Config.InstallationID, ConfigSHA256: hash(f.config), FailureDomains: domainPin, Target: publicationManifestTarget{Class: f.profile.TargetClass, Domain: f.profile.FailureDomain, Risks: append([]string{}, f.profile.TargetRisks...)}, RecoveryEvidenceStatus: "not_provided"})
	if err != nil {
		t.Fatal(err)
	}
	discovery.PublicationPolicy = &originalPublicationPolicyReference{Protocol: originalPublicationPolicyVersion, Path: write("original-publication-policy.json", policyRaw), SHA256: hash(policyRaw)}
	m.Discovery = discovery
	controller := true
	for _, object := range []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerServiceAccount, Namespace: s.Config.Namespace, UID: types.UID(discovery.ControllerServiceAccountUID)}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.SourceAPIServiceAccount, Namespace: s.Config.Namespace, UID: types.UID(discovery.SourceAPIServiceAccountUID)}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "d-resources", Namespace: s.Config.Namespace, UID: "d-resources-uid"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "d-secrets", Namespace: s.Config.Namespace, UID: "d-secrets-uid"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerDeployment, Namespace: s.Config.Namespace, UID: types.UID(discovery.ControllerDeploymentUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}}}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "d-source-rs", Namespace: s.Config.Namespace, UID: "d-source-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: discovery.ControllerDeployment, UID: types.UID(discovery.ControllerDeploymentUID), Controller: &controller}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "d-source-pod", Namespace: s.Config.Namespace, UID: "d-source-pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "d-source-rs", UID: "d-source-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	} {
		// This is finite named API fixture setup, not controller production writes.
		if err := scenario.addObject(object); err != nil {
			t.Fatal(err)
		}
	}
	s.controllerActor.PodName, s.controllerActor.PodUID, s.controllerActor.ServiceAccountName = "d-source-pod", "d-source-pod-uid", discovery.ControllerServiceAccount
	scopeSHA, err := sourceMetadataScope(m)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, _ := json.Marshal(originalSourceMetadataGrant{Version: sourceMetadataGrantVersion, InstallationID: s.Config.InstallationID, ControllerOwner: s.Config.ControllerOwner, DeploymentConfigSHA256: s.ConfigDigest, CaptureGrantSHA256: s.Forward.GrantSHA256(), ConfigSHA256: hash(f.config), ScopeSHA256: scopeSHA, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID, ControllerDeployment: discovery.ControllerDeployment, ControllerDeploymentUID: discovery.ControllerDeploymentUID, ControllerServiceAccount: discovery.ControllerServiceAccount, ControllerServiceAccountUID: discovery.ControllerServiceAccountUID, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)})
	grant, _ := json.Marshal(signedSourceMetadataGrant{Record: record, Signature: ed25519.Sign(private, append([]byte(sourceMetadataGrantDomain), record...))})
	write("original-metadata-grant.json", grant)
	discovery.GrantSHA256 = hash(grant)
	material, _ := json.Marshal(m)
	write("capture-materials.json", material)
	if err := s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(material)}}); err != nil {
		t.Fatal("same-task original metadata material loader", err)
	}
	// No capture authority is requested: taskless delegation is consumed only by
	// the real DeploymentService observer, never an empty task.
}
