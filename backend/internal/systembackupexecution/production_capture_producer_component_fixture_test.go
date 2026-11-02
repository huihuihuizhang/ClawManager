package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/crypto/bcrypt"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type materialProducerComponent struct {
	installer                                  *install.Installer
	enrollment                                 install.EnrollmentPin
	model                                      *producerComponentSQL
	definition                                 ProductionMaterialDefinition
	core                                       DeploymentConfig
	forward                                    *c.PinnedExecutionIdentity
	password, key                              []byte
	definitionFile, definitionSHA, privateFile string
	outputs                                    []string
	enrollmentWrites                           atomic.Int64
	armTail, tailReached                       atomic.Bool
}

func componentConfigValues(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-resources.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Default json.RawMessage `json:"default"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if json.Unmarshal(raw, &schema) != nil {
		t.Fatal("original public config contract")
	}
	value := map[string]any{"enabled": false, "alert_profile": "development", "minimum_recovery_points": 1}
	for group, definition := range map[string]string{"durations": "DurationConfig", "capacity": "CapacityConfig", "concurrency": "ConcurrencyConfig", "preflight_limits": "PreflightLimits"} {
		fields := map[string]json.RawMessage{}
		for name, property := range schema.Defs[definition].Properties {
			if len(property.Default) == 0 {
				t.Fatal("missing original public default", name)
			}
			fields[name] = property.Default
		}
		value[group] = fields
	}
	var registries []sec.BootstrapRegistryRef
	for _, name := range []string{"parts", "redis_sources", "failure_domains", "disaster_identity_mapping", "source_writers", "rbac_bindings", "secret_allowlist", "strong_auth_issuers", "provider_proof_issuers"} {
		registries = append(registries, sec.BootstrapRegistryRef{Kind: name, Version: "component-original-1", SHA256: hash([]byte(name))})
	}
	var references []sec.BootstrapSecretRef
	for _, purpose := range []string{"artifact_write", "artifact_read", "artifact_delete", "artifact_upload_issuer", "artifact_ca", "evidence_store", "evidence_write", "evidence_read", "evidence_delete", "evidence_ca", "evidence_kek", "kek", "capture_signing", "acceptance_signing", "catalog_signing", "catalog_read", "catalog_append", "catalog_snapshot", "nonce_hmac", "status_relay"} {
		references = append(references, sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: hash([]byte(purpose)), Version: "component-original-1"})
	}
	value["registries"], value["references"] = registries, references
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := sec.DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal("real complete disabled config decoder", err)
	}
	return decoded.CanonicalJSON()
}

// Independently declared constructor inputs and actual A Installer calls with
// real bcrypt/Ed25519. SQL and Kubernetes are strict component models. No task,
// actual source/custody/provider capability or field readiness is manufactured.
func newMaterialProducerComponent(t *testing.T, ctx context.Context) *materialProducerComponent {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("complete producer enforces native Linux private directory/file modes")
	}
	f := &materialProducerComponent{}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) string {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key, f.password = key, []byte("component-only-original-local-admin-password")
	t.Cleanup(func() { clear(f.key); clear(f.password) })
	f.privateFile = write("original-enrolled-issuer.private", key)
	cfg := runtimeDeploymentFixture(t)
	cfg.InstallationID, cfg.CaptureScope = "installation_producer_component", "six-part"
	cfg.SourceDatabase, cfg.SourceServerUUID = "original_component_source", "12345678-1234-1234-1234-123456789abc"
	cfg.KeyDirectory, cfg.ProfileFile = dir, filepath.Join(dir, "profile.json")
	cfg.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(dir, "capture-materials.json")}
	cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(dir, "formal-verifier-declaration.json")}
	cfg.RuntimeSources.Supported = []b.AgentKind{{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}}
	grantPublic, grantKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(grantKey)
	cfg.ForwardGrant = GrantReference{Path: filepath.Join(dir, "forward.json"), PublicKey: base64.StdEncoding.EncodeToString(grantPublic)}
	cfg.RecoveryGrant = GrantReference{Path: filepath.Join(dir, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(grantPublic)}
	profile := api.ExecutionProfile{InstallationID: cfg.InstallationID, Revision: "component-original-1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "same-cluster-copy", TargetRisks: []string{"source_overlap", "same_failure_domain"}, FailureDomain: "original-component-domain", RestoreTargetRef: "component-declaration-only", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileSHA, err := profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	write("profile.json", profileRaw)
	coreRaw, err := json.Marshal(cfg)
	if err != nil || cfg.Validate() != nil {
		t.Fatal("original full core config", err)
	}
	coreFile := write("core.json", coreRaw)
	config := componentConfigValues(t)
	configFile := write("config.json", config)
	recordKey := make([]byte, 32)
	if _, err := rand.Read(recordKey); err != nil {
		t.Fatal(err)
	}
	defer clear(recordKey)
	write("record-v1", recordKey)
	now := time.Now().UTC().Truncate(time.Microsecond)
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: "component_controller@127.0.0.1", ServerUUID: cfg.SourceServerUUID, Database: cfg.SourceDatabase, ConfigVersion: 1, ConfigSHA256: hash(config), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(coreRaw), WorkerIssuerSHA256: strings.Repeat("e", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(recordKey)}}}
	grantRaw, _ := json.Marshal(grant)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(grantRaw), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(grantKey, grantRaw))})
	write("forward.json", envelope)
	f.forward, err = c.NewPinnedExecutionIdentity(cfg.ForwardGrant.Path, hash(envelope), dir, grantPublic)
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, _, operations := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("explicit pure source declaration")
	}
	metadata.Redis.Policy.Purpose = "functional_test"
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("producer must not claim source permission from this unused TLS fixture")
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := write("original-source-public-ca.pem", ca)
	m := productionCaptureMaterials{Version: productionCaptureMaterialsVersion, Revision: "component-original-1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DeploymentConfigSHA256: hash(coreRaw), CaptureGrantSHA256: hash(envelope), Operations: map[string]productionCaptureOperation{}, SkillBucket: metadata.Skills.Bucket, SkillPrefix: metadata.Skills.Prefix, MaxObjects: metadata.Skills.MaxObjects, MaxObjectBytes: metadata.Skills.MaxObjectBytes, MaxObjectTotalBytes: metadata.Skills.MaxTotalBytes, ResourceTypes: []productionResourceType{{Part: "deployment_resources", Version: "v1", Resource: "configmaps"}, {Part: "secret_bundle", Version: "v1", Resource: "secrets"}}}
	for _, name := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation} {
		x := operations[name]
		x.Formal.ConfigSHA256 = grant.ConfigSHA256
		x.Workload.Identity.Namespace, x.Workload.Image, x.Workload.StagingClaim, x.Workload.ServiceAccount = cfg.Namespace, cfg.WorkerImage, cfg.StagingClaim, cfg.Security.ServiceAccountName
		x.Workload.WorkerControl.URL = cfg.ControlURL
		x.MountIdentities = []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: x.Workload.FormalMaterials.ConfigMap, UID: "component-" + name + "-mapping-uid", SHA256: hash([]byte(name))}}
		for _, input := range x.Workload.FormalMaterials.Inputs {
			x.MountIdentities = append(x.MountIdentities, kube.MountIdentity{Volume: input.Volume, Kind: input.Kind, Name: input.Name, UID: "component-shared-original-source-input-uid", SHA256: hash([]byte(input.Kind + "/" + input.Name))})
		}
		if name == "capture-database" {
			database := *x.Request.Database
			database.Name, database.ServerUUID, database.Address, database.TLSServerName, database.RootCA = cfg.SourceDatabase, cfg.SourceServerUUID, u.Host, u.Hostname(), ca
			database.SourceScope = domain.BusinessTableSourceScope
			projection, err := domain.SchemaCensusProjection(cfg.SourceDatabase, "component_metadata@localhost", false)
			if err != nil {
				t.Fatal(err)
			}
			database.SchemaCensus = &domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: "component_metadata@localhost", DefinitionSHA256: hash([]byte("BEGIN " + projection + "; END"))}
			x.Request.Database = &database
		}
		m.Operations[name] = x
	}
	controlIssuer, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(controlPrivate)
	m.ControlEvidence = &ce.CaptureInput{SchemaRegistryFile: filepath.Join(dir, "schema-declaration.json"), SchemaRegistrySHA256: strings.Repeat("a", 64), RedactionRegistryFile: filepath.Join(dir, "redaction-declaration.json"), RedactionRegistrySHA256: strings.Repeat("b", 64), CoverageWindowSeconds: 3600}
	m.ControlEvidenceSource = &worker.ControlEvidenceSourceMount{Endpoint: cfg.ControlURL, GrantFile: filepath.Join(dir, "control-worker-declaration.json"), ControllerGrantFile: filepath.Join(dir, "control-controller-declaration.json"), GrantSHA256: strings.Repeat("c", 64), Issuer: controlIssuer}
	for _, object := range []bool{false, true} {
		name := "redis"
		credential := metadataSourceCredential{Username: "component-source", Password: []byte("component-only")}
		if object {
			name, credential = "objects", metadataSourceCredential{AccessKey: "component-only", SecretKey: []byte("component-only")}
		}
		raw, _ := json.Marshal(credential)
		mount := worker.FormalSourceMount{GrantFile: filepath.Join(dir, name+".grant.json"), Issuer: public, CredentialFile: write(name+".credential.json", raw), CredentialSHA256: hash(raw)}
		mapping := &worker.SourceTLSMapping{Address: u.Host, ServerName: u.Hostname(), CAFile: caFile, CASHA256: hash(ca)}
		if object {
			mount.Objects, mount.ObjectPrefixes = mapping, []worker.ObjectSourcePrefix{{Bucket: m.SkillBucket, Prefix: m.SkillPrefix + "/"}}
			m.Objects = mount
		} else {
			mount.Redis, mount.RedisScope, mount.RedisPrefixes = mapping, &worker.RedisSourceBoundary{ID: metadata.Redis.Policy.Source.ID, ServerID: metadata.Redis.ServerID, Database: metadata.Redis.Policy.DB}, append([]string{}, metadata.Redis.Policy.Prefixes...)
			m.Redis = mount
		}
	}
	runtimePolicy := metadata.Mounts[0].Policy
	runtimePolicy.Runtime = scope.Runtime{Type: "openclaw", Mode: "pro", Backend: "desktop", Variant: "linux", OS: "linux"}
	token := []byte("component-only-original-metadata-token")
	m.Discovery = &productionSourceDiscovery{GrantFile: filepath.Join(dir, "metadata.grant.json"), Issuer: public, ControllerDeployment: "component-controller", ControllerDeploymentUID: "component-controller-uid", ControllerServiceAccount: "component-controller", ControllerServiceAccountUID: "component-controller-sa-uid", SourceAPI: worker.ResourceSourceMount{Server: server.URL, CAFile: caFile, CASHA256: hash(ca), TokenFile: write("source.token", token)}, SourceAPITokenSHA256: hash(token), SourceAPIServiceAccount: "component-source", SourceAPIServiceAccountUID: "component-source-sa-uid", Redis: metadata.Redis, RuntimePolicies: []worker.RuntimePolicy{runtimePolicy}, ResourceActors: map[string]productionSourceActor{"deployment_resources": {Name: "component-resources", UID: "component-resources-uid"}, "secret_bundle": {Name: "component-secrets", UID: "component-secrets-uid"}}, TeamPlatformUnits: map[string][]string{"deployment/" + cfg.Writers[0].Namespace + "/" + cfg.Writers[0].Name: b.TeamsWorkUnits()}}
	unsigned, _ := json.Marshal(m)
	f.core = cfg
	f.definition = ProductionMaterialDefinition{Version: productionMaterialDefinitionVersion, CoreFile: coreFile, CoreSHA256: hash(coreRaw), ConfigFile: configFile, ConfigSHA256: hash(config), ForwardGrantSHA256: hash(envelope), NotBefore: now.Add(-time.Second), Until: now.Add(45 * time.Second), Materials: unsigned}
	definitionRaw, _ := json.Marshal(f.definition)
	f.definitionFile, f.definitionSHA = write("definition.json", definitionRaw), hash(definitionRaw)
	f.outputs = []string{m.Redis.GrantFile, m.Objects.GrantFile, m.Discovery.GrantFile, cfg.CaptureModules.Path}
	stored, err := bcrypt.GenerateFromPassword(f.password, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	f.model = &producerComponentSQL{account: "component_installer@127.0.0.1", server: grant.ServerUUID, database: grant.Database, username: "component-original-local-admin", stored: string(stored), userID: 901, afterSourceWindow: f.definition.Until.Add(time.Microsecond)}
	db := sql.OpenDB(producerComponentConnector{f.model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	plan := install.Plan{SchemaVersion: install.PlanVersion, EnrollmentName: "component-original-enrollment", EnrollmentID: "component-enrollment", EnrollmentRevision: 1, IssuerID: "component-original-issuer", Target: owner.Target{InstallationID: cfg.InstallationID, ServerUUID: grant.ServerUUID, Database: grant.Database, DatabaseAccount: grant.DatabaseAccount, ClusterID: "component-original-cluster", Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID}, InstallerDatabaseAccount: f.model.account, LocalAdminUsername: f.model.username, OwnerUsername: "component-original-operator", OwnerUID: "component-owner-uid", OwnerGroups: []string{"system:authenticated"}, IssuerPublicKeySHA256: hash(public), KubernetesAPI: "https://component-api.invalid", KubernetesCASHA256: hash(ca), DatabaseCASHA256: hash(ca), DatabaseTLSServerName: "component-original-mysql.invalid"}
	client := kubefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(plan.Target.ClusterID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(cfg.NamespaceUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: cfg.Security.ServiceAccountName, Namespace: cfg.Namespace, UID: types.UID(cfg.Security.ServiceAccountUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: m.Discovery.ControllerServiceAccount, Namespace: cfg.Namespace, UID: types.UID(m.Discovery.ControllerServiceAccountUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: m.Discovery.SourceAPIServiceAccount, Namespace: cfg.Namespace, UID: types.UID(m.Discovery.SourceAPIServiceAccountUID)}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: m.Discovery.ControllerDeployment, Namespace: cfg.Namespace, UID: types.UID(m.Discovery.ControllerDeploymentUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: m.Discovery.ControllerServiceAccount}}}})
	client.PrependReactor("create", "selfsubjectreviews", func(ktesting.Action) (bool, kruntime.Object, error) {
		if f.model.openTx.Load() != 0 {
			t.Fatal("identity API called under original SQL locks")
		}
		return true, &authnv1.SelfSubjectReview{Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: plan.OwnerUsername, UID: plan.OwnerUID, Groups: plan.OwnerGroups}}}, nil
	})
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, kruntime.Object, error) {
		attributes := action.(ktesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).Spec.ResourceAttributes
		allowed := attributes != nil && attributes.Namespace == cfg.Namespace && attributes.Resource == "configmaps" && attributes.Name == plan.EnrollmentName && (attributes.Verb == "get" || attributes.Verb == "create" || attributes.Verb == "update")
		return true, &authzv1.SelfSubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: !allowed}}, nil
	})
	client.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, kruntime.Object, error) {
		cm := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		cm.UID, cm.ResourceVersion = "component-actual-enrollment-uid", "1"
		f.enrollmentWrites.Add(1)
		err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, cfg.Namespace)
		return true, cm, err
	})
	client.PrependReactor("get", "deployments", func(ktesting.Action) (bool, kruntime.Object, error) {
		if f.armTail.Load() && !f.tailReached.Load() {
			all := true
			for _, file := range f.outputs {
				info, err := os.Stat(file)
				all = all && err == nil && info != nil && info.Size() > 0
			}
			if all {
				f.tailReached.Store(true)
				f.model.clockBeyondOriginalWindow.Store(true)
			}
		}
		return false, nil, nil
	})
	planRaw, _ := json.Marshal(plan)
	planRaw, err = jsoncanonicalizer.Transform(planRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.installer, err = install.New(db, client, planRaw, hash(planRaw), public, hash(public))
	if err != nil {
		t.Fatal("actual A installer constructor", err)
	}
	receipt, err := f.installer.Enroll(ctx, f.password)
	if err != nil {
		t.Fatal("actual authenticated A enrollment through controlled protocols", err)
	}
	f.enrollment = receipt.Pin
	return f
}
