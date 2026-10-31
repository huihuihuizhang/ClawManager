package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type aPublisherVerifierFixture struct {
	history                *publisherHistoryFixture
	cfg                    a.PublisherVerifierConfig
	factory                *a.PublisherVerifierFactory
	envelope               []byte
	logins, decrypts       atomic.Int64
	generates              atomic.Int64
	controlGenerateRequest *w.KeyRequest
	controlContexts        sync.Map
	onLogin, onDecrypt     func()
	original               a.OriginalRecord
	putOriginal            func(a.OriginalRecord, uint64)
	captureDeadline        time.Time
	materials              PublisherVerifierMaterials
	credentialIssuedAt     atomic.Int64
}

type aPublisherVerifierFixtureOptions struct {
	FullService           bool
	SourceBytes           int
	CapabilityWindow      time.Duration
	PublicationTarget     *PublicationTargetMaterials
	ControlEvidence       bool
	ControlURL            string
	ControlRequestedParts []string
	ConfigSnapshot        []byte
	WrapControlConnector  func(driver.Connector) driver.Connector
	WorkerIssuer          *control.IdentityIssuer
}

func newAPublisherVerifierFixture(t *testing.T, fullService ...bool) *aPublisherVerifierFixture {
	options := aPublisherVerifierFixtureOptions{}
	if len(fullService) > 0 {
		options.FullService = fullService[0]
	}
	return newAPublisherVerifierFixtureOptions(t, options)
}

func newAPublisherVerifierFixtureOptions(t *testing.T, fixture aPublisherVerifierFixtureOptions) *aPublisherVerifierFixture {
	t.Helper()
	credentials, serverUUID := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if credentials == "" {
		t.Skip("requires independently pinned owned local MySQL")
	}
	if serverUUID == "" {
		t.Fatal("independent UUID required")
	}
	x := &aPublisherVerifierFixture{}
	var wk a.ControllerVerifierWorkload
	var expectedContext string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		wr.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/controller-jwt/login":
			var login map[string]string
			if !fixture.ControlEvidence || json.NewDecoder(r.Body).Decode(&login) != nil || login["role"] != "controller-unwrap-role" || login["jwt"] != "local-controller-projected-jwt-only" {
				wr.WriteHeader(403)
				return
			}
			json.NewEncoder(wr).Encode(map[string]any{"auth": map[string]any{"client_token": "local-controller-unwrap-token-only", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"controller-unwrap-policy"}, "metadata": map[string]string{"role": login["role"], "namespace": "controller", "pod_uid": "controller-pod-uid", "service_account_uid": "controller-sa"}}})
		case "/v1/auth/capture-jwt/login":
			if !fixture.ControlEvidence {
				wr.WriteHeader(403)
				return
			}
			var login map[string]string
			if json.NewDecoder(r.Body).Decode(&login) != nil || login["role"] != "capture-generate-role" || login["jwt"] != "local-capture-projected-jwt-only" {
				wr.WriteHeader(403)
				return
			}
			json.NewEncoder(wr).Encode(map[string]any{"auth": map[string]any{"client_token": "local-control-generate-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"capture-generate-policy"}, "metadata": map[string]string{"role": login["role"], "namespace": "backup", "pod_uid": "capture-pod-uid", "service_account_uid": "capture-sa"}}})
		case "/v1/transit/datakey/plaintext/original-key":
			if !fixture.ControlEvidence || x.history == nil || x.controlGenerateRequest == nil {
				wr.WriteHeader(403)
				return
			}
			var references int
			var request map[string]string
			expected, _ := k.TransitContext(*x.controlGenerateRequest)
			if x.history.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM system_backup_v2_kek_references WHERE reference_state='unknown'").Scan(&references) != nil || references < 1 || r.Header.Get("X-Vault-Token") != "local-control-generate-token" || json.NewDecoder(r.Body).Decode(&request) != nil || request["bits"] != "256" || request["key_version"] != "1" || request["context"] != expected {
				wr.WriteHeader(403)
				return
			}
			x.generates.Add(1)
			x.controlContexts.Store(request["context"], true)
			json.NewEncoder(wr).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
		case "/v1/auth/publisher-jwt/login":
			x.logins.Add(1)
			var request map[string]string
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["role"] != "publisher-unwrap" || request["jwt"] != "local-publisher-projected-jwt-only" {
				wr.WriteHeader(403)
				return
			}
			if x.onLogin != nil {
				x.onLogin()
			}
			x.credentialIssuedAt.Store(time.Now().UnixNano())
			json.NewEncoder(wr).Encode(map[string]any{"auth": map[string]any{"client_token": "local-publisher-batch-token-only", "token_type": "batch", "renewable": false, "lease_duration": 1, "policies": []string{"publisher-unwrap-policy"}, "metadata": map[string]string{"role": "publisher-unwrap", "namespace": wk.Namespace, "pod_uid": wk.PodUID, "service_account_uid": wk.ServiceAccountUID}}})
		case "/v1/transit/decrypt/original-key":
			x.decrypts.Add(1)
			var request map[string]string
			if fixture.ControlEvidence && r.Header.Get("X-Vault-Token") == "local-controller-unwrap-token-only" {
				if x.controlGenerateRequest == nil {
					wr.WriteHeader(403)
					return
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || len(request) != 2 || request["ciphertext"] != "vault:v1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)) {
					wr.WriteHeader(403)
					return
				}
				if _, exists := x.controlContexts.Load(request["context"]); !exists {
					wr.WriteHeader(403)
					return
				}
				json.NewEncoder(wr).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}})
				return
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["context"] != expectedContext || request["ciphertext"] != "vault:v1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)) || r.Header.Get("X-Vault-Token") != "local-publisher-batch-token-only" {
				wr.WriteHeader(403)
				return
			}
			if x.onDecrypt != nil {
				x.onDecrypt()
			}
			json.NewEncoder(wr).Encode(map[string]any{"data": map[string]string{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}})
		default:
			wr.WriteHeader(403)
		}
	}))
	t.Cleanup(provider.Close)
	x.history = newPublisherHistoryFixture(t, func(options *consumerFixtureOptions) {
		if fixture.WorkerIssuer != nil {
			options.WorkerIssuerSHA256 = hash(fixture.WorkerIssuer.Certificate.Raw)
		}
		options.WrapControlConnector = fixture.WrapControlConnector
		options.ConfigSnapshot = fixture.ConfigSnapshot
		options.OwnedCredentialsFile, options.OwnedServerUUID = credentials, serverUUID
		options.JobDeadlineSeconds = 1
		if fixture.FullService {
			options.DeploymentCore = func(g c.ExecutionGrant, issuer ed25519.PublicKey, dir string) DeploymentConfig {
				cfg := testDeploymentConfiguration(t)
				if fixture.ControlEvidence {
					cfg = runtimeDeploymentFixture(t)
					cfg.CaptureScope = "six-part"
					cfg.TrustDomain = "fixture.invalid"
					cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(dir, "formal-materials.json")}
					cfg.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(dir, "capture-materials.json")}
					cfg.SourceServerUUID, cfg.SourceDatabase = g.ServerUUID, g.Database
				}
				cfg.InstallationID = g.InstallationID
				cfg.ControllerOwner = g.ControllerOwner
				cfg.ApplicationScope = "original-app"
				cfg.Namespace = "ns"
				if fixture.ControlEvidence {
					cfg.Namespace = "backup"
				}
				if fixture.ControlURL != "" {
					cfg.ControlURL = fixture.ControlURL
				}
				if cfg.RuntimeSources != nil {
					cfg.RuntimeSources.Namespaces = []string{cfg.Namespace}
				}
				cfg.NamespaceUID = "ns-original"
				cfg.Security.ServiceAccountName = "capture"
				cfg.Security.ServiceAccountUID = "capture-sa"
				cfg.KeyDirectory = dir
				if fixture.WorkerIssuer != nil {
					cfg.IssuerSHA256 = hash(fixture.WorkerIssuer.Certificate.Raw)
					cfg.IssuerCertificate, cfg.IssuerKey = filepath.Join(dir, "worker-ca.crt"), filepath.Join(dir, "worker-ca.key")
					key, err := x509.MarshalPKCS8PrivateKey(fixture.WorkerIssuer.Signer)
					if err != nil || os.WriteFile(cfg.IssuerCertificate, fixture.WorkerIssuer.ServerRoots, 0600) != nil || os.WriteFile(cfg.IssuerKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600) != nil {
						t.Fatal("owned independently pinned worker issuer")
					}
					clear(key)
				}
				cfg.ProfileFile = filepath.Join(dir, "profile.json")
				cfg.CapacityFile = filepath.Join(dir, "capacity.json")
				cfg.ForwardGrant = GrantReference{Path: filepath.Join(dir, "grant.json"), PublicKey: base64.StdEncoding.EncodeToString(issuer)}
				cfg.RecoveryGrant = GrantReference{Path: filepath.Join(dir, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(issuer)}
				cfg.PublisherVerifier = &PublisherVerifierReference{Protocol: PublisherVerifierMaterialsVersion, Path: filepath.Join(dir, "publisher-materials.json")}
				if fixture.PublicationTarget != nil {
					fixture.PublicationTarget.InstallationID = g.InstallationID
					fixture.PublicationTarget.Root = g.InstallationID + "/"
					cfg.PublicationTarget = &PublicationTargetReference{Protocol: publicationTargetVersion, Path: filepath.Join(dir, "publication-target.json")}
					raw, _ := json.Marshal(fixture.PublicationTarget)
					if os.WriteFile(cfg.PublicationTarget.Path, raw, 0600) != nil {
						t.Fatal("owner target material")
					}
					t.Setenv("SYSTEM_BACKUP_PUBLICATION_TARGET_FILE", cfg.PublicationTarget.Path)
					t.Setenv("SYSTEM_BACKUP_PUBLICATION_TARGET_SHA256", hash(raw))
				}
				for i := range cfg.Writers {
					cfg.Writers[i].Namespace = cfg.Namespace
				}
				cfg.Security.Volumes = []kube.MountIdentity{{Kind: "PersistentVolumeClaim", Name: "source", UID: "source-uid", PVName: "source-pv", PVUID: "source-pv-uid"}, {Kind: "PersistentVolumeClaim", Name: "staging", UID: "staging-uid", PVName: "staging-pv", PVUID: "staging-pv-uid"}}
				return cfg
			}
		}
		options.PrepareSource = func(root *os.Root, inv *worker.Invocation) {
			inv.ProviderKey.Endpoint = provider.URL
			if fixture.SourceBytes > 0 {
				data := make([]byte, fixture.SourceBytes)
				defer clear(data)
				if _, err := rand.Read(data); err != nil {
					t.Fatal(err)
				}
				if root.WriteFile("bounded-stream-payload.bin", data, 0600) != nil {
					t.Fatal("bounded stream fixture")
				}
			}
		}
		options.Configure = func(inv *worker.Invocation, _db, _admin *sql.DB, _ d.Authority) {
			x.captureDeadline = time.Now().UTC().Add(3 * time.Second)
			inv.Request.Deadline = x.captureDeadline
		}
	})
	h := x.history
	ctx := context.Background()
	g := h.cfg.Deployment
	actor := h.cfg.Workload
	// Extend only the focused A fixture role, on this UUID/marker-owned schema.
	for _, migration := range []string{"127_backup_v2_kek_registry.sql", "128_backup_installation_kek_authority.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", migration))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range strings.Split(string(raw), ";") {
			if strings.TrimSpace(stmt) != "" {
				if _, err = h.admin.Exec(stmt); err != nil {
					t.Fatal("owned registry DDL", err)
				}
			}
		}
	}
	user := strings.Split(g.DatabaseAccount, "@")[0]
	grants, err := c.FormalCaptureGrantSQL(g.Database, user, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"system_backup_v2_kek_fences": true, "system_backup_v2_kek_bindings": true, "system_backup_v2_kek_coverage": true, "system_backup_v2_kek_references": true, "system_backup_installation_kek_authority": true}
	for _, grant := range grants {
		for table := range required {
			if strings.Contains(grant, "`.`"+table+"`") {
				if _, err = h.admin.Exec(grant); err != nil {
					t.Fatal("official focused verifier grant", err)
				}
				delete(required, table)
			}
		}
	}
	if len(required) != 0 {
		t.Fatal("official verifier role lacks required registry reads")
	}
	reads := a.VerifierKubernetesReads{Version: a.VerifierKubernetesReadsVersion, Namespace: actor.Namespace, NamespaceUID: actor.NamespaceUID, PodName: actor.PodName, PodUID: actor.PodUID, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, OwnerKind: "Deployment", OwnerName: "publisher-deployment", OwnerUID: "publisher-deployment-uid", ReplicaSetName: "publisher-rs", ReplicaSetUID: "publisher-rs-uid"}
	wk = a.ControllerVerifierWorkload{Namespace: actor.Namespace, PodName: actor.PodName, PodUID: actor.PodUID, ServiceAccountName: actor.ServiceAccountName, ServiceAccountUID: actor.ServiceAccountUID, OwnerKind: reads.OwnerKind, OwnerUID: reads.OwnerUID, ControllerOwner: actor.PublisherOwner, GrantSHA256: actor.GrantSHA256, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256}
	controller := true
	pod, err := h.owner.Client.CoreV1().Pods(actor.Namespace).Get(ctx, actor.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: reads.ReplicaSetName, UID: "publisher-rs-uid", Controller: &controller}}
	if _, err = h.owner.Client.CoreV1().Pods(actor.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.owner.Client.AppsV1().ReplicaSets(actor.Namespace).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: reads.ReplicaSetName, Namespace: actor.Namespace, UID: "publisher-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: reads.OwnerName, UID: "publisher-deployment-uid", Controller: &controller}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.owner.Client.AppsV1().Deployments(actor.Namespace).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: reads.OwnerName, Namespace: actor.Namespace, UID: "publisher-deployment-uid"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	invocation := h.invocation
	if h.access != nil {
		record, err := h.owner.Gate.Records.LoadPublisherCapture(ctx, h.access)
		if err != nil {
			t.Fatal(err)
		}
		invocation = record.Invocation
	}
	request := invocation.ProviderKey.Request
	expectedContext, err = k.TransitContext(request)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
	caHash := hash(ca)
	ref := func(purpose, capability, identity string) reg.TypedReference {
		raw, _ := json.Marshal(map[string]string{"ref_kind": "external_kms_key", "purpose": purpose, "identity_hash": identity, "identity_version": "operation-r1", "description_redacted": "owned publisher permission", "kms_capability": capability, "provider_identity_hash": strings.Repeat("e", 64), "scope_hash": strings.Repeat("f", 64)})
		return reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}
	}
	binding := reg.Binding{InstallationID: g.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: request.Key.IdentityHash, Version: request.Key.RegistryVersion}, Key: request.Key, Provider: reg.ProviderBinding{Endpoint: provider.URL, KeyName: "original-key", ProviderIdentityHash: strings.Repeat("e", 64), ScopeHash: strings.Repeat("f", 64), CAPEMSHA256: caHash, CASource: reg.SourceRecord{SourceID: "original-ca", RecordID: "ca", RecordVersion: "v1", ContentSHA256: caHash}}, GenerateRef: ref("data_key_generation", "generate_data_key", strings.Repeat("1", 64)), UnwrapRef: ref("kek_unwrap", "unwrap_data_key", strings.Repeat("2", 64))}
	installationIssuer, installationKey, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() { clear(installationKey) })
	bindingRaw, _ := json.Marshal(binding)
	now := time.Now().UTC()
	x.original = a.OriginalRecord{Binding: binding, Source: reg.SourceRecord{SourceID: "original-installation-owner", RecordID: "original-kek", RecordVersion: "v1", ContentSHA256: hash(bindingRaw)}, Revision: "owner-r1", NotBefore: now.Add(-time.Minute), Until: now.Add(2 * time.Minute)}
	writer, err := a.NewInstallationAuthorityWriter(h.admin, binding.InstallationID, reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, installationIssuer)
	if err != nil {
		t.Fatal(err)
	}
	x.putOriginal = func(original a.OriginalRecord, version uint64) {
		t.Helper()
		raw, _ := json.Marshal(original)
		if _, err := writer.Put(ctx, raw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), raw...)), version); err != nil {
			t.Fatal("original installation mapping write", err)
		}
	}
	x.putOriginal(x.original, 0)
	semantic := binding
	for _, ref := range []*reg.TypedReference{&semantic.GenerateRef, &semantic.UnwrapRef} {
		var value map[string]json.RawMessage
		json.Unmarshal(ref.RawJSON, &value)
		delete(value, "description_redacted")
		ref.RawJSON, _ = json.Marshal(value)
		ref.SHA256 = ""
	}
	semanticRaw, _ := json.Marshal(semantic)
	fingerprint, _ := reg.BindingFingerprint(binding)
	if _, err = h.admin.Exec(`INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES(?,?,?,?,?,?)`, g.InstallationID, binding.Key.IdentityHash, binding.Key.RegistryVersion, fingerprint, hash(semanticRaw), bindingRaw); err != nil {
		t.Fatal(err)
	}
	capRecord := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: k.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "publisher-jwt", Role: "publisher-unwrap", Policy: "publisher-unwrap-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: binding.UnwrapRef, ControllerVerifier: &wk}}, Source: reg.SourceRecord{SourceID: "original-provider-observer", RecordID: "sev_publisher_unwrap", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	if fixture.CapabilityWindow > 0 {
		capRecord.Until = now.Add(fixture.CapabilityWindow)
	}
	facts, _ := json.Marshal(capRecord.Facts)
	capRecord.Source.ContentSHA256 = hash(facts)
	capIssuer, capKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(capKey)
	capRaw, _ := json.Marshal(capRecord)
	capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
	if _, err = h.admin.Exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES(?,'system',?,'capability_snapshot','inline',?,?,?,'application/json','none','internal','healthy',?)`, capRecord.Source.RecordID, g.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capRecord.Until); err != nil {
		t.Fatal(err)
	}
	capPin := a.ProviderCapabilityPin{Source: capRecord.Source, Issuer: capIssuer}
	unused := capPin
	unused.Source.RecordID = "sev_unused_generate"
	capabilities, err := a.NewSQLProviderCapabilityPreparation(h.db, reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, g.InstallationID, unused, capPin)
	if err != nil {
		t.Fatal(err)
	}
	jwt := filepath.Join(t.TempDir(), "publisher.jwt")
	if os.WriteFile(jwt, []byte("local-publisher-projected-jwt-only"), 0600) != nil {
		t.Fatal("JWT fixture")
	}
	x.cfg = a.PublisherVerifierConfig{Capabilities: capabilities, Binding: binding, CAPEM: ca, JWTFile: jwt, InstallationIssuer: installationIssuer, Workload: wk, KubernetesReads: reads, Kubernetes: h.owner.Client, Authority: h.cfg, Records: h.owner.Gate.Records}
	caFile := filepath.Join(t.TempDir(), "publisher-ca.crt")
	if os.WriteFile(caFile, ca, 0600) != nil {
		t.Fatal("CA fixture")
	}
	x.materials = PublisherVerifierMaterials{Version: PublisherVerifierMaterialsVersion, Database: reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, Binding: binding, GenerateCapability: unused, UnwrapCapability: capPin, InstallationIssuer: installationIssuer, CAFile: caFile, JWTFile: jwt, Workload: wk, KubernetesReads: reads, Grant: h.cfg.GrantMount}
	x.factory, err = a.NewPublisherVerifierFactory(x.cfg)
	if err != nil {
		t.Fatal("concrete publisher factory", err)
	}
	stage, err := h.owner.Staging.OpenRoot(h.original.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	envelope, err := staging.OpenFile(ctx, stage, h.candidate.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer envelope.Close()
	x.envelope, err = io.ReadAll(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestAPublisherVerifierOriginalHistorySQLTLSAndReceipt(t *testing.T) {
	x := newAPublisherVerifierFixture(t)
	h := x.history
	ctx := context.Background()
	if delay := time.Until(x.captureDeadline) + time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	verifier, err := x.factory.ForPart(ctx, h.scope)
	if err != nil {
		t.Fatal("current publisher could not read expired worker/capture invocation", err)
	}
	defer verifier.Close()
	if !time.Now().After(x.captureDeadline) || !verifier.ValidUntil().After(x.captureDeadline) {
		t.Fatal("positive did not outlive original invocation window")
	}
	calls := 0
	use := func(key []byte) error {
		calls++
		if !bytes.Equal(key, bytes.Repeat([]byte{9}, 32)) {
			return fmt.Errorf("wrong original DEK")
		}
		return verifier.Recheck(ctx)
	}
	if err = verifier.WithDEK(ctx, x.envelope, use); err != nil || calls != 1 || x.logins.Load() != 1 || x.decrypts.Load() != 1 {
		t.Fatal("original envelope SQL/TLS WithDEK", err, calls, x.logins.Load(), x.decrypts.Load())
	}
	// Public output copies and manufactured DTOs never manufacture a receipt.
	record, err := h.owner.Gate.Records.LoadPublisherCapture(ctx, h.access)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"invocation", "request", "candidate", "config-raw", "plan-raw", "checkpoint-raw", "until", "no-receipt"} {
		t.Run(fault, func(t *testing.T) {
			copy := record
			if record.Invocation.ProviderKey != nil {
				key := *record.Invocation.ProviderKey
				copy.Invocation.ProviderKey = &key
			}
			switch fault {
			case "invocation":
				copy.Invocation = record.Invocation
				copy.Invocation.Request.ArtifactName = "other.enc"
			case "request":
				copy.Invocation.ProviderKey.Request.Context.Part = "other"
			case "candidate":
				copy.CandidateJSON = append(append([]byte{}, record.CandidateJSON...), byte(' '))
			case "config-raw":
				copy.Input.ConfigSnapshot = append(append([]byte{}, record.Input.ConfigSnapshot...), byte(' '))
			case "plan-raw":
				copy.Plan.CanonicalJSON = append(append([]byte{}, record.Plan.CanonicalJSON...), byte(' '))
			case "checkpoint-raw":
				copy.PartResult.Checkpoint = append(append([]byte{}, record.PartResult.Checkpoint...), byte(' '))
			case "until":
				copy.ValidUntil = copy.ValidUntil.Add(time.Second)
			case "no-receipt":
				copy = c.PublisherCaptureRecord{Input: record.Input, Plan: record.Plan, Job: record.Job, Invocation: record.Invocation, CandidateJSON: record.CandidateJSON, CandidateSHA256: record.CandidateSHA256, RequestSHA256: record.RequestSHA256, CaptureResultSHA256: record.CaptureResultSHA256, KeyUse: record.KeyUse, SealScope: record.SealScope, PartResult: record.PartResult, ValidUntil: record.ValidUntil}
			}
			tx, err := h.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if copy.RecheckTx(ctx, tx, h.access) == nil {
				t.Fatal("changed/manufactured history DTO passed receipt")
			}
		})
	}
	bound, err := verifier.ForEnvelope(ctx, x.envelope)
	if err != nil {
		t.Fatal(err)
	}
	request := verifier.ExpectedRequest()
	wrong := w.WrappedKey{Request: request, Algorithm: "provider-native", Ciphertext: []byte("vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 60)))}
	before := x.logins.Load() + x.decrypts.Load()
	if bound.Unwrap(ctx, request, wrong, use) == nil || x.logins.Load()+x.decrypts.Load() != before || calls != 1 {
		t.Fatal("same Request substituted wrapped ciphertext reached provider")
	}
	if verifier.WithDEK(ctx, append(append([]byte{}, x.envelope...), byte(' ')), use) == nil || x.logins.Load()+x.decrypts.Load() != before {
		t.Fatal("replaced original envelope reached provider")
	}
	for _, fault := range []string{"key-use", "candidate", "journal", "part"} {
		t.Run(fault, func(t *testing.T) {
			var column string
			switch fault {
			case "key-use":
				column = "key_use_json"
			case "candidate":
				column = "candidate_cipher"
			case "journal":
				column = "request_json"
			case "part":
				bad := h.scope
				bad.Part = "absent-part"
				if _, err := x.factory.ForPart(ctx, bad); err == nil {
					t.Fatal("unknown part admitted")
				}
				return
			}
			var saved []byte
			if h.admin.QueryRow("SELECT "+column+" FROM system_backup_v2_runtime_resources WHERE observed_uid=?", h.job.UID).Scan(&saved) != nil {
				t.Fatal("owned original journal")
			}
			changed := append(append([]byte{}, saved...), byte(' '))
			if fault == "key-use" {
				var use map[string]any
				if json.Unmarshal(saved, &use) != nil {
					t.Fatal("original key-use JSON")
				}
				use["nonce"] = strings.Repeat("d", 32)
				changed, _ = json.Marshal(use)
			}
			if fault == "journal" {
				var request map[string]any
				if json.Unmarshal(saved, &request) != nil {
					t.Fatal("original Job request JSON")
				}
				metadata, ok := request["metadata"].(map[string]any)
				if !ok {
					t.Fatal("original Job metadata")
				}
				metadata["name"] = "changed-original-job"
				changed, _ = json.Marshal(request)
			}
			if _, err := h.admin.Exec("UPDATE system_backup_v2_runtime_resources SET "+column+"=? WHERE observed_uid=?", changed, h.job.UID); err != nil {
				t.Fatal(err)
			}
			var observed []byte
			if h.admin.QueryRow("SELECT "+column+" FROM system_backup_v2_runtime_resources WHERE observed_uid=?", h.job.UID).Scan(&observed) != nil || !bytes.Equal(observed, changed) || bytes.Equal(observed, saved) {
				t.Fatal("negative original journal mutation did not commit exact changed bytes")
			}
			defer h.admin.Exec("UPDATE system_backup_v2_runtime_resources SET "+column+"=? WHERE observed_uid=?", saved, h.job.UID)
			before := x.logins.Load() + x.decrypts.Load()
			if verifier.WithDEK(ctx, x.envelope, use) == nil || calls != 1 || x.logins.Load()+x.decrypts.Load() != before {
				t.Fatal("changed original history reached provider/DEK")
			}
		})
	}
	if x.logins.Load() != 1 || x.decrypts.Load() != 1 || calls != 1 {
		t.Fatal("negative changed provider or DEK counts")
	}
	h.service.ForwardEnabled = false
	if verifier.WithDEK(ctx, x.envelope, use) == nil || x.logins.Load() != 1 || x.decrypts.Load() != 1 || calls != 1 {
		t.Fatal("disabled actual deployment wrapper reached provider/DEK")
	}
	h.service.ForwardEnabled = true
}

func TestAPublisherVerifierChangesDuringProviderBoundaries(t *testing.T) {
	for _, mode := range []string{"login-renew", "login-original-unwrap-revoke", "decrypt-candidate-change"} {
		t.Run(mode, func(t *testing.T) {
			x := newAPublisherVerifierFixture(t)
			h := x.history
			ctx := context.Background()
			verifier, err := x.factory.ForPart(ctx, h.scope)
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Close()
			until := verifier.ValidUntil()
			var fresh c.ClaimToken
			switch mode {
			case "login-renew":
				x.onLogin = func() {
					var err error
					fresh, err = c.RenewClaimInInstallation(ctx, h.db, h.original.InstallationID, h.token, c.LeasePolicy{TTL: 45 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
					if err != nil {
						t.Error(err)
					}
				}
			case "login-original-unwrap-revoke":
				x.onLogin = func() {
					original := x.original
					original.Revision = "owner-r2"
					original.UnwrapRevoked = true
					x.putOriginal(original, 1)
				}
			case "decrypt-candidate-change":
				x.onDecrypt = func() {
					if _, err := h.admin.Exec("UPDATE system_backup_v2_runtime_resources SET candidate_cipher=CONCAT(candidate_cipher,'x') WHERE observed_uid=?", h.job.UID); err != nil {
						t.Error(err)
					}
				}
			}
			called := 0
			if verifier.WithDEK(ctx, x.envelope, func([]byte) error { called++; return nil }) == nil || called != 0 {
				t.Fatal("provider boundary drift reached DEK")
			}
			if x.logins.Load() != 1 || mode != "decrypt-candidate-change" && x.decrypts.Load() != 0 || mode == "decrypt-candidate-change" && x.decrypts.Load() != 1 {
				t.Fatal("wrong provider boundary counts")
			}
			if !verifier.ValidUntil().Equal(until) {
				t.Fatal("original verification window extended")
			}
			if mode == "login-renew" {
				x.onLogin = nil
				if verifier.Recheck(ctx) == nil {
					t.Fatal("old verifier adopted new claim")
				}
				scope := h.scope
				scope.Claim.RowVersion = fresh.RowVersion
				next, err := x.factory.ForPart(ctx, scope)
				if err != nil {
					t.Fatal("actual fresh token", err)
				}
				defer next.Close()
				if next.WithDEK(ctx, x.envelope, func([]byte) error { return nil }) != nil {
					t.Fatal("fresh exact claim failed original envelope")
				}
			}
		})
	}
}
