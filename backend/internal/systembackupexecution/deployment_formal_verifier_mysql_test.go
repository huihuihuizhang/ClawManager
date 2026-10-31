package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Actual D deployment factory -> original SQL candidate -> A original signed
// authority/capability/grant -> TLS login+unwrap -> private seal -> SQL result.
// The source bytes/Kubernetes metadata remain local fixtures, never production.
func TestDeploymentFormalVerifierActualCandidateConsumerMySQLAndTLS(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	ctx := context.Background()
	var workload a.ControllerVerifierWorkload
	var expectedContext string
	logins, decrypts := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/controller-jwt/login":
			logins++
			var req map[string]string
			if json.NewDecoder(r.Body).Decode(&req) != nil || req["role"] != "controller-unwrap-role" || req["jwt"] != "local-controller-projected-jwt-only" {
				t.Error("wrong original controller login")
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "local-controller-unwrap-token-only", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"controller-unwrap-policy"}, "metadata": map[string]string{"role": "controller-unwrap-role", "namespace": workload.Namespace, "pod_uid": workload.PodUID, "service_account_uid": workload.ServiceAccountUID}}})
		case "/v1/transit/decrypt/original-key":
			decrypts++
			if r.Header.Get("X-Vault-Token") != "local-controller-unwrap-token-only" {
				t.Error("wrong independent provider credential")
				w.WriteHeader(403)
				return
			}
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["context"] != expectedContext || body["ciphertext"] != "vault:v1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)) {
				t.Error("provider request lost original full context/ciphertext")
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}})
		default:
			t.Error("factory attempted another provider operation")
			w.WriteHeader(403)
		}
	}))
	defer server.Close()
	owner, service, admin, db, authority, job, _, _, refresh := newConsumerMySQLFixture(t, func(i *worker.Invocation) { i.ProviderKey.Endpoint = server.URL })
	for _, name := range []string{"127_backup_v2_kek_registry.sql", "128_backup_installation_kek_authority.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range strings.Split(string(raw), ";") {
			if strings.TrimSpace(sql) != "" {
				if _, err = admin.Exec(sql); err != nil {
					t.Fatal("original KEK DDL failed", err)
				}
			}
		}
	}
	var account, database, uuid string
	var now time.Time
	if db.QueryRow("SELECT CURRENT_USER(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&account, &database, &uuid, &now) != nil {
		t.Fatal("local identity unavailable")
	}
	for table, verbs := range map[string]string{"system_backup_installation_kek_authority": "SELECT", "system_backup_v2_kek_fences": "SELECT,INSERT,UPDATE", "system_backup_v2_kek_bindings": "SELECT", "system_backup_v2_kek_coverage": "SELECT", "system_backup_v2_kek_references": "SELECT"} {
		if _, err := admin.Exec("GRANT " + verbs + " ON `" + database + "`.`" + table + "` TO '" + strings.Split(account, "@")[0] + "'@'127.0.0.1'"); err != nil {
			t.Fatal("local controller table grant", err)
		}
	}
	_, _, desc, err := owner.input(ctx, authority, false)
	if err != nil {
		t.Fatal(err)
	}
	var invocation worker.Invocation
	if len(desc.Parts) != 1 || json.Unmarshal(desc.Parts[0].InvocationJSON, &invocation) != nil {
		t.Fatal("original invocation missing")
	}
	expectedContext, err = k.TransitContext(invocation.ProviderKey.Request)
	if err != nil {
		t.Fatal(err)
	}
	var originalRequestHash string
	if db.QueryRow("SELECT request_sha256 FROM system_backup_v2_runtime_resources WHERE observed_uid=?", job.UID).Scan(&originalRequestHash) != nil {
		t.Fatal("original request hash missing")
	}
	if originalRequestHash != desc.Parts[0].Intent.SpecSHA256 {
		t.Log("real kube.Intent request SHA differs from typed plan SpecSHA256; verifier must authenticate both encodings, not equate them")
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ref := func(purpose, capability, identity string) reg.TypedReference {
		raw, _ := json.Marshal(map[string]string{"ref_kind": "external_kms_key", "purpose": purpose, "identity_hash": identity, "identity_version": "operation-r1", "description_redacted": "local original permission", "kms_capability": capability, "provider_identity_hash": strings.Repeat("e", 64), "scope_hash": strings.Repeat("f", 64)})
		return reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}
	}
	key := invocation.ProviderKey.Request.Key
	binding := reg.Binding{InstallationID: authority.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: key.IdentityHash, Version: key.RegistryVersion}, Key: key, Provider: reg.ProviderBinding{Endpoint: server.URL, KeyName: "original-key", ProviderIdentityHash: strings.Repeat("e", 64), ScopeHash: strings.Repeat("f", 64), CAPEMSHA256: hash(ca), CASource: reg.SourceRecord{SourceID: "original-ca", RecordID: "ca", RecordVersion: "v1", ContentSHA256: hash(ca)}}, GenerateRef: ref("data_key_generation", "generate_data_key", strings.Repeat("1", 64)), UnwrapRef: ref("kek_unwrap", "unwrap_data_key", strings.Repeat("2", 64))}
	installationIssuer, installationKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(installationKey)
	encoded, _ := json.Marshal(binding)
	original := a.OriginalRecord{Binding: binding, Source: reg.SourceRecord{SourceID: "original-installation-owner", RecordID: "original-key", RecordVersion: "v1", ContentSHA256: hash(encoded)}, Revision: "owner-r1", NotBefore: now.Add(-time.Minute), Until: authority.DeadlineAt}
	writer, err := a.NewInstallationAuthorityWriter(admin, authority.InstallationID, reg.DatabaseIdentity{ServerUUID: uuid, Database: database}, installationIssuer)
	if err != nil {
		t.Fatal(err)
	}
	originalRaw, _ := json.Marshal(original)
	if _, err = writer.Put(ctx, originalRaw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), originalRaw...)), 0); err != nil {
		t.Fatal(err)
	}
	workload = a.ControllerVerifierWorkload{Namespace: "controller", PodName: "controller-pod", PodUID: "verifier-pod-uid", ServiceAccountName: "controller-sa", ServiceAccountUID: "verifier-sa-uid", OwnerKind: "Deployment", OwnerUID: "controller-deployment-uid", ControllerOwner: authority.ClaimOwner, ConfigVersion: authority.ConfigVersion, ConfigSHA256: authority.ConfigSHA256}
	grant := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: authority.InstallationID, Database: reg.DatabaseIdentity{ServerUUID: uuid, Database: database}, DatabaseAccount: account, Workload: workload, CaptureGrantSHA256: service.Forward.GrantSHA256(), NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	issuer, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	grantRaw, _ := json.Marshal(grant)
	grantEnvelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: grantRaw, Signature: ed25519.Sign(private, append([]byte(a.ControllerVerifierGrantDomain), grantRaw...))})
	workload.GrantSHA256 = hash(grantEnvelope)
	ctrl := true
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: workload.PodName, Namespace: workload.Namespace, UID: types.UID(workload.PodUID), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller-rs", UID: "controller-rs-uid", Controller: &ctrl}}}, Spec: corev1.PodSpec{ServiceAccountName: workload.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: workload.ServiceAccountName, Namespace: workload.Namespace, UID: types.UID(workload.ServiceAccountUID)}}, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-rs", Namespace: workload.Namespace, UID: "controller-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "controller-deployment", UID: types.UID(workload.OwnerUID), Controller: &ctrl}}}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller-deployment", Namespace: workload.Namespace, UID: types.UID(workload.OwnerUID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: owner.Namespace, UID: types.UID(owner.NamespaceUID)}})
	owner.Client = client
	capability := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: "backup_dek_unwrap", Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "controller-jwt", Role: "controller-unwrap-role", Policy: "controller-unwrap-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: binding.UnwrapRef, ControllerVerifier: &workload}}, Source: reg.SourceRecord{SourceID: "original-provider-observer", RecordID: "sev_controller_unwrap", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	facts, _ := json.Marshal(capability.Facts)
	capability.Source.ContentSHA256 = hash(facts)
	capIssuer, capKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(capKey)
	capRaw, _ := json.Marshal(capability)
	capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
	if _, err = admin.Exec("INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)", capability.Source.RecordID, authority.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capability.Until); err != nil {
		t.Fatal(err)
	}
	semantic := binding
	for _, r := range []*reg.TypedReference{&semantic.GenerateRef, &semantic.UnwrapRef} {
		var value map[string]json.RawMessage
		json.Unmarshal(r.RawJSON, &value)
		delete(value, "description_redacted")
		r.RawJSON, _ = json.Marshal(value)
		r.SHA256 = ""
	}
	semanticRaw, _ := json.Marshal(semantic)
	fingerprint, _ := reg.BindingFingerprint(binding)
	if _, err = admin.Exec("INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES(?,?,?,?,?,?)", authority.InstallationID, key.IdentityHash, key.RegistryVersion, fingerprint, hash(semanticRaw), encoded); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile, jwtFile, grantFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "controller.jwt"), filepath.Join(dir, "verifier.json")
	for path, body := range map[string][]byte{caFile: ca, jwtFile: []byte("local-controller-projected-jwt-only"), grantFile: grantEnvelope} {
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("local mount failed")
		}
	}
	capPin := a.ProviderCapabilityPin{Source: capability.Source, Issuer: capIssuer}
	generatePin := capPin
	generatePin.Source.RecordID = "sev_unused_generate"
	materials := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: grant.Database, Binding: binding, GenerateCapability: generatePin, UnwrapCapability: capPin, InstallationIssuer: installationIssuer, CAFile: caFile, JWTFile: jwtFile, Workload: workload, Grant: a.ControllerVerifierGrantMount{File: grantFile, SHA256: workload.GrantSHA256, Issuer: issuer}}
	materialFile := filepath.Join(dir, "verifier-materials.json")
	materialRaw, _ := json.Marshal(materials)
	if os.WriteFile(materialFile, materialRaw, 0600) != nil {
		t.Fatal("independent startup materials failed")
	}
	service.Config.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: materialFile}
	service.Config.ControllerOwner = authority.ClaimOwner
	if err = service.loadFormalVerifier([]FormalVerifierInput{{File: materialFile, SHA256: hash(materialRaw)}}); err != nil {
		t.Fatal("independently pinned startup materials", err)
	}
	if err = service.attachFormalVerifier(owner); err != nil {
		t.Fatal("production verifier composition failed", err)
	}
	originalRecord, err := owner.ReadFormalCandidate(ctx, authority, job, false)
	if err != nil {
		t.Fatal(err)
	}
	scope := FormalCandidateReadScope{Authority: authority, Job: job, Invocation: invocation, Candidate: originalRecord.Candidate, CapturePod: originalRecord.Pod, CaptureGrantSHA256: originalRecord.ExecutionGrantSHA256}
	probe, err := owner.FormalKeys(ctx, scope)
	if err != nil {
		t.Fatal("production key factory construction", err)
	}
	if err = probe.Recheck(ctx, scope); err != nil {
		probe.Close()
		t.Fatal("production key factory original scope recheck", err)
	}
	probe.Close()
	bounded, err := openFormalCandidateKeys(ctx, owner.FormalKeys, scope)
	if err != nil {
		t.Fatal("D original factory scope admission", err)
	}
	bounded.Close()
	refresh()
	evidence, err := owner.Evidence(ctx, authority, job)
	if err != nil || evidence == nil || logins != 1 || decrypts != 1 {
		t.Fatal("production factory original Evidence consumer failed", err, logins, decrypts)
	}
	if _, err = owner.ReadResult(ctx, authority, job, *evidence); err != nil {
		t.Fatal("production original result readback failed", err)
	}
	again, err := owner.Evidence(ctx, authority, job)
	if err != nil || again == nil || *again != *evidence || logins != 1 || decrypts != 1 {
		t.Fatal("ACK replay repeated independent provider use", err, logins, decrypts)
	}
	changed, _ := cloneFormalReadScope(scope)
	changed.Candidate.Ciphertext.SHA256 = strings.Repeat("e", 64)
	if use, err := owner.FormalKeys(ctx, changed); err == nil {
		use.Close()
		t.Fatal("production factory accepted changed original candidate")
	}
	original.UnwrapRevoked = true
	original.Revision = "owner-r2"
	revoked, _ := json.Marshal(original)
	if _, err = writer.Put(ctx, revoked, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), revoked...)), 1); err != nil {
		t.Fatal("original owner revocation failed", err)
	}
	if use, err := owner.FormalKeys(ctx, scope); err == nil {
		use.Close()
		t.Fatal("production factory bypassed original owner Unwrap revocation")
	}
	if logins != 1 || decrypts != 1 {
		t.Fatal("rejected production scope reached provider", logins, decrypts)
	}
}
