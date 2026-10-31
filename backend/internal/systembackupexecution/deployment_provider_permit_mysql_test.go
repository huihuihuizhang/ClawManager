package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Actual original PublicJobOwner.Authorize, SQL key-use transaction, A issuer,
// authenticated mTLS control client, pinned TLS provider and worker candidate.
// Kubernetes/TokenReview metadata is a local fake API, never cluster evidence.
func TestDeploymentProviderPermitActualHandlerMySQLAndTLS(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, mode := range []string{"valid", "unknown-reserve-ack", "revoked-after-login"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			var db *sql.DB
			var invocation worker.Invocation
			var revoke func() error
			var initializeOriginal func() error
			var generates, logins atomic.Int32
			provider := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				out.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/auth/capture-jwt/login":
					logins.Add(1)
					var login map[string]string
					if json.NewDecoder(r.Body).Decode(&login) != nil || login["role"] != "capture-generate-role" || login["jwt"] != "local-capture-projected-jwt-only" {
						t.Error("wrong worker JWT login")
						out.WriteHeader(403)
						return
					}
					if mode == "revoked-after-login" {
						if err := revoke(); err != nil {
							t.Error(err)
							out.WriteHeader(403)
							return
						}
					}
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-issued-generate-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"capture-generate-policy"}, "metadata": map[string]string{"role": "capture-generate-role", "namespace": "backup", "pod_uid": "capture-pod-uid", "service_account_uid": "capture-sa"}}})
				case "/v1/transit/datakey/plaintext/original-key":
					generates.Add(1)
					var state string
					if db.QueryRowContext(r.Context(), `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "unknown" {
						t.Error("Generate preceded committed original unknown reference")
						out.WriteHeader(403)
						return
					}
					var body map[string]string
					expected, _ := k.TransitContext(invocation.ProviderKey.Request)
					if r.Header.Get("X-Vault-Token") != "local-issued-generate-token" || json.NewDecoder(r.Body).Decode(&body) != nil || body["context"] != expected || body["bits"] != "256" || body["key_version"] != "1" {
						t.Error("wrong Generate binding")
						out.WriteHeader(403)
						return
					}
					json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
				default:
					t.Error("unexpected provider operation")
					out.WriteHeader(403)
				}
			}))
			defer provider.Close()
			var config k.Config
			var materials FormalVerifierDeploymentConfig
			var minimum time.Time
			options := &consumerFixtureOptions{}
			options.Configure = func(i *worker.Invocation, controlDB, admin *sql.DB, authority d.Authority) {
				db = controlDB
				exec := func(q string, args ...any) {
					t.Helper()
					if _, err := admin.ExecContext(ctx, q, args...); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"127_backup_v2_kek_registry.sql", "128_backup_installation_kek_authority.sql"} {
					raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
					if err != nil {
						t.Fatal(err)
					}
					for _, statement := range strings.Split(string(raw), ";") {
						if strings.TrimSpace(statement) != "" {
							exec(statement)
						}
					}
				}
				participants, err := os.ReadFile(filepath.Join("..", "db", "migrations", "079_add_system_backup_control.sql"))
				if err != nil {
					t.Fatal(err)
				}
				participantDDL := "CREATE TABLE IF NOT EXISTS system_backup_participants" + strings.Split(strings.Split(string(participants), "CREATE TABLE IF NOT EXISTS system_backup_participants")[1], "CREATE TABLE IF NOT EXISTS system_backup_restore_evidence")[0]
				exec(strings.TrimSuffix(strings.TrimSpace(participantDDL), ";"))
				exec("DROP TABLE system_backup_gate")
				gateDDL := "CREATE TABLE IF NOT EXISTS system_backup_gate (" + strings.Split(strings.Split(string(participants), "CREATE TABLE IF NOT EXISTS system_backup_gate (")[1], "CREATE TABLE IF NOT EXISTS system_backup_mutation_leases")[0]
				exec(strings.TrimSuffix(strings.TrimSpace(gateDDL), ";"))
				var account, database, uuid string
				if db.QueryRow("SELECT CURRENT_USER(),DATABASE(),@@server_uuid").Scan(&account, &database, &uuid) != nil {
					t.Fatal("SQL identity unavailable")
				}
				for table, verbs := range map[string]string{"system_backup_installation_kek_authority": "SELECT", "system_backup_v2_kek_fences": "SELECT,INSERT,UPDATE", "system_backup_v2_kek_bindings": "SELECT", "system_backup_v2_kek_coverage": "SELECT", "system_backup_v2_kek_references": "SELECT,INSERT,UPDATE"} {
					exec("GRANT " + verbs + " ON `" + database + "`.`" + table + "` TO '" + strings.Split(account, "@")[0] + "'@'127.0.0.1'")
				}
				exec("GRANT SELECT ON `" + database + "`.`system_backup_participants` TO '" + strings.Split(account, "@")[0] + "'@'127.0.0.1'")
				i.ProviderKey.Endpoint = provider.URL
				ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
				ref := func(purpose, capability, identity string) reg.TypedReference {
					raw, _ := json.Marshal(map[string]string{"ref_kind": "external_kms_key", "purpose": purpose, "identity_hash": identity, "identity_version": "operation-r1", "description_redacted": "local original permission", "kms_capability": capability, "provider_identity_hash": strings.Repeat("e", 64), "scope_hash": strings.Repeat("f", 64)})
					return reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}
				}
				key := i.ProviderKey.Request.Key
				binding := reg.Binding{InstallationID: authority.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: key.IdentityHash, Version: key.RegistryVersion}, Key: key, Provider: reg.ProviderBinding{Endpoint: provider.URL, KeyName: "original-key", ProviderIdentityHash: strings.Repeat("e", 64), ScopeHash: strings.Repeat("f", 64), CAPEMSHA256: hash(ca), CASource: reg.SourceRecord{SourceID: "original-ca", RecordID: "ca", RecordVersion: "v1", ContentSHA256: hash(ca)}}, GenerateRef: ref("data_key_generation", "generate_data_key", strings.Repeat("1", 64)), UnwrapRef: ref("kek_unwrap", "unwrap_data_key", strings.Repeat("2", 64))}
				now := time.Now().UTC()
				installationPub, installationKey, _ := ed25519.GenerateKey(rand.Reader)
				t.Cleanup(func() { clear(installationKey) })
				rawBinding, _ := json.Marshal(binding)
				original := a.OriginalRecord{Binding: binding, Source: reg.SourceRecord{SourceID: "original-installation-owner", RecordID: "original-key", RecordVersion: "v1", ContentSHA256: hash(rawBinding)}, Revision: "owner-r1", NotBefore: now.Add(-time.Minute), Until: authority.DeadlineAt}
				databaseID := reg.DatabaseIdentity{ServerUUID: uuid, Database: database}
				writer, err := a.NewInstallationAuthorityWriter(admin, authority.InstallationID, databaseID, installationPub)
				if err != nil {
					t.Fatal(err)
				}
				put := func(record a.OriginalRecord, version uint64) error {
					raw, _ := json.Marshal(record)
					_, err := writer.Put(ctx, raw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), raw...)), version)
					return err
				}
				initializeOriginal = func() error { return put(original, 0) }
				revoke = func() error {
					changed := original
					changed.GenerateRevoked = true
					changed.Revision = "owner-r2"
					return put(changed, 1)
				}
				permission := a.ProviderCapabilityPermission{Path: "transit/datakey/plaintext/original-key", ProviderVersion: "1", AuthMount: "capture-jwt", Role: "capture-generate-role", Policy: "capture-generate-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: binding.GenerateRef}
				capRecord := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: k.Generate, Permission: permission}, Source: reg.SourceRecord{SourceID: "original-provider-permission-owner", RecordID: "sev_original_capture_generate", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: now.Add(2 * time.Minute)}
				facts, _ := json.Marshal(capRecord.Facts)
				capRecord.Source.ContentSHA256 = hash(facts)
				capPub, capKey, _ := ed25519.GenerateKey(rand.Reader)
				defer clear(capKey)
				capRaw, _ := json.Marshal(capRecord)
				capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
				exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)`, capRecord.Source.RecordID, authority.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capRecord.Until)
				workload := a.ControllerVerifierWorkload{Namespace: "controller", PodName: "controller-pod", PodUID: "controller-pod-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa", OwnerKind: "Deployment", OwnerUID: "controller-deployment-uid", ControllerOwner: authority.ClaimOwner, ConfigVersion: authority.ConfigVersion, ConfigSHA256: authority.ConfigSHA256}
				rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
				defer clear(rootKey)
				issuerPub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
				defer clear(issuerKey)
				dir := t.TempDir()
				jwtFile := filepath.Join(dir, "job.jwt")
				keyFile := filepath.Join(dir, "issuer.key")
				grantFile := filepath.Join(dir, "issuer.json")
				if os.WriteFile(jwtFile, []byte("local-capture-projected-jwt-only"), 0600) != nil || os.WriteFile(keyFile, issuerKey, 0600) != nil {
					t.Fatal("issuer materials unavailable")
				}
				minimum = now.Truncate(time.Second).Add(75*time.Second + 123456789*time.Nanosecond)
				grant := a.ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: binding, Database: databaseID, DatabaseAccount: account, Workload: workload, SigningPublicKey: issuerPub, GeneratePermission: permission, WorkerNamespace: "backup", WorkerServiceAccountName: "capture", WorkerServiceAccountUID: "capture-sa", WorkerJWTIdentityFile: jwtFile, NotBefore: now.Add(-time.Minute), Until: minimum}
				grantRaw, _ := json.Marshal(grant)
				grantEnvelope, _ := json.Marshal(a.SignedProviderPermitIssuerGrant{Record: grantRaw, Signature: ed25519.Sign(rootKey, append([]byte(a.ProviderPermitIssuerGrantDomain), grantRaw...))})
				if os.WriteFile(grantFile, grantEnvelope, 0600) != nil {
					t.Fatal("grant write failed")
				}
				workload.GrantSHA256 = hash(grantEnvelope)
				pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: issuerPub, IssuerGrantSHA256: workload.GrantSHA256}
				i.FormalCapture.PermitDelivery = &pin
				config = k.Config{Endpoint: provider.URL, InstallationID: authority.InstallationID, KeyName: "original-key", Key: key, CAPEM: ca, CASHA256: hash(ca), NotBefore: now.Add(-time.Minute), NotAfter: authority.DeadlineAt}
				materials = FormalVerifierDeploymentConfig{Database: databaseID, Binding: binding, InstallationIssuer: installationPub, GenerateCapability: a.ProviderCapabilityPin{Source: capRecord.Source, Issuer: capPub}, UnwrapCapability: a.ProviderCapabilityPin{Source: reg.SourceRecord{SourceID: "unused-unwrap", RecordID: "sev_unused_unwrap", RecordVersion: "v1", ContentSHA256: strings.Repeat("f", 64)}, Issuer: rootPub}, ProviderPermits: &ProviderPermitDeploymentConfig{Workload: workload, Grant: a.ProviderPermitIssuerGrantMount{File: grantFile, SHA256: workload.GrantSHA256, Issuer: rootPub}, SigningKeyFile: keyFile, DeliveryPin: pin}}
				options.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "original-formal", Inputs: []kube.FormalInputMount{{Volume: "formal-kms", Kind: "ConfigMap", Name: "original-kms", Directory: "/run/backup/materials/kms", Items: []corev1.KeyToPath{{Key: "ca", Path: "ca"}}}}}
				invocation = *i
			}
			owner, service, admin, controlDB, authority, job, candidate, _, refresh := newConsumerMySQLFixtureOptions(t, options)
			db = controlDB
			if _, err := admin.Exec(`UPDATE system_backup_gate SET hold_deadline=? WHERE scope='original-app'`, authority.DeadlineAt); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(`INSERT INTO system_backup_participants(scope,participant_id,generation,state,resume_result,checkpoint_hash) VALUES('original-app','original-platform-writer',?,'paused','none',?)`, authority.MaintenanceFencingToken, strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
			if err := initializeOriginal(); err != nil {
				t.Fatal("original installation owner", err)
			}
			semantic := materials.Binding
			for _, ref := range []*reg.TypedReference{&semantic.GenerateRef, &semantic.UnwrapRef} {
				var value map[string]json.RawMessage
				json.Unmarshal(ref.RawJSON, &value)
				delete(value, "description_redacted")
				ref.RawJSON = mustJSON(t, value)
				ref.SHA256 = ""
			}
			semanticRaw := mustJSON(t, semantic)
			fingerprint, _ := reg.BindingFingerprint(materials.Binding)
			if _, err := admin.Exec(`INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES(?,?,?,?,?,?)`, authority.InstallationID, materials.Binding.Key.IdentityHash, materials.Binding.Key.RegistryVersion, fingerprint, hash(semanticRaw), mustJSON(t, materials.Binding)); err != nil {
				t.Fatal("original binding index fixture", err)
			}
			if authority.AttemptNo != 3 {
				t.Fatal("must exercise actual original attempt3")
			}
			service.Config.ControllerOwner = authority.ClaimOwner
			service.Config.Security = owner.Security
			service.formalVerifier = &materials
			client := installOriginalWorkerAPIFixture(t, owner, admin, authority, job, invocation)
			caps, err := a.NewSQLProviderCapabilityPreparation(db, materials.Database, authority.InstallationID, materials.GenerateCapability, materials.UnwrapCapability)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "valid" {
				original := materials.ProviderPermits
				for _, fault := range []string{"delivery-issuer", "delegation-pin", "identity-key"} {
					changed := *original
					switch fault {
					case "delivery-issuer":
						changed.DeliveryPin.Issuer = bytes.Repeat([]byte{1}, 32)
					case "delegation-pin":
						changed.DeliveryPin.IssuerGrantSHA256 = strings.Repeat("0", 64)
					case "identity-key":
						service.Config.IssuerKey = changed.SigningKeyFile
					}
					materials.ProviderPermits = &changed
					if service.attachProviderPermits(owner, caps) == nil || owner.providerPermits != nil {
						t.Fatal("wrong independent deployment permit pins admitted", fault)
					}
					service.Config.IssuerKey = ""
				}
				materials.ProviderPermits = original
			}
			if err = service.attachProviderPermits(owner, caps); err != nil {
				t.Fatal("actual deployment issuer composition", err)
			}
			// This fixture originally seeded a consumer candidate. The producer starts
			// before any candidate and owns fresh create-only output.
			if _, err = admin.Exec(`UPDATE system_backup_v2_runtime_resources SET candidate_cipher=NULL,candidate_key_ref=NULL,candidate_sha256=NULL WHERE resource_kind='Job'`); err != nil {
				t.Fatal(err)
			}
			staging, err := owner.Staging.OpenRoot(authority.TaskPublicID)
			if err != nil {
				t.Fatal(err)
			}
			defer staging.Close()
			if staging.Remove(candidate.Ciphertext.Name) != nil || staging.Remove(candidate.Envelope.Name) != nil {
				t.Fatal("old fixture candidate cleanup failed")
			}
			source, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if source.WriteFile("history.json", []byte(`{"private":"actual worker source"}`), 0600) != nil {
				t.Fatal("source write failed")
			}
			refresh()
			var dropped atomic.Bool
			handler := WorkloadIdentity{Client: client, Namespace: owner.Namespace, ServiceAccount: owner.Security.ServiceAccountName, ServiceAccountUID: owner.Security.ServiceAccountUID, Next: worker.ControlHandler{Authorizer: owner}}
			endpoint := http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if mode == "unknown-reserve-ack" && !dropped.Load() {
					// Execute the actual handler and commit, discard only its successful ACK.
					raw := new(bytes.Buffer)
					raw.ReadFrom(r.Body)
					r.Body.Close()
					r.Body = http.NoBody
					var req worker.ControlRequest
					json.Unmarshal(raw.Bytes(), &req)
					r.Body = ioNopReader(raw.Bytes())
					if req.Action == "key-reserve" {
						recorded := httptest.NewRecorder()
						handler.ServeHTTP(recorded, r)
						if recorded.Code == 200 {
							dropped.Store(true)
							out.WriteHeader(503)
							return
						}
						for key, values := range recorded.Header() {
							out.Header()[key] = values
						}
						out.WriteHeader(recorded.Code)
						out.Write(recorded.Body.Bytes())
						return
					}
				}
				handler.ServeHTTP(out, r)
			})
			controlClient := originalMTLSControlClient(t, owner, authority, invocation, endpoint)
			if mode == "valid" {
				var originalBinding []byte
				if db.QueryRow(`SELECT binding_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job'`).Scan(&originalBinding) != nil {
					t.Fatal("original binding fixture missing")
				}
				if _, err := admin.Exec(`UPDATE system_backup_v2_runtime_resources SET observed_uid='',resource_version='',lifecycle='creating',binding_json=NULL WHERE resource_kind='Job'`); err != nil {
					t.Fatal(err)
				}
				if err := controlClient.Ready(ctx, invocation); !errors.Is(err, worker.ErrNotReady) {
					t.Fatal("dispatched original Job observation gap must return 503", err)
				}
				for _, fault := range []string{"revoked", "wrong-uid", "old-attempt"} {
					switch fault {
					case "revoked":
						_, err = admin.Exec(`UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE resource_kind='Job'`)
					case "wrong-uid":
						_, err = admin.Exec(`UPDATE system_backup_v2_runtime_resources SET observed_uid='replacement-job',resource_version='1' WHERE resource_kind='Job'`)
					case "old-attempt":
						_, err = admin.Exec(`INSERT INTO system_backup_v2_attempts VALUES('backup',?,4,'capture','running',1)`, authority.TaskPublicID)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err = controlClient.Ready(ctx, invocation); err == nil || errors.Is(err, worker.ErrNotReady) {
						t.Fatal("invalid original Job hidden as pending", fault, err)
					}
					if _, err = admin.Exec(`UPDATE system_backup_v2_runtime_resources SET revoked=FALSE,observed_uid='',resource_version='' WHERE resource_kind='Job'`); err != nil {
						t.Fatal(err)
					}
					if _, err = admin.Exec(`DELETE FROM system_backup_v2_attempts WHERE attempt_no=4`); err != nil {
						t.Fatal(err)
					}
				}
				var permits, uses int
				if db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE evidence_type='diagnostic'`).Scan(&permits) != nil || db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE key_use_json IS NOT NULL`).Scan(&uses) != nil || permits != 0 || uses != 0 || generates.Load() != 0 {
					t.Fatal("pending observation admitted key use")
				}
				rows, err := owner.rows(authority)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				record, err := rows.Load(ctx, tx, kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: job.Namespace, Name: job.Name}})
				tx.Rollback()
				if err != nil {
					t.Fatal(err)
				}
				runner, err := owner.runner(authority, false)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = runner.Journal.Observe(ctx, record, job.UID, "1"); err != nil {
					t.Fatal("actual original controller observation", err)
				}
				if _, err = admin.Exec(`UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE resource_kind='Job'`, originalBinding); err != nil {
					t.Fatal("restore original binding fixture", err)
				}
				bad := invocation
				access := *invocation.ProviderKey
				bad.ProviderKey = &access
				bad.Request.Binding.Attempt = "1"
				bad.ProviderKey.Request.Context.AttemptNo = "1"
				if err := controlClient.Ready(ctx, bad); err == nil {
					t.Fatal("worker-selected attempt admitted")
				}
				pod, err := client.CoreV1().Pods(owner.Namespace).Get(ctx, "capture-pod", metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				original := pod.DeepCopy()
				pod.OwnerReferences[0].UID = "replacement-job"
				if _, err = client.CoreV1().Pods(owner.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if err = controlClient.Ready(ctx, invocation); err == nil {
					t.Fatal("replacement Job inherited original attempt")
				}
				if _, err = client.CoreV1().Pods(owner.Namespace).Update(ctx, original, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if _, err = admin.Exec(`INSERT INTO system_backup_v2_attempts VALUES('backup',?,4,'capture','running',1)`, authority.TaskPublicID); err != nil {
					t.Fatal(err)
				}
				if err = controlClient.Ready(ctx, invocation); err == nil {
					t.Fatal("old original attempt remained current")
				}
				if _, err = admin.Exec(`DELETE FROM system_backup_v2_attempts WHERE attempt_no=4`); err != nil {
					t.Fatal(err)
				}
				if _, err = admin.Exec(`UPDATE system_backup_participants SET state='running'`); err != nil {
					t.Fatal(err)
				}
				if err = controlClient.Ready(ctx, invocation); err == nil {
					t.Fatal("unpaused source passed actual collectors gate")
				}
				if _, err = admin.Exec(`UPDATE system_backup_participants SET state='paused'`); err != nil {
					t.Fatal(err)
				}
				var admitted int
				if db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE key_use_json IS NOT NULL`).Scan(&admitted) != nil || admitted != 0 || generates.Load() != 0 {
					t.Fatal("negative original identity reached key-use/provider")
				}
			}
			if err := controlClient.Ready(ctx, invocation); err != nil {
				t.Fatal("actual mTLS ready handler", err)
			}
			capture, err := worker.NewDeliveredCaptureKeyJob(ctx, controlClient, invocation, config, *invocation.FormalCapture.PermitDelivery)
			if err != nil {
				t.Fatal("actual mTLS reserve/SQL issuer", err)
			}
			defer capture.Close()
			var rawLease, deliveryRaw []byte
			var expires time.Time
			if db.QueryRow(`SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job'`).Scan(&rawLease) != nil || db.QueryRow(`SELECT inline_payload,expires_at FROM system_backup_v2_evidence WHERE evidence_type='diagnostic'`).Scan(&deliveryRaw, &expires) != nil {
				t.Fatal("original SQL readback missing")
			}
			var lease worker.KeyUseLease
			var delivery k.DeliveredProviderPermit
			var payload k.DeliveredPermitPayload
			if json.Unmarshal(rawLease, &lease) != nil || json.Unmarshal(deliveryRaw, &delivery) != nil || json.Unmarshal(delivery.Payload, &payload) != nil || !expires.Equal(minimum.UTC().Truncate(time.Microsecond)) || !expires.Equal(lease.Until) || !expires.Equal(payload.Permit.ExpiresAt) {
				t.Fatal("actual shortest signed/SQL nanosecond boundary diverged")
			}
			result, err := worker.RunFormalCapture(ctx, invocation, capture, worker.FormalCaptureEnvironment{Workspace: source, Staging: staging})
			if mode == "revoked-after-login" {
				if err == nil || generates.Load() != 0 || logins.Load() != 1 {
					t.Fatal("revoked original source reached provider", err)
				}
				return
			}
			if err != nil {
				t.Fatal("actual formal capture", err)
			}
			if err = capture.ReportCandidate(ctx, invocation, result); err != nil {
				t.Fatal("actual candidate handler", err)
			}
			if generates.Load() != 1 || logins.Load() != 1 || (mode == "unknown-reserve-ack" && !dropped.Load()) {
				t.Fatal("provider/replay counts", generates.Load(), logins.Load())
			}
			original, err := owner.ReadFormalCandidate(ctx, authority, job, false)
			if err != nil || original.KeyUseNonce != lease.Nonce || original.Authority.AttemptNo != 3 || original.Candidate.Ciphertext != result.Ciphertext {
				t.Fatal("original candidate readback", err)
			}
			var permits int
			if db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE evidence_type='diagnostic'`).Scan(&permits) != nil || permits != 1 {
				t.Fatal("reserve ACK created extra permit")
			}
		})
	}
}

func ioNopReader(raw []byte) *readCloseBuffer { return &readCloseBuffer{bytes.NewReader(raw)} }

type readCloseBuffer struct{ *bytes.Reader }

func (*readCloseBuffer) Close() error { return nil }

func installOriginalWorkerAPIFixture(t *testing.T, o *PublicJobOwner, admin *sql.DB, authority d.Authority, binding d.JobBinding, inv worker.Invocation, mountedData ...map[string]map[string]string) *fake.Clientset {
	t.Helper()
	ctx := context.Background()
	immutable, controller := true, true
	var raw []byte
	if admin.QueryRow(`SELECT request_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job' AND task_public_id=? AND namespace_name=? AND resource_name=? AND observed_uid=?`, authority.TaskPublicID, binding.Namespace, binding.Name, binding.UID).Scan(&raw) != nil {
		t.Fatal("original Job unavailable")
	}
	var job batchv1.Job
	if json.Unmarshal(raw, &job) != nil {
		t.Fatal("invalid Job")
	}
	job.UID = types.UID(binding.UID)
	job.ResourceVersion = "1"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "capture-pod", Namespace: binding.Namespace, UID: "capture-pod-uid", ResourceVersion: "1", Labels: map[string]string{"batch.kubernetes.io/controller-uid": binding.UID}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: binding.Name, UID: types.UID(binding.UID), Controller: &controller}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for key, value := range job.Spec.Template.Labels {
		pod.Labels[key] = value
	}
	pod.Spec.NodeName = "worker-node"
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, ContainerID: "containerd://original-worker", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
	workload := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "controller-pod", Namespace: "controller", UID: "controller-pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller-rs", UID: "controller-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: "controller"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	client := fake.NewSimpleClientset(&job, pod, workload, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: o.Namespace, UID: types.UID(o.NamespaceUID)}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-node", UID: "worker-node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "capture", Namespace: o.Namespace, UID: "capture-sa"}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: "controller", UID: "controller-sa"}}, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-rs", Namespace: "controller", UID: "controller-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "controller-deployment", UID: "controller-deployment-uid", Controller: &controller}}}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller-deployment", Namespace: "controller", UID: "controller-deployment-uid"}})
	o.Client = client
	o.Security.NodeUIDs = map[string]string{"worker-node": "worker-node-uid"}
	// This helper replaces the entire named local Kubernetes surface. Retain
	// only pins for objects on that surface, never the previous pair member's
	// same-volume-name ConfigMap pin after its original Job has completed.
	o.Security.Volumes = nil
	for _, volume := range pod.Spec.Volumes {
		switch {
		case volume.PersistentVolumeClaim != nil:
			name := volume.PersistentVolumeClaim.ClaimName
			uid := name + "-uid"
			pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: name + "-pv", UID: types.UID(name + "-pv-uid")}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: name, Namespace: o.Namespace, UID: types.UID(uid)}}}
			claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: o.Namespace, UID: types.UID(uid)}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pv.Name}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
			client.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{})
			client.CoreV1().PersistentVolumeClaims(o.Namespace).Create(ctx, claim, metav1.CreateOptions{})
			o.Security.Volumes = append(o.Security.Volumes, kube.MountIdentity{Volume: volume.Name, Kind: "PersistentVolumeClaim", Name: name, UID: uid, PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)})
		case volume.ConfigMap != nil:
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: volume.ConfigMap.Name, Namespace: o.Namespace, UID: types.UID(volume.ConfigMap.Name + "-uid")}, Immutable: &immutable, Data: map[string]string{"fixture": "original pinned mount"}}
			if len(mountedData) == 1 && mountedData[0][cm.Name] != nil {
				cm.Data = mountedData[0][cm.Name]
			}
			if volume.Name == "worker-request" {
				cm.Data = map[string]string{"invocation.json": string(mustJSON(t, inv))}
				desired, err := kube.WorkerConfigMap(kube.Identity{Name: cm.Name, Namespace: o.Namespace, Owner: authority.TaskPublicID}, inv)
				if err != nil {
					t.Fatal(err)
				}
				intent, err := kube.Intent("ConfigMap", desired)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = admin.Exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'ConfigMap',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, o.Namespace, cm.Name, authority.TaskPublicID, intent.RequestSHA256, intent.RequestJSON, string(cm.UID), authority.AttemptNo); err != nil {
					t.Fatal(err)
				}
			} else {
				o.Security.Volumes = append(o.Security.Volumes, kube.MountIdentity{Volume: volume.Name, Kind: "ConfigMap", Name: cm.Name, UID: string(cm.UID), SHA256: kube.ContentHash([]any{cm.Data, cm.BinaryData})})
			}
			if _, err := client.CoreV1().ConfigMaps(o.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		case volume.Secret != nil:
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: volume.Secret.SecretName, Namespace: o.Namespace, UID: types.UID(volume.Secret.SecretName + "-uid")}, Immutable: &immutable, Data: map[string][]byte{"fixture": []byte("original worker identity fixture")}}
			if _, err := client.CoreV1().Secrets(o.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			envelope := identityEnvelope{PlainSHA256: kube.ContentHash(secret.Data)}
			if _, err := admin.Exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'IdentitySecret',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, o.Namespace, secret.Name, authority.TaskPublicID, strings.Repeat("d", 64), mustJSON(t, envelope), string(secret.UID), authority.AttemptNo); err != nil {
				t.Fatal(err)
			}
		}
	}
	client.PrependReactor("create", "tokenreviews", func(action ktest.Action) (bool, runtime.Object, error) {
		review := action.(ktest.CreateAction).GetObject().(*authv1.TokenReview)
		if review.Spec.Token != "local-current-worker-pod-token" {
			return true, &authv1.TokenReview{}, nil
		}
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{kube.WorkerTokenAudience}, User: authv1.UserInfo{Username: "system:serviceaccount:" + o.Namespace + ":capture", UID: "capture-sa", Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"capture-pod"}, "authentication.kubernetes.io/pod-uid": {"capture-pod-uid"}}}}}, nil
	})
	return client
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func originalMTLSControlClient(t *testing.T, o *PublicJobOwner, authority d.Authority, inv worker.Invocation, handler http.Handler) *worker.ControlClient {
	_, makeClient := originalMTLSControlServer(t, handler)
	return makeClient(o, authority, inv)
}

// Reserve the actual TLS endpoint before the signed core/source grants are
// frozen. Worker identity is issued only after the original invocation exists.
func originalMTLSControlServer(t *testing.T, handler http.Handler) (string, func(*PublicJobOwner, d.Authority, worker.Invocation, ...string) *worker.ControlClient) {
	t.Helper()
	now := time.Now()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() { clear(key) })
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local original control CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	serverCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL, func(o *PublicJobOwner, authority d.Authority, inv worker.Invocation, endpointOverride ...string) *worker.ControlClient {
		t.Helper()
		invHash, _ := inv.Hash()
		identity, err := (control.IdentityIssuer{Certificate: root, Signer: key, TrustDomain: o.TrustDomain, ServerRoots: ca}).IssueWorker(authority.TaskPublicID, authority.DeadlineAt, invHash)
		if err != nil {
			t.Fatal(err)
		}
		defer identity.Clear()
		dir := t.TempDir()
		for name, raw := range identity.Data {
			if os.WriteFile(filepath.Join(dir, name), raw, 0600) != nil {
				t.Fatal("identity write failed")
			}
		}
		tokenFile := filepath.Join(dir, "token")
		os.WriteFile(tokenFile, []byte("local-current-worker-pod-token"), 0600)
		controlURL := server.URL
		if len(endpointOverride) == 1 {
			controlURL = endpointOverride[0]
		}
		client, err := worker.NewControlClient(controlURL, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		if err != nil {
			t.Fatal(err)
		}
		if client.WithWorkloadToken(tokenFile) != nil {
			t.Fatal("bound token missing")
		}
		t.Cleanup(client.Close)
		return client
	}
}
