package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/buildinfo"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	k "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These are independent LOCAL owner/provider fixtures consumed by the real
// material loaders. They do not replace the original task, capture Authority,
// encrypted plan, ten worker results or current publication claim.
type aSameTaskCertificateMaterials struct {
	signs          atomic.Int64
	loseSignResult bool
	commitACKFault bool
	loseStoreACK   bool
	loseCommit     atomic.Bool
}

func (aFixture *aSameTaskCertificateMaterials) options() dOriginalSixPartFixtureOptions {
	var commitACKLoss *atomic.Bool
	if aFixture.commitACKFault {
		commitACKLoss = &aFixture.loseCommit
	}
	return dOriginalSixPartFixtureOptions{
		ControlCommitACKLoss: commitACKLoss,
		BeforeCoreSeal: func(_ context.Context, _ *testing.T, f *dOriginalSixPartTask, core *DeploymentConfig) error {
			core.PublicationSigners = &PublicationSignerReference{Protocol: PublicationSignerMaterialsVersion, Path: filepath.Join(f.directory, "a-original-publication-signers.json")}
			core.PublisherVerifier = &PublisherVerifierReference{Protocol: PublisherVerifierMaterialsVersion, Path: filepath.Join(f.directory, "a-original-publisher-verifier.json")}
			return nil
		},
		BeforeRuntimeComposition: func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) error {
			aFixture.install(ctx, t, f)
			return nil
		},
		BeforePrepare: func(ctx context.Context, _ *testing.T, f *dOriginalSixPartTask) error {
			return f.service.CheckPublisherVerifierReadiness(ctx)
		},
	}
}

func (aFixture *aSameTaskCertificateMaterials) install(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) {
	t.Helper()
	s := f.service
	formal := s.formalVerifier
	if formal == nil || formal.KubernetesReads == nil || s.Config.PublicationSigners == nil || s.Config.PublisherVerifier == nil {
		t.Fatal("original pre-seal publication references/formal materials unavailable")
	}
	write := func(file string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal("same-task independent publication material file", err)
		}
	}
	private := func(name string, raw []byte) string {
		file := filepath.Join(f.directory, name)
		write(file, raw)
		return file
	}
	g := s.Forward.DeploymentBinding()
	reads := *formal.KubernetesReads
	pod, err := f.owner.Client.CoreV1().Pods(s.Config.Namespace).Get(ctx, reads.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != reads.PodUID || pod.Status.Phase != "Running" {
		t.Fatal("same original controller workload", err)
	}
	publisher := "public:" + reads.PodUID
	now := time.Now().UTC()
	deployment := security.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: s.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt}
	actor := security.PublisherCaptureWorkload{Namespace: reads.Namespace, NamespaceUID: reads.NamespaceUID, PodName: reads.PodName, PodUID: reads.PodUID, ServiceAccountName: reads.ServiceAccountName, ServiceAccountUID: reads.ServiceAccountUID, PublisherOwner: publisher}
	grant := security.PublisherCaptureGrant{Version: security.PublisherCaptureGrantVersion, Deployment: deployment, Workload: actor, NotBefore: now.Add(-time.Minute), Until: g.ExpiresAt}
	grantIssuer, grantKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := json.Marshal(grant)
	grantEnvelope, _ := json.Marshal(security.SignedPublisherCaptureGrant{Record: grantRaw, Signature: ed25519.Sign(grantKey, append([]byte(security.PublisherCaptureGrantDomain), grantRaw...))})
	clear(grantKey)
	grantMount := security.PublisherCaptureGrantMount{File: private("a-original-publisher-grant.json", grantEnvelope), SHA256: hash(grantEnvelope), Issuer: grantIssuer}
	workload := formal.Workload
	workload.ControllerOwner, workload.GrantSHA256 = publisher, grantMount.SHA256
	// The SAME actual controller Pod uses its real controller-Unwrap identity.
	// Generate remains the original separate worker role. A separately signed
	// provider permission binds this publisher grant to that existing mapping.
	capability := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: formal.Binding, Operation: k.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "controller-jwt", Role: "controller-unwrap-role", Policy: "controller-unwrap-policy", PolicySHA256: hash([]byte("explicit local unwrap policy")), RoleSHA256: hash([]byte("explicit local unwrap role")), JWTTrustSHA256: hash([]byte("explicit local verifier JWT trust")), Reference: formal.Binding.UnwrapRef, ControllerVerifier: &workload}}, Revision: "a-original-publisher-r1", NotBefore: now.Add(-time.Minute), Until: g.ExpiresAt}
	capability.Source = formal.UnwrapCapability.Source
	capability.Source.RecordID = "sev_a_original_publisher_unwrap"
	factsRaw, _ := json.Marshal(capability.Facts)
	capability.Source.ContentSHA256 = hash(factsRaw)
	capIssuer, capKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capRaw, _ := json.Marshal(capability)
	capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
	clear(capKey)
	if _, err = f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)`, capability.Source.RecordID, g.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capability.Until); err != nil {
		t.Fatal("original publisher provider capability", err)
	}
	materials := PublisherVerifierMaterials{Version: PublisherVerifierMaterialsVersion, Database: formal.Database, Binding: formal.Binding, GenerateCapability: formal.GenerateCapability, UnwrapCapability: a.ProviderCapabilityPin{Source: capability.Source, Issuer: capIssuer}, InstallationIssuer: formal.InstallationIssuer, CAFile: formal.CAFile, JWTFile: formal.JWTFile, Workload: workload, KubernetesReads: reads, Grant: grantMount}
	raw, _ := json.Marshal(materials)
	write(s.Config.PublisherVerifier.Path, raw)
	if err = s.loadPublisherVerifierInput([]PublisherVerifierInput{{File: s.Config.PublisherVerifier.Path, SHA256: hash(raw)}}); err != nil {
		t.Fatal("actual same-task publisher material loader", err)
	}
	signingInput := aFixture.installSigners(t, f, reads, private)
	if err = s.loadPublicationSignerInput([]PublicationSignerInput{signingInput}); err != nil {
		t.Fatal("actual same-task signer material loader", err)
	}
	if err = s.attachPublicationSigners(ctx, f.control, f.owner.Client, reads.PodName); err != nil {
		t.Fatal("actual same-task signer attachment", err)
	}
	if err = s.attachPublisherVerifier(ctx, f.control, f.owner.Client, f.owner.Gate.Records); err != nil {
		t.Fatal("actual same-task publisher attachment", err)
	}
	s.staging = f.owner.Staging
	if err = checkDOriginalCoreUnchanged(s, f.sealedCore); err != nil || aFixture.signs.Load() != 0 {
		t.Fatal("bootstrap changed original core or invoked artifact signer", err)
	}
}

func (aFixture *aSameTaskCertificateMaterials) installSigners(t *testing.T, f *dOriginalSixPartTask, reads a.VerifierKubernetesReads, privateFile func(string, []byte) string) PublicationSignerInput {
	t.Helper()
	s, g := f.service, f.service.Forward.DeploymentBinding()
	keys := map[string]ed25519.PrivateKey{}
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/v1/auth/a-publisher/login" {
			var input struct{ Role, JWT string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&input) != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			purpose := strings.TrimSuffix(input.Role, "-role")
			if keys[purpose] == nil || input.JWT != "explicit-local-original-"+purpose+"-projected-jwt" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "explicit-local-sign-token-" + purpose, "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{purpose + "-policy"}, "metadata": map[string]string{"role": input.Role, "namespace": reads.Namespace, "pod_uid": reads.PodUID, "service_account_uid": reads.ServiceAccountUID}}})
			return
		}
		purpose := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
		var input struct {
			Input   string `json:"input"`
			Version string `json:"key_version"`
		}
		if keys[purpose] == nil || r.Header.Get("X-Vault-Token") != "explicit-local-sign-token-"+purpose || json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&input) != nil || input.Version != "7" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(input.Input)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		signature := ed25519.Sign(keys[purpose], raw)
		aFixture.signs.Add(1)
		if aFixture.loseSignResult {
			// The real external signing operation happened; its public result
			// is deliberately withheld. The publisher may never Sign again.
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if aFixture.loseStoreACK {
			aFixture.loseCommit.Store(true)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v7:" + base64.StdEncoding.EncodeToString(signature)}})
	}))
	t.Cleanup(provider.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
	caFile := privateFile("a-original-signing-ca.pem", ca)
	now := time.Now().UTC()
	record := security.InstallationSigningRecord{InstallationID: g.InstallationID, Revision: 1, NotBefore: now.Add(-time.Minute), Until: g.ExpiresAt}
	materials := PublicationSignerMaterials{Version: PublicationSignerMaterialsVersion}
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[purpose] = key
		t.Cleanup(func() { clear(key) })
		binding := security.TransitSigningBinding{InstallationID: g.InstallationID, Purpose: purpose, KeyID: "a-original-" + purpose, KeyVersion: "a-original-r1", Endpoint: provider.URL, KeyName: purpose, ProviderVersion: "7"}
		mount := PublicationSigningMount{Binding: binding, AuthMount: "a-publisher", Role: purpose + "-role", Policy: purpose + "-policy", JWTFile: privateFile("a-original-"+purpose+".jwt", []byte("explicit-local-original-"+purpose+"-projected-jwt")), CAFile: caFile, CASHA256: hash(ca)}
		materials.Mounts = append(materials.Mounts, mount)
		record.Keys = append(record.Keys, security.ArtifactSigningPublicKey{InstallationID: g.InstallationID, Purpose: purpose, KeyID: binding.KeyID, KeyVersion: binding.KeyVersion, PublicKey: public, NotBefore: now.Add(-time.Minute), NotAfter: g.ExpiresAt})
		record.Permissions = append(record.Permissions, security.InstallationSigningPermission{Binding: binding, AuthMount: mount.AuthMount, Role: mount.Role, Policy: mount.Policy, CASHA256: mount.CASHA256, SQLOwner: &security.SQLSigningOwnerGrant{ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: "public:" + reads.PodUID, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, Workload: security.SigningWorkloadIdentity{Namespace: reads.Namespace, PodUID: reads.PodUID, ServiceAccountUID: reads.ServiceAccountUID}}})
	}
	issuer, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(record)
	materials.Record = security.FileSigningRecordReader{RecordFile: privateFile("a-original-signing-record.json", raw), SignatureFile: privateFile("a-original-signing-record.sig", ed25519.Sign(key, append([]byte(security.InstallationSigningDomain), raw...)))}
	clear(key)
	materials.Pin = security.InstallationSigningPin{InstallationID: g.InstallationID, Revision: record.Revision, RecordSHA256: hash(raw), Issuer: issuer}
	raw, _ = json.Marshal(materials)
	if err = os.WriteFile(s.Config.PublicationSigners.Path, raw, 0600); err != nil {
		t.Fatal("original signer material", err)
	}
	return PublicationSignerInput{File: s.Config.PublicationSigners.Path, SHA256: hash(raw)}
}

// This is a real same-task continuation, gated on original Store.Record having
// actually reached validating. A failed capture never enters this callback.
// No remote publication, marker, acceptance or catalog success is inferred.
func TestAOriginalSixPartCertificatePublicationMySQL(t *testing.T) {
	for _, mode := range []string{"current", "stage-version-after-prepare", "finished-at-after-prepare", "task-version-after-prepare", "provider-sign-result-unknown", "dispatch-commit-ack-unknown", "store-commit-ack-unknown"} {
		t.Run(mode, func(t *testing.T) { runAOriginalSixPartCertificatePublication(t, mode) })
	}
}

func runAOriginalSixPartCertificatePublication(t *testing.T, mode string, after ...func(context.Context, *dOriginalSixPartTask, *c.ClaimToken, publicationVerifiedCapture)) {
	runAOriginalSixPartCertificatePublicationConfigured(t, mode, nil, after...)
}

func runAOriginalSixPartCertificatePublicationConfigured(t *testing.T, mode string, configure func(*dOriginalSixPartFixtureOptions), after ...func(context.Context, *dOriginalSixPartTask, *c.ClaimToken, publicationVerifiedCapture)) {
	t.Helper()
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") != "" {
		if !regexp.MustCompile(`^[a-f0-9]{7,64}$`).MatchString(buildinfo.Commit) {
			t.Fatal("original publication SQL test requires a real Git commit linked before capture with -ldflags -X clawreef/internal/buildinfo.Commit=<git HEAD>")
		}
		t.Log("original pre-capture linked build commit", buildinfo.Commit)
	}
	fixture := &aSameTaskCertificateMaterials{loseSignResult: mode == "provider-sign-result-unknown", commitACKFault: mode == "dispatch-commit-ack-unknown" || mode == "store-commit-ack-unknown", loseStoreACK: mode == "store-commit-ack-unknown"}
	options := fixture.options()
	if configure != nil {
		configure(&options)
	}
	runDOriginalSixPartCaptureWithOptions(t, false, true, options, func(ctx context.Context, f *dOriginalSixPartTask, work c.ExecutionWork, _ []d.ModuleResult) {
		var version uint64
		var delay int64
		if err := f.control.QueryRowContext(ctx, `SELECT row_version,COALESCE(TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),next_reconcile_at),0) FROM system_backup_v2_backups WHERE public_id=? AND status='validating' AND controller_owner IS NULL`, f.publicID).Scan(&version, &delay); err != nil {
			t.Fatal("original validating task did not release capture claim", err)
		}
		if delay > 10_000_000 {
			t.Fatal("original next reconciliation exceeds local test wait budget")
		}
		if delay > 0 {
			timer := time.NewTimer(time.Duration(delay)*time.Microsecond + time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		claim, err := (c.SQLTaskClaimStore{DB: f.control, InstallationID: f.service.Config.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: f.publicID}, f.service.PublisherOwner, version, policy)
		if err != nil {
			t.Fatal("same original publisher claim receipt", err)
		}
		taskVersionChanged := false
		defer func() {
			_, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Release(ctx, claim, time.Second)
			if taskVersionChanged {
				if !errors.Is(err, c.ErrClaimLost) {
					t.Error("old publisher claim adopted independently changed task version")
				}
			} else if err != nil {
				t.Error("same original publisher claim release", err)
			}
		}()
		capture, err := f.service.verifyOriginalPublicationCapture(ctx, &claim, work.Input.Authority.AttemptNo, policy)
		if err != nil || len(capture.Parts) != 10 {
			t.Fatal("same-task full current publisher C/domain verification", len(capture.Parts), err)
		}
		if sqlDomains, err := publicationSQLBusinessCounts(capture); err != nil || len(sqlDomains) != 6 {
			t.Fatal("same-task original-registry SQL business summary inputs", err)
		}
		if policy, err := publicationSecretPolicyFacts(capture); err != nil || policy.RegistryVersion != f.secretPolicyVersion || policy.RegistrySHA256 != f.secretPolicySHA || policy.RequiredEntries != 1 || policy.CapturedEntries != 1 {
			t.Fatal("same-task original independent SecretPolicy complete-C coverage", err)
		}
		signers, err := f.service.PublicationSignersForTask(ctx, claim)
		if err != nil {
			t.Fatal("same-task current original signing consumer", err)
		}
		defer signers.Close()
		prepared, err := f.service.prepareOriginalCaptureCertificate(ctx, claim, work.Input.Authority.AttemptNo, capture, signers)
		if err != nil {
			t.Fatal("same-task real certificate producer", err)
		}
		var evidenceBefore uint64
		if err = f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?`, f.publicID).Scan(&evidenceBefore); err != nil {
			t.Fatal("original evidence before Stage", err)
		}
		stageFault := mode == "stage-version-after-prepare" || mode == "finished-at-after-prepare" || mode == "task-version-after-prepare"
		if stageFault {
			query, args, readback, readArgs := "", []any{}, "", []any{}
			switch mode {
			case "stage-version-after-prepare":
				query, args = `UPDATE system_backup_v2_staging_resources SET row_version=row_version+1 WHERE public_id=? AND row_version=?`, []any{prepared.original.stage.owner.Resource, prepared.original.stage.version}
				readback, readArgs = `SELECT row_version=? FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{prepared.original.stage.version + 1, prepared.original.stage.owner.Resource}
			case "finished-at-after-prepare":
				query, args = `UPDATE system_backup_v2_attempts SET finished_at=TIMESTAMPADD(MICROSECOND,1,finished_at) WHERE target_type='backup' AND target_public_id=? AND phase='capture' AND attempt_no=? AND finished_at=?`, []any{f.publicID, work.Input.Authority.AttemptNo, prepared.original.completed}
				readback, readArgs = `SELECT finished_at=? FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' AND attempt_no=?`, []any{prepared.original.completed.Add(time.Microsecond), f.publicID, work.Input.Authority.AttemptNo}
			case "task-version-after-prepare":
				query, args = `UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=? AND row_version=? AND controller_owner=?`, []any{f.publicID, claim.RowVersion, claim.Owner}
				readback, readArgs = `SELECT row_version=? FROM system_backup_v2_backups WHERE public_id=?`, []any{claim.RowVersion + 1, f.publicID}
			default:
				t.Fatal("unknown same-task certificate fault")
			}
			result, err := f.db.ExecContext(ctx, query, args...)
			if err != nil {
				t.Fatal("independent same-task SQL fault", err)
			}
			if affected, err := result.RowsAffected(); err != nil || affected != 1 {
				t.Fatal("same-task fault did not affect original row", affected, err)
			}
			var observed bool
			if err = f.db.QueryRowContext(ctx, readback, readArgs...).Scan(&observed); err != nil || !observed {
				t.Fatal("independent original fault readback", err)
			}
			taskVersionChanged = mode == "task-version-after-prepare"
		}
		tx, err := f.control.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = prepared.Stage(ctx, tx)
		if stageFault {
			tx.Rollback()
			if err == nil || fixture.signs.Load() != 0 {
				t.Fatal("changed original business facts reached signing input/provider", mode, err)
			}
			var evidenceAfter uint64
			if err = f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?`, f.publicID).Scan(&evidenceAfter); err != nil || evidenceAfter != evidenceBefore {
				t.Fatal("failed original Stage left signing evidence", err)
			}
			t.Log("same original task Stage refused before signer", f.publicID, mode)
			return
		}
		if err != nil {
			tx.Rollback()
			t.Fatal("same-task business snapshot and signing-input Stage", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal("original signing-input commit unknown; no signing authorized", err)
		}
		if fixture.signs.Load() != 0 {
			t.Fatal("artifact signing occurred before original Stage commit")
		}
		if mode == "dispatch-commit-ack-unknown" {
			fixture.loseCommit.Store(true)
		}
		raw, sum, err := prepared.SignCommitted(ctx)
		if mode == "dispatch-commit-ack-unknown" || mode == "store-commit-ack-unknown" {
			raw, sum = checkAOriginalCertificateCommitACK(t, ctx, f, claim, capture, prepared, mode, raw, sum, err, fixture)
			if mode == "dispatch-commit-ack-unknown" {
				if _, err = f.service.prepareOriginalCaptureCertificate(ctx, claim, work.Input.Authority.AttemptNo, capture, signers); !errors.Is(err, c.ErrExecutionCommitUnknown) || fixture.signs.Load() != 0 {
					t.Fatal("unknown dispatch commit admitted another preparation", err)
				}
				return
			}
			err = nil
		}
		if mode == "provider-sign-result-unknown" {
			if !errors.Is(err, c.ErrExecutionCommitUnknown) || fixture.signs.Load() != 1 || len(raw) != 0 || sum != "" {
				t.Fatal("actual provider unknown result did not retain single-send boundary", err)
			}
			if _, _, err = prepared.SignCommitted(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || fixture.signs.Load() != 1 {
				t.Fatal("unknown external signature was sent again", err)
			}
			if _, err = f.service.prepareOriginalCaptureCertificate(ctx, claim, work.Input.Authority.AttemptNo, capture, signers); !errors.Is(err, c.ErrExecutionCommitUnknown) || fixture.signs.Load() != 1 {
				t.Fatal("unknown signature admitted another timestamp/input", err)
			}
			t.Log("same original provider Sign result unknown; reentry remained query only", f.publicID, fixture.signs.Load())
			return
		}
		if err != nil || hash(raw) != sum || fixture.signs.Load() != 1 {
			t.Fatal("same-task externally signed capture certificate", err)
		}
		history, err := f.service.PublicationSigningHistory(ctx)
		if err != nil {
			t.Fatal("independently pinned public signing history", err)
		}
		if verified, err := history.VerifyPublicationRecord(raw, security.ArtifactSigningTask{BackupPublicID: f.publicID, AttemptNo: int64(work.Input.Authority.AttemptNo)}, "capture_certificate"); err != nil || verified != sum {
			t.Fatal("independent original certificate public verification", err)
		}
		var envelope struct {
			Payload   publicationCaptureCertificatePayload `json:"payload"`
			Signature json.RawMessage                      `json:"signature"`
		}
		if decodeProviderDeploymentJSON(raw, &envelope) != nil || envelope.Payload.Installation != f.service.Config.InstallationID || envelope.Payload.Backup != f.publicID || envelope.Payload.Attempt != work.Input.Authority.AttemptNo || envelope.Payload.Context != capture.CaptureContextSHA256 || len(envelope.Payload.Jobs) != 10 || len(envelope.Payload.Checkpoints) != 10 || len(envelope.Payload.Stages) != 1 || envelope.Payload.Stages[0].UID != prepared.original.stage.owner.Resource || !envelope.Payload.CompletedAt.Equal(prepared.original.completed) || !envelope.Payload.ExpiresAt.Equal(envelope.Payload.IssuedAt.Add(time.Duration(prepared.original.ttl)*time.Second)) {
			t.Fatal("signed certificate changed actual original task/completion/staging facts")
		}
		checkAOriginalCertificateKnownResume(t, ctx, f, claim, capture, prepared, signers, raw, sum, &fixture.signs)
		t.Log("same original task certificate only", f.publicID, len(capture.Parts), sum)
		for _, next := range after {
			next(ctx, f, &claim, capture)
		}
	})
}
