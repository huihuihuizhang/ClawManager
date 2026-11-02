package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Same original capture, native upload, complete fixed-version C, manifest,
// marker and real SQL dispatches. The local Kube/S3 transports are fixtures;
// this is not a real-page or production success/acceptance demonstration.
func TestPublicationAcceptanceOriginalHappyPathAndUnknownMySQL(t *testing.T) {
	runAOriginalSixPartManifestUploadJob(t, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, store *nativePublicationS3, native *aNativePublicationServer) {
		proof := publicationOriginalFinalForTest(ctx, t, f, claim, capture, store, native)
		complete := proof.cleanup
		var status string
		var usable bool
		accepted, err := f.service.completeOriginalPublicationAcceptance(ctx, proof)
		if err != nil || accepted == nil {
			t.Fatal("actual current proof to original acceptance signature and native publication", err)
		}
		decoded, err := decodePublicationAcceptancePayload(accepted.signed.prepared.intent.Payload)
		if err != nil || !decoded.Accepted || decoded.CleanupID != complete.evidence.PublicID || decoded.CleanupSHA256 != complete.evidence.SHA256 {
			t.Fatal("acceptance substituted actual cleanup", err)
		}
		root := acceptanceSigningID(f.service.Config.InstallationID, f.publicID, capture.Input.CaptureAttemptNo)
		var phases int
		if f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id IN (?,?,?)`, root+"_prepared", root+"_sent", root+"_result").Scan(&phases) != nil || phases != 3 {
			t.Fatal("immutable acceptance prepared/send/result journal incomplete", phases)
		}
		repeated, err := f.service.completeOriginalPublicationAcceptance(ctx, proof)
		if err != nil || repeated == nil || repeated.object.Key != accepted.object.Key || repeated.object.Version != accepted.object.Version || repeated.object.SHA256 != accepted.object.SHA256 || !bytes.Equal(repeated.signed.raw, accepted.signed.raw) {
			t.Fatal("known original acceptance replay changed bytes/version", err)
		}
		tx, err := f.control.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		checkErr := repeated.recheckTx(ctx, tx)
		_ = tx.Rollback()
		if checkErr != nil {
			t.Fatal("typed acceptance consumer original tx", checkErr)
		}
		// Explicit fault DATA in this owned fixture, not production deletion or
		// a provider-absence proof: retained unhealthy result must block retry.
		if _, err = f.db.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET observed_health='unknown' WHERE public_id=?`, root+"_result"); err != nil {
			t.Fatal(err)
		}
		if denied, err := f.service.completeOriginalPublicationAcceptance(ctx, proof); !errors.Is(err, c.ErrExecutionCommitUnknown) || denied != nil {
			t.Fatal("unknown original result was regenerated/re-signed", err)
		}
		if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable) != nil || status != "publishing" || usable {
			t.Fatal("acceptance alone promoted terminal state")
		}
		native.mu.Lock()
		puts := native.puts
		native.mu.Unlock()
		if puts != 19 {
			t.Fatal("acceptance retry sent another artifact request", puts)
		}
	}, func(store *nativePublicationS3, native *aNativePublicationServer) {
		key := nativePublicationCredential{AccessKey: "local-cleanup-delete-only-fixture", SecretKey: strings.Repeat("d", 32), NotBefore: time.Now().Add(-time.Minute), Until: native.deadline}
		raw, _ := json.Marshal(key)
		file := filepath.Join(filepath.Dir(store.config.ReadCredentialFile), "local-cleanup-delete.json")
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		store.config.DeleteIdentityHash = hash([]byte("local cleanup exact delete fixture"))
		store.config.DeleteRefVersion = "local-cleanup-delete-v1"
		store.config.DeleteCredentialFile = file
		store.config.DeleteCredentialSHA256 = hash(raw)
		native.remove = key
	})
}

func publicationOriginalFinalForTest(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, store *nativePublicationS3, native *aNativePublicationServer) *publicationFinalVerification {
	t.Helper()
	native.candidateDeleteKey = "/" + store.config.Bucket + "/" + store.config.RemoteStagingRoot + f.publicID + "/1/manifest-candidate.json"
	native.onRead = func(dst http.ResponseWriter, request *http.Request) bool {
		value := request.Header.Get("Range")
		if value == "" {
			return false
		}
		bounds, ok := strings.CutPrefix(value, "bytes=")
		left, right, cut := strings.Cut(bounds, "-")
		start, e1 := strconv.ParseInt(left, 10, 64)
		end, e2 := strconv.ParseInt(right, 10, 64)
		raw := bytes.Clone(native.objects[request.URL.Path])
		if !ok || !cut || e1 != nil || e2 != nil || start < 0 || end < start || end >= int64(len(raw)) || request.URL.Query().Get("versionId") != "original-v1" {
			http.Error(dst, "invalid original range", 403)
			return true
		}
		dst.Header().Set("x-amz-version-id", "original-v1")
		dst.Header().Set("Content-Range", "bytes "+left+"-"+right+"/"+strconv.Itoa(len(raw)))
		dst.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		dst.WriteHeader(206)
		_, _ = dst.Write(raw[start : end+1])
		return true
	}
	policy := aOriginalPublicationFixturePolicy(t, f)
	marker, err := f.service.completeOriginalPublicationManifestAndMarker(ctx, claim, capture.Input.CaptureAttemptNo, policy, store, capture)
	if err != nil {
		t.Fatal("same original remote C/manifest/marker", err)
	}
	exit, err := f.service.observeOriginalPublicationUploadExit(ctx, *claim, capture.Input.CaptureAttemptNo, marker)
	if err != nil {
		t.Fatal("original upload exit", err)
	}
	deletes := aInstallOriginalNativeCleanupDeleteAPI(t, f.owner.Client.(*kubefake.Clientset), exit)
	candidate, err := f.service.cleanupOriginalPublicationCandidate(ctx, *claim, capture.Input.CaptureAttemptNo, store, exit)
	if err != nil {
		t.Fatal("original candidate cleanup", err)
	}
	resources, err := f.service.cleanupOriginalPublicationNativeResources(ctx, candidate)
	if err != nil || *deletes != 3 {
		t.Fatal("original native cleanup", err)
	}
	complete, err := f.service.cleanupOriginalPublicationLocal(ctx, resources)
	if err != nil || complete == nil {
		t.Fatal("actual original SQL gated local cleanup", err)
	}
	if len(complete.seals) != 2*len(capture.Parts) {
		t.Fatal("container-internal original seals omitted")
	}
	custody, err := openPublicationLocalCustody(f.owner.Staging)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	if !publicationLocalFilesAbsent(f.owner.Staging, custody, f.publicID, complete.seals) {
		t.Fatal("actual owned directory/seals survived")
	}
	var state, result, status string
	var version uint64
	var usable bool
	if f.control.QueryRowContext(ctx, `SELECT lifecycle,cleanup_result,row_version FROM system_backup_v2_staging_resources WHERE public_id=?`, complete.intent.Owner.Resource).Scan(&state, &result, &version) != nil || state != "deleted" || result != "succeeded" || version != complete.intent.RowVersion+3 {
		t.Fatal("original104 CAS chain missing", state, result, version)
	}
	if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable) != nil || status != "publishing" || usable {
		t.Fatal("cleanup promoted terminal state")
	}
	oldClaim := complete.native.candidate.exit.claim
	fresh, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Renew(ctx, *claim, policy)
	if err != nil {
		t.Fatal("explicit finalization token", err)
	}
	*claim = fresh
	proof, err := f.service.verifyOriginalPublicationFinalization(ctx, claim, policy, complete)
	if err != nil || proof == nil {
		t.Fatal("actual current final opener with authenticated Team/Skills relations", err)
	}
	if complete.native.candidate.exit.claim != oldClaim || complete.intent.Claim != oldClaim || claim.RowVersion <= oldClaim.RowVersion || proof.claim != *claim {
		t.Fatal("old cleanup token adopted or current token was not renewed")
	}
	originalParts := proof.skillParts
	proof.skillParts = proof.skillParts[:len(proof.skillParts)-1]
	if err := proof.recheckVerifiedTx(ctx, nil); err == nil {
		t.Fatal("mutated verified member set accepted")
	}
	proof.skillParts = originalParts
	tx, err := f.control.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkErr := proof.recheckVerifiedTx(ctx, tx)
	_ = tx.Rollback()
	if checkErr != nil {
		t.Fatal("actual current final consumer transaction", checkErr)
	}
	if !publicationLocalFilesAbsent(f.owner.Staging, custody, f.publicID, complete.seals) {
		t.Fatal("final verifier recreated deleted seal/task payload")
	}
	if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable) != nil || status != "publishing" || usable {
		t.Fatal("read verifier promoted terminal state")
	}

	return proof
}

// Commit a registry-only Unwrap invalidation AFTER actual full remote C. The
// signed owner mapping/capability material is deliberately unchanged. These
// are explicit mutations in the exclusively owned SQL fixture, not an owner
// authorization implementation or a provider-absence claim.
func TestPublicationAcceptanceCurrentUnwrapRevocationMySQL(t *testing.T) {
	for _, phase := range []string{"prepared", "signed", "published"} {
		t.Run(phase, func(t *testing.T) {
			var signer *aSameTaskCertificateMaterials
			runAOriginalSixPartManifestUploadJobWithHooks(t, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, store *nativePublicationS3, native *aNativePublicationServer) {
				proof := publicationOriginalFinalForTest(ctx, t, f, claim, capture, store, native)
				// The shared gate must work in a truly read-only transaction: no
				// registry Bind INSERT IGNORE, nested tx, KMS or provider request.
				checkCurrent := func() error {
					tx, err := f.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
					if err != nil {
						return err
					}
					defer tx.Rollback()
					_, _, err = acceptanceRecoveryFactsTx(ctx, tx, proof)
					return err
				}
				if err := checkCurrent(); err != nil {
					t.Fatal("healthy read-only current gate", err)
				}
				before := signer.signs.Load()
				prepared, err := f.service.prepareOriginalPublicationAcceptance(ctx, proof)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				var signed *publicationSignedAcceptance
				var accepted *publicationAcceptedObject
				if phase != "prepared" {
					signed, err = prepared.SignCommitted(ctx)
					if err != nil || signed == nil {
						t.Fatal("actual original pre-revocation Sign", err)
					}
				}
				if phase == "published" {
					accepted, err = f.service.publishOriginalPublicationAcceptance(ctx, signed)
					if err != nil || accepted == nil {
						t.Fatal("actual original pre-revocation full acceptance read", err)
					}
				}
				binding := f.service.publisherVerifier.Binding
				owner, signature, err := (a.SQLOriginalReader{}).RecheckOriginal(ctx, f.db, binding.InstallationID, binding.ConfigRef)
				if err != nil {
					t.Fatal(err)
				}
				// A genuine current row-version/epoch advance for Generate only
				// must retain exact historical-artifact Unwrap eligibility.
				generate := reg.Revocation{Purpose: reg.GenerateRevocation, Source: reg.SourceRecord{SourceID: "owned-fixture-registry-observer", RecordID: "original-generate-invalidation", RecordVersion: "r2", ContentSHA256: hash([]byte("owned generate revocation DATA"))}, SourceRevision: "r2", ObservedAt: time.Now().UTC().Add(-time.Millisecond)}
				generateRaw, _ := json.Marshal(generate)
				generateTx, err := f.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer generateTx.Rollback()
				generateResult, err := generateTx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?`, binding.InstallationID)
				if err != nil || publicationOneRow(generateResult) != nil {
					t.Fatal("owned Generate fence invalidation", err)
				}
				generateResult, err = generateTx.ExecContext(ctx, `UPDATE system_backup_v2_kek_bindings SET generate_revocation_json=?,row_version=row_version+1 WHERE installation_id=? AND identity_hash=? AND registry_version=? AND generate_revocation_json IS NULL`, generateRaw, binding.InstallationID, binding.Key.IdentityHash, binding.Key.RegistryVersion)
				if err != nil || publicationOneRow(generateResult) != nil {
					t.Fatal("owned exact Generate invalidation", err)
				}
				if err = generateTx.Commit(); err != nil {
					t.Fatal(err)
				}
				if err = checkCurrent(); err != nil {
					t.Fatal("Generate-only revocation blocked retained Unwrap in read-only gate", err)
				}
				revocation := reg.Revocation{Purpose: reg.UnwrapRevocation, Source: reg.SourceRecord{SourceID: "owned-fixture-registry-observer", RecordID: "original-unwrap-invalidation", RecordVersion: "r2", ContentSHA256: hash([]byte("owned revocation source DATA"))}, SourceRevision: "r2", ObservedAt: time.Now().UTC().Add(-time.Millisecond)}
				raw, _ := json.Marshal(revocation)
				tx, err := f.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?`, binding.InstallationID)
				if err != nil || publicationOneRow(result) != nil {
					t.Fatal("owned original fence invalidation", err)
				}
				result, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_bindings SET unwrap_revocation_json=?,row_version=row_version+1 WHERE installation_id=? AND identity_hash=? AND registry_version=? AND unwrap_revocation_json IS NULL`, raw, binding.InstallationID, binding.Key.IdentityHash, binding.Key.RegistryVersion)
				if err != nil || publicationOneRow(result) != nil {
					t.Fatal("owned exact registry Unwrap invalidation", err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				afterOwner, afterSig, err := (a.SQLOriginalReader{}).RecheckOriginal(ctx, f.db, binding.InstallationID, binding.ConfigRef)
				if err != nil || !bytes.Equal(owner, afterOwner) || !bytes.Equal(signature, afterSig) {
					t.Fatal("test changed signed mapping instead of independent registry", err)
				}
				if err = checkCurrent(); err == nil {
					t.Fatal("read-only gate ignored committed Unwrap revocation")
				}
				if p, err := f.service.prepareOriginalPublicationAcceptance(ctx, proof); err == nil || p != nil {
					t.Fatal("prepare ignored current Unwrap revocation", err)
				}
				if p, err := prepared.SignCommitted(ctx); err == nil || p != nil {
					t.Fatal("send/result recovery ignored current Unwrap revocation", err)
				}
				if signed != nil {
					if p, err := f.service.publishOriginalPublicationAcceptance(ctx, signed); err == nil || p != nil {
						t.Fatal("publish ignored current Unwrap revocation", err)
					}
				}
				if accepted != nil {
					tx, err := f.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
					if err != nil {
						t.Fatal(err)
					}
					check := accepted.recheckTx(ctx, tx)
					_ = tx.Rollback()
					if check == nil {
						t.Fatal("typed consumer ignored current Unwrap revocation")
					}
				}
				wantSigns := before
				if phase != "prepared" {
					wantSigns++
				}
				if signer.signs.Load() != wantSigns {
					t.Fatal("revocation caused another provider Sign", signer.signs.Load(), wantSigns)
				}
				native.mu.Lock()
				puts := native.puts
				native.mu.Unlock()
				wantPuts := 18
				if phase == "published" {
					wantPuts++
				}
				if puts != wantPuts {
					t.Fatal("revocation allowed another PUT", puts, wantPuts)
				}
				var status string
				var usable, eligible bool
				if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable,acceptance_eligible FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable, &eligible) != nil || status != "publishing" || usable || eligible {
					t.Fatal("revocation promoted terminal state", status, usable, eligible)
				}
			}, &aOriginalPublicationUploadHooks{SigningFixture: func(f *aSameTaskCertificateMaterials) { signer = f }}, func(store *nativePublicationS3, native *aNativePublicationServer) {
				key := nativePublicationCredential{AccessKey: "acceptance-revoke-delete-only", SecretKey: strings.Repeat("d", 32), NotBefore: time.Now().Add(-time.Minute), Until: native.deadline}
				raw, _ := json.Marshal(key)
				file := filepath.Join(filepath.Dir(store.config.ReadCredentialFile), "acceptance-revoke-delete.json")
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				store.config.DeleteIdentityHash, store.config.DeleteRefVersion = hash([]byte("acceptance revoke exact delete DATA")), "acceptance-revoke-delete-v1"
				store.config.DeleteCredentialFile, store.config.DeleteCredentialSHA256 = file, hash(raw)
				native.remove = key
			})
		})
	}
}
