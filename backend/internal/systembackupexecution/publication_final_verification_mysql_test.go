package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Same original capture, native upload, complete fixed-version C, manifest,
// marker and real SQL dispatches. The local Kube/S3 transports are fixtures;
// this is not a real-page or production success/acceptance demonstration.
func TestPublicationFinalVerificationAfterDeletedStageMySQL(t *testing.T) {
	runAOriginalSixPartManifestUploadJob(t, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, store *nativePublicationS3, native *aNativePublicationServer) {
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
		native.mu.Lock()
		puts := native.puts
		native.mu.Unlock()
		if puts != 18 {
			t.Fatal("final verifier sent an artifact request", puts)
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
