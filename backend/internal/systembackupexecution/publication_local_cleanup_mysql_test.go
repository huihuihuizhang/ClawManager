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

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Same original capture, native upload, complete fixed-version C, manifest,
// marker and real SQL dispatches. The local Kube/S3 transports are fixtures;
// this is not a real-page or production success/acceptance demonstration.
func TestPublicationOriginalLocalCleanupSameTaskMySQL(t *testing.T) {
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
		again, err := f.service.cleanupOriginalPublicationLocal(ctx, resources)
		if err != nil || again == nil || again.evidence != complete.evidence || !bytes.Equal(again.body, complete.body) || *deletes != 3 {
			t.Fatal("query-only original cleanup readback", err)
		}
		// A lost deletion result with surviving payload grants observation only.
		// Explicit fixture state change, not a manufactured success receipt.
		if _, err = f.control.ExecContext(ctx, `UPDATE system_backup_v2_staging_resources SET lifecycle='deleting',cleanup_result='running',row_version=row_version-1 WHERE public_id=?`, complete.intent.Owner.Resource); err != nil {
			t.Fatal(err)
		}
		if err = f.owner.Staging.Mkdir(f.publicID, 0700); err != nil {
			t.Fatal(err)
		}
		residual, err := f.owner.Staging.OpenRoot(f.publicID)
		if err != nil {
			t.Fatal(err)
		}
		if err = residual.WriteFile("residual.enc", []byte("owned uncertain residual DATA"), 0600); err != nil {
			t.Fatal(err)
		}
		if denied, err := f.service.cleanupOriginalPublicationLocal(ctx, resources); err == nil || denied != nil {
			t.Fatal("uncertain deletion dispatched again")
		}
		if raw, err := residual.ReadFile("residual.enc"); err != nil || string(raw) != "owned uncertain residual DATA" {
			t.Fatal("query-only path removed residual", err)
		}
		_ = residual.Close()
		fresh, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Renew(ctx, *claim, policy)
		if err != nil {
			t.Fatal(err)
		}
		*claim = fresh
		if denied, err := f.service.cleanupOriginalPublicationLocal(ctx, resources); err == nil || denied != nil {
			t.Fatal("old cleanup adopted new claim")
		}
		if err = staging.WithCustodyLock(ctx, custody, func() error { return nil }); err != nil {
			t.Fatal("custody lock leaked", err)
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
