package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Same original eleven-member capture and REAL upload-only worker/result
// receiver from A, then D's actual production post-upload bridge. No C receipt,
// signing authority, task status or observed object version is manufactured.
func TestDOriginalUploadedManifestThroughRemoteCAnd102MySQL(t *testing.T) {
	runDOriginalUploadedManifestThroughRemoteCAnd102(t, false)
}

func TestDOriginalUploadedManifestAndCommittedMarkerMySQL(t *testing.T) {
	runDOriginalUploadedManifestThroughRemoteCAnd102(t, true)
}

func TestDOriginalUploadedManifestMarkerAndUploadExitMySQL(t *testing.T) {
	runDOriginalUploadedManifestThroughRemoteCAnd102(t, true, true)
}

func TestDOriginalUploadedManifestMarkerAndCandidateCleanupMySQL(t *testing.T) {
	runDOriginalUploadedManifestThroughRemoteCAnd102(t, true, true, true)
}

func runDOriginalUploadedManifestThroughRemoteCAnd102(t *testing.T, withMarker bool, withExit ...bool) {
	var configure []func(*nativePublicationS3, *aNativePublicationServer)
	if len(withExit) == 2 && withExit[1] {
		configure = append(configure, func(store *nativePublicationS3, native *aNativePublicationServer) {
			deleteKey := nativePublicationCredential{AccessKey: "original-candidate-delete-only-local", SecretKey: strings.Repeat("d", 32), NotBefore: time.Now().Add(-time.Minute), Until: native.deadline}
			raw, _ := json.Marshal(deleteKey)
			file := filepath.Join(filepath.Dir(store.config.ReadCredentialFile), "candidate-delete.json")
			if os.WriteFile(file, raw, 0600) != nil {
				t.Fatal("local independent delete credential fixture")
			}
			store.config.DeleteIdentityHash = hash([]byte("original candidate exact delete identity"))
			store.config.DeleteRefVersion = "original-delete-v1"
			store.config.DeleteCredentialFile = file
			store.config.DeleteCredentialSHA256 = hash(raw)
			native.remove = deleteKey
		})
	}
	runAOriginalSixPartManifestUploadJob(t, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, store *nativePublicationS3, native *aNativePublicationServer) {
		if len(withExit) == 2 && withExit[1] {
			native.candidateDeleteKey = "/" + store.config.Bucket + "/" + store.config.RemoteStagingRoot + f.publicID + "/1/manifest-candidate.json"
		}
		var ranges atomic.Int32
		native.onRead = func(dst http.ResponseWriter, request *http.Request) bool {
			value := request.Header.Get("Range")
			if value == "" {
				return false
			}
			ranges.Add(1)
			bounds, ok := strings.CutPrefix(value, "bytes=")
			left, right, cut := strings.Cut(bounds, "-")
			start, e1 := strconv.ParseInt(left, 10, 64)
			end, e2 := strconv.ParseInt(right, 10, 64)
			// serve holds the native fixture mutex while invoking onRead.
			raw := bytes.Clone(native.objects[request.URL.Path])
			if !ok || !cut || e1 != nil || e2 != nil || start < 0 || end < start || end >= int64(len(raw)) || request.URL.Query().Get("versionId") != "original-v1" {
				http.Error(dst, "invalid original native Range", 403)
				return true
			}
			dst.Header().Set("x-amz-version-id", "original-v1")
			dst.Header().Set("Content-Range", "bytes "+left+"-"+right+"/"+strconv.Itoa(len(raw)))
			dst.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			dst.WriteHeader(206)
			_, _ = dst.Write(raw[start : end+1])
			return true
		}
		before := *claim
		policy := aOriginalPublicationFixturePolicy(t, f)
		object, err := f.service.completeOriginalPublicationUploadedManifest(ctx, claim, capture.Input.CaptureAttemptNo, policy, store, capture)
		if err != nil || object.receipt == nil || object.Key != store.config.Root+f.publicID+"/1/manifest.json" || ranges.Load() != 16 || claim.RowVersion <= before.RowVersion {
			t.Fatal("actual current C to original102 manifest", err, ranges.Load())
		}
		var status, state, kind string
		var canCancel, usable bool
		var committed sql.NullTime
		var sends, actions int
		if f.control.QueryRowContext(ctx, `SELECT status,can_cancel,commit_started_at,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &canCancel, &committed, &usable) != nil || status != "publishing" || canCancel || !committed.Valid || usable {
			t.Fatal("manifest stage changed terminal/eligibility contract", status, canCancel, usable)
		}
		if f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?`, f.publicID).Scan(&actions) != nil || actions != 1 || f.control.QueryRowContext(ctx, `SELECT action_type,state,send_attempt_count FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?`, f.publicID).Scan(&kind, &state, &sends) != nil || kind != "manifest_put" || state != "confirmed_present" || sends != 1 {
			t.Fatal("original102 one-send manifest not retained", kind, state, sends, actions)
		}
		tx, err := f.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		if err = object.recheckPublicationReceiptTx(ctx, tx, *claim); err != nil {
			tx.Rollback()
			t.Fatal("real complete-body manifest receipt current TX", err)
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		native.mu.Lock()
		puts := native.puts
		native.mu.Unlock()
		if puts != 17 {
			t.Fatal("expected fifteen objects,candidate and exactly one manifest PUT", puts)
		}
		t.Log("same original upload claim DATA closed before C Renew; latest actual claim consumed in102; full C16 ranges; one immutable manifest with full readback; no marker/acceptance/catalog/cleanup/terminal success", f.publicID)
		if withMarker {
			foreign := &nativePublicationS3{config: store.config}
			foreign.config.Root += "foreign/"
			if denied, err := f.service.publishOriginalCommittedMarkerAfterManifest(ctx, *claim, capture.Input.CaptureAttemptNo, foreign, object); err == nil || denied.Key != "" {
				t.Fatal("foreign marker target adopted real manifest receipt", err)
			}
			marker, err := f.service.publishOriginalCommittedMarkerAfterManifest(ctx, *claim, capture.Input.CaptureAttemptNo, store, object)
			if err != nil || marker.receipt == nil || marker.Key != store.config.Root+f.publicID+"/1/_COMMITTED" {
				t.Fatal("actual typed MF to marker102", err)
			}
			native.mu.Lock()
			puts = native.puts
			native.mu.Unlock()
			if puts != 18 || f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=? AND action_type IN ('manifest_put','marker_put') AND state='confirmed_present' AND send_attempt_count=1`, f.publicID).Scan(&actions) != nil || actions != 2 {
				t.Fatal("original manifest/marker one-send actions", puts, actions)
			}
			if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable) != nil || status != "publishing" || usable {
				t.Fatal("marker changed terminal/eligibility contract", status, usable)
			}
			t.Log("same real original C-gated manifest receipt consumed for exact v12 _COMMITTED; parent/current SQL rechecked; no acceptance/catalog/cleanup/terminal success", f.publicID)
			if len(withExit) > 0 && withExit[0] {
				exit, err := f.service.observeOriginalPublicationUploadExit(ctx, *claim, capture.Input.CaptureAttemptNo, marker)
				if err != nil || exit == nil || len(exit.pods) != 1 || exit.process.Pod.UID == "" {
					t.Fatal("actual returned upload/result invocation to current SQL kubelet exit", err)
				}
				var proofs int
				if f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=?`, f.publicID, exit.process.Pod.UID).Scan(&proofs) != nil || proofs != 1 {
					t.Fatal("original kubelet stop proof missing")
				}
				t.Log("same first authenticated107 Pod/container/node identity explicitly exited after real local upload/result invocation returned; actual current marker consumer persisted stop witness; no cleanup/acceptance/catalog/terminal success", f.publicID)
				if len(withExit) == 2 && withExit[1] {
					cleaned, err := f.service.cleanupOriginalPublicationCandidate(ctx, *claim, capture.Input.CaptureAttemptNo, store, exit)
					if err != nil || cleaned == nil || !cleaned.deleted {
						t.Fatal("actual original104 -> one dedicated DELETE -> fixed-version absence -> deleted", err)
					}
					native.mu.Lock()
					deletes, objects := native.deletes, len(native.objects)
					native.mu.Unlock()
					var lifecycle, result, version string
					if deletes != 1 || objects != 17 || f.control.QueryRowContext(ctx, `SELECT lifecycle,cleanup_result,immutable_version FROM system_backup_v2_staging_resources WHERE public_id=?`, exit.material.CandidateResource).Scan(&lifecycle, &result, &version) != nil || lifecycle != "deleted" || result != "succeeded" || version != cleaned.object.Version {
						t.Fatal("remote candidate cleanup did not retain original exact version", deletes, objects, lifecycle, result)
					}
					t.Log("actual original uploader exit receipt consumed by dedicated artifact_delete; one fixed original-version DELETE, independent NoSuchVersion and original104 deleted; remaining payload/Job/Secret cleanup and signed acceptance/catalog/terminal remain incomplete", f.publicID)
				}
			}
			fresh, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Renew(ctx, *claim, policy)
			if err != nil {
				t.Fatal("actual next claim transition for stale-parent negative", err)
			}
			*claim = fresh
			if len(withExit) > 0 && withExit[0] {
				if denied, err := f.service.observeOriginalPublicationUploadExit(ctx, *claim, capture.Input.CaptureAttemptNo, marker); err == nil || denied != nil {
					t.Fatal("old marker/process receipt adopted actual renewed claim", err)
				}
			}
			if denied, err := f.service.publishOriginalCommittedMarkerAfterManifest(ctx, *claim, capture.Input.CaptureAttemptNo, store, object); err == nil || denied.Key != "" {
				t.Fatal("old manifest/C completion adopted renewed claim", err)
			}
			native.mu.Lock()
			puts = native.puts
			native.mu.Unlock()
			if puts != 18 {
				t.Fatal("denied stale-parent marker repeated a send", puts)
			}
		}
	}, configure...)
}
