package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	"github.com/google/uuid"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kt "k8s.io/client-go/testing"
)

type aPublicationReceiveSnapshot struct {
	Sequence, RowVersion uint64
	Evidence             int
}

func aPublicationReceiveState(t *testing.T, f *aPublicationMaterialFixture) aPublicationReceiveSnapshot {
	t.Helper()
	var state aPublicationReceiveSnapshot
	h := f.x.history
	if h.admin.QueryRow(`SELECT last_accepted_sequence,row_version FROM system_backup_v2_job_observations WHERE target_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&state.Sequence, &state.RowVersion) != nil || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?`, h.original.TaskPublicID).Scan(&state.Evidence) != nil {
		t.Fatal("original receive cursor/evidence unavailable")
	}
	return state
}

// Real local mTLS HTTP plus TokenReview/current native Pod and original SQL.
// Opaque native versions are inert transport DATA; the provider is intentionally
// not contacted, and no artifact/finalization/terminal success is asserted.
func TestPublicationAuthenticatedResultOriginal107CursorAndRefusalMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"current-and-duplicate", "part-latest", "candidate-latest", "token-denied", "wrong-audience", "wrong-service-account", "wrong-pod-uid", "foreign-job-owner", "wrong-certificate", "107-generation-drift", "claim-released", "publish-attempt-failed", "original-expired", "receipt-commit-ack-lost"} {
		t.Run(mode, func(t *testing.T) {
			boundary := &aStageCommitBoundary{}
			f := newAPublicationMaterialFixtureControl(t, true, func(conn driver.Connector) driver.Connector { return aPublicationReceiveConnector{conn, boundary} })
			aPublicationActualObservationDDL(t, f)
			patches := aPublicationNativeJobAPI(t, f, "current")
			h, ctx := f.x.history, context.Background()
			job, err := h.service.ensureStartedPublicationJob(ctx, h.token, 1, f.store.config, f.request)
			if err != nil {
				t.Fatal("original started publication Job", err)
			}
			m, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, PublicationUploadRequest{})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			yes := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: job.Namespace, Name: job.Name + "-worker", UID: types.UID(uuid.NewString()), Labels: job.Spec.Template.Labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
			aOriginalPublicationRunningPod(t, f.client, h.service.Config, pod)
			if mode == "foreign-job-owner" {
				pod.OwnerReferences[0].UID = types.UID(uuid.NewString())
			}
			if err = f.client.Tracker().Add(pod); err != nil {
				t.Fatal(err)
			}
			tokenReviews := 0
			f.client.PrependReactor("create", "tokenreviews", func(action kt.Action) (bool, runtime.Object, error) {
				tokenReviews++
				review := action.(kt.CreateAction).GetObject().(*authv1.TokenReview)
				if review.Spec.Token != "actual-publication-bound-token" || len(review.Spec.Audiences) != 1 || review.Spec.Audiences[0] != kube.WorkerTokenAudience {
					t.Fatal("result did not use its actual dedicated-audience token")
				}
				review.Status = authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{kube.WorkerTokenAudience}, User: authv1.UserInfo{Username: "system:serviceaccount:" + pod.Namespace + ":" + h.service.Config.PublicationWorker.ServiceAccountName, UID: h.service.Config.PublicationWorker.ServiceAccountUID, Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}}
				switch mode {
				case "token-denied":
					review.Status.Authenticated = false
				case "wrong-audience":
					review.Status.Audiences = []string{"other"}
				case "wrong-service-account":
					review.Status.User.UID = "other-upload-sa"
				case "wrong-pod-uid":
					review.Status.User.Extra["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue{uuid.NewString()}
				}
				return true, review, nil
			})
			h.service.Runtime.Control = http.NotFoundHandler()
			f.resultHandler = h.service.controlHandler()
			pair, err := tls.X509KeyPair(m.secret.Data["tls.crt"], m.secret.Data["tls.key"])
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong-certificate" {
				other, err := h.owner.Issuer.IssueWorker(m.intent.Backup, m.intent.Deadline, strings.Repeat("f", 64))
				if err != nil {
					t.Fatal(err)
				}
				pair, err = tls.X509KeyPair(other.Data["tls.crt"], other.Data["tls.key"])
				other.Clear()
				if err != nil {
					t.Fatal(err)
				}
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(m.secret.Data["ca.crt"]) {
				t.Fatal("original server roots")
			}
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			post := func(message publicationResultMessage) int {
				t.Helper()
				aRefreshPublicationPayloadCapacity(t, f.x)
				body, _ := ce.Canonical(message)
				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.resultURL+PublicationResultPath, bytes.NewReader(body))
				request.Header.Set("Authorization", "Bearer actual-publication-bound-token")
				request.Header.Set("Content-Type", "application/json")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal("actual controlled result HTTP", err)
				}
				io.Copy(io.Discard, io.LimitReader(response.Body, 1025))
				response.Body.Close()
				return response.StatusCode
			}
			messageFor := func(sequence uint64) publicationResultMessage {
				message := publicationResultMessage{Version: publicationResultVersion, Installation: m.intent.Installation, Backup: m.intent.Backup, Attempt: 1, RequestSHA256: m.intent.RequestSHA256, Sequence: sequence}
				if sequence <= uint64(len(m.request.Objects)) {
					o := m.request.Objects[sequence-1]
					message.Object = PublicationUploadObservation{Key: m.request.ArtifactRoot + m.request.Backup + "/1/" + o.Path, SHA256: o.SHA256, Bytes: o.Bytes, Version: "actual-opaque-fixed-version"}
				} else {
					manifest, key, _ := m.request.validate()
					message.Object = PublicationUploadObservation{Key: key, SHA256: hash(manifest), Bytes: int64(len(manifest)), Version: "actual-opaque-candidate-version"}
				}
				return message
			}
			message := messageFor(1)
			var priorExpiry *aPublicationReceiveSnapshot
			if mode == "original-expired" {
				// Establish this same real TLS connection and token/Pod path
				// while the original certificate/window is healthy. Keepalive
				// then exercises fresh handler expiry rather than TLS setup.
				if status := post(message); status != 204 {
					t.Fatal("healthy authenticated receipt before real expiry", status)
				}
				state := aPublicationReceiveState(t, f)
				if state.Sequence != 1 {
					t.Fatal("healthy pre-expiry cursor missing")
				}
				priorExpiry = &state
				message = messageFor(2)
			}
			if mode == "candidate-latest" {
				for sequence := uint64(1); sequence <= uint64(len(m.request.Objects)); sequence++ {
					if status := post(messageFor(sequence)); status != 204 {
						t.Fatal("original positive fixed-version part", sequence, status)
					}
				}
				message = messageFor(uint64(len(m.request.Objects) + 1))
			}
			if mode == "part-latest" || mode == "candidate-latest" {
				message.Object.Version = "latest"
			}
			if mode == "107-generation-drift" {
				result, err := h.admin.Exec(`UPDATE system_backup_v2_job_observations SET job_generation=3 WHERE phase='publish'`)
				if err != nil {
					t.Fatal(err)
				}
				var observed int64
				if count, err := result.RowsAffected(); err != nil || count != 1 || h.admin.QueryRow(`SELECT job_generation FROM system_backup_v2_job_observations WHERE phase='publish'`).Scan(&observed) != nil || observed != 3 {
					t.Fatal("independent original 107 generation drift did not happen")
				}
			}
			if mode == "claim-released" {
				if _, err = (c.ClaimCoordinator{Executor: h.admin, InstallationID: m.intent.Installation}).Release(ctx, h.token, time.Second); err != nil {
					t.Fatal(err)
				}
				var owner sql.NullString
				var rv uint64
				if h.admin.QueryRow(`SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, m.intent.Backup).Scan(&owner, &rv) != nil || owner.Valid || rv <= h.token.RowVersion {
					t.Fatal("independent actual Release effect absent")
				}
			}
			if mode == "publish-attempt-failed" {
				aPublicationFailRunningAttempt(t, f)
			}
			if mode == "original-expired" {
				if wait := time.Until(m.intent.Deadline) + 20*time.Millisecond; wait > 0 {
					time.Sleep(wait)
				}
			}
			if mode == "receipt-commit-ack-lost" {
				boundary.arm("publication-result", func() error {
					if state := aPublicationReceiveState(t, f); state.Sequence != 1 {
						t.Fatal("receipt SQL ACK lost before actual cursor commit")
					}
					return errAPublicationACKLost
				})
			}
			before := aPublicationReceiveState(t, f)
			if priorExpiry != nil && before != *priorExpiry {
				t.Fatal("original cursor/evidence changed during expiry wait")
			}
			status := post(message)
			positive := mode == "current-and-duplicate" || mode == "receipt-commit-ack-lost"
			if positive {
				want := 204
				if mode == "receipt-commit-ack-lost" {
					want = 503
				}
				if status != want {
					t.Fatal("actual original receipt", mode, status)
				}
				after := aPublicationReceiveState(t, f)
				if after.Sequence != before.Sequence+1 || after.RowVersion != before.RowVersion+1 || after.Evidence != before.Evidence+2 || post(message) != 204 || aPublicationReceiveState(t, f) != after {
					t.Fatal("duplicate/SQL ACK recovery rewrote cursor or evidence")
				}
				if mode == "current-and-duplicate" {
					for sequence := uint64(2); sequence <= uint64(len(m.request.Objects)+1); sequence++ {
						if status := post(messageFor(sequence)); status != 204 {
							t.Fatal("complete ordered fixed-version hints", sequence, status)
						}
					}
					if state := aPublicationReceiveState(t, f); state.Sequence != uint64(len(m.request.Objects)+1) {
						t.Fatal("candidate cursor missing")
					}
				}
			} else if status != 403 || aPublicationReceiveState(t, f) != before {
				t.Fatal("refused relay changed original cursor/evidence", mode, status)
			}
			if *patches != 1 || f.jobCreates != 1 || f.secretCreates != 1 || f.secretUpdates != 1 || f.provider.puts != 0 || f.provider.gets != 0 || f.provider.heads != 0 || f.x.logins.Load() != 0 || f.x.decrypts.Load() != 0 || tokenReviews == 0 {
				t.Fatal("result reception reached source/KMS/provider or resent native material")
			}
			var runtimePublish, terminal int
			if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE phase='publish'`).Scan(&runtimePublish) != nil || runtimePublish != 0 || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_backups WHERE status IN ('succeeded','failed','canceled')`).Scan(&terminal) != nil || terminal != 0 {
				t.Fatal("transport created capture runtime authority or terminal result")
			}
		})
	}
}
