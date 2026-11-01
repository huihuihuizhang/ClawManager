package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Typed transport/Job DATA only. No current SQL, native content read receipt,
// publication grant or acceptance can be created by this consistency check.
func TestOriginalUploadCompletionRequiresNativeExitAndEveryTypedResultData(t *testing.T) {
	for _, mode := range []string{"complete", "no-results-yet", "partial-running", "results-without-exit", "exit-missing-results", "failed", "foreign-job", "changed-generation", "suspended", "deleted", "foreign-result", "result-order", "candidate-drift", "wrong-cursor", "wrong-request-hash"} {
		t.Run(mode, func(t *testing.T) {
			request, _, _ := publicationContainerRequestData(t)
			raw, _ := json.Marshal(request)
			sha := hash(raw)
			no := false
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{UID: types.UID("original-data-job"), Generation: 2}, Spec: batchv1.JobSpec{Suspend: &no}, Status: batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}}
			prefix := request.ArtifactRoot + request.Backup + "/" + strconv.FormatUint(request.Attempt, 10) + "/"
			messages := []publicationResultMessage{}
			for i, object := range request.Objects {
				messages = append(messages, publicationResultMessage{Version: publicationResultVersion, Installation: request.Installation, Backup: request.Backup, Attempt: request.Attempt, RequestSHA256: sha, Sequence: uint64(i + 1), Object: PublicationUploadObservation{Key: prefix + object.Path, Version: "fixed-native-v1", SHA256: object.SHA256, Bytes: object.Bytes}})
			}
			manifest, candidate, err := request.validate()
			if err != nil {
				t.Fatal(err)
			}
			messages = append(messages, publicationResultMessage{Version: publicationResultVersion, Installation: request.Installation, Backup: request.Backup, Attempt: request.Attempt, RequestSHA256: sha, Sequence: uint64(len(messages) + 1), Object: PublicationUploadObservation{Key: candidate, Version: "fixed-native-v1", SHA256: hash(manifest), Bytes: int64(len(manifest))}})
			sequence, status := uint64(len(messages)), "upload_candidate"
			switch mode {
			case "no-results-yet":
				messages = nil
				sequence = 0
				status = ""
				job.Status = batchv1.JobStatus{}
			case "partial-running":
				messages = messages[:3]
				sequence = 3
				status = "upload_objects"
				job.Status = batchv1.JobStatus{}
			case "results-without-exit":
				job.Status = batchv1.JobStatus{}
			case "exit-missing-results":
				messages = messages[:3]
				sequence = 3
				status = "upload_objects"
			case "failed":
				job.Status.Failed = 1
			case "foreign-job":
				job.UID = "foreign-job"
			case "changed-generation":
				job.Generation++
			case "suspended":
				yes := true
				job.Spec.Suspend = &yes
			case "deleted":
				at := metav1.Now()
				job.DeletionTimestamp = &at
			case "foreign-result":
				messages[0].Backup = "sbk_foreign"
			case "result-order":
				messages[0].Sequence++
			case "candidate-drift":
				messages[len(messages)-1].Object.SHA256 = hash([]byte("changed candidate"))
			case "wrong-cursor":
				status = "upload_objects"
			case "wrong-request-hash":
				sha = hash([]byte("other request"))
			}
			complete, err := publicationUploadCompletion(request, sha, "original-data-job", 2, job, sequence, status, messages)
			switch mode {
			case "complete":
				if err != nil || !complete {
					t.Fatal("complete original typed result/exit DATA rejected", err)
				}
			case "no-results-yet", "partial-running", "results-without-exit":
				if err != nil || complete {
					t.Fatal("pending upload became completed", mode, err)
				}
			case "exit-missing-results":
				if !errors.Is(err, ErrPublicationUploadMissingResults) || complete {
					t.Fatal(err)
				}
			case "failed":
				if !errors.Is(err, ErrPublicationUploadFailed) || complete {
					t.Fatal(err)
				}
			default:
				if err == nil || complete {
					t.Fatal("foreign/incomplete upload DATA accepted", mode)
				}
			}
		})
	}
}

func TestOriginalUploadWaitUsesShortestOriginalDeadlineData(t *testing.T) {
	for _, mode := range []string{"certificate", "claim", "material", "request", "foreign-certificate", "missing-certificate"} {
		t.Run(mode, func(t *testing.T) {
			request, _, _ := publicationContainerRequestData(t)
			base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
			material, claim := base.Add(50*time.Second), base.Add(40*time.Second)
			request.Deadline = base.Add(time.Minute)
			var envelope originalCaptureCertificateEnvelope
			json.Unmarshal(request.CaptureCertificate, &envelope)
			var cert publicationCaptureCertificatePayload
			json.Unmarshal(envelope.Payload, &cert)
			cert.ExpiresAt = base.Add(30 * time.Second)
			want := cert.ExpiresAt
			switch mode {
			case "claim":
				claim = base.Add(20 * time.Second)
				want = claim
			case "material":
				material = base.Add(10 * time.Second)
				want = material
			case "request":
				request.Deadline = base.Add(5 * time.Second)
				want = request.Deadline
			case "foreign-certificate":
				cert.Backup = "sbk_other"
			}
			envelope.Payload, _ = ce.Canonical(cert)
			request.CaptureCertificate, _ = ce.Canonical(envelope)
			if mode == "missing-certificate" {
				request.CaptureCertificate = nil
			}
			got, err := originalPublicationUploadDeadline(request, material, claim)
			if mode == "foreign-certificate" || mode == "missing-certificate" {
				if err == nil {
					t.Fatal("unbound deadline accepted")
				}
				return
			}
			if err != nil || !got.Equal(want) {
				t.Fatal("an original upload window was extended", mode, got, want, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var service *DeploymentService
	if err := service.awaitOriginalPublicationUpload(ctx, c.ClaimToken{}, 1, PublicationTargetMaterials{}, time.Second, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel did not stop before touching SQL/native/material", err)
	}
}

func originalUploadPollFixtureData(t *testing.T) publicationUploadPollData {
	t.Helper()
	request, _, _ := publicationContainerRequestData(t)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	sha := hash(raw)
	no := false
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{UID: types.UID("original-poll-data-job"), Generation: 2}, Spec: batchv1.JobSpec{Suspend: &no}, Status: batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}}
	prefix := request.ArtifactRoot + request.Backup + "/" + strconv.FormatUint(request.Attempt, 10) + "/"
	var messages []publicationResultMessage
	for i, object := range request.Objects {
		messages = append(messages, publicationResultMessage{Version: publicationResultVersion, Installation: request.Installation, Backup: request.Backup, Attempt: request.Attempt, RequestSHA256: sha, Sequence: uint64(i + 1), Object: PublicationUploadObservation{Key: prefix + object.Path, Version: "fixed-native-poll-data", SHA256: object.SHA256, Bytes: object.Bytes}})
	}
	manifest, candidate, err := request.validate()
	if err != nil {
		t.Fatal(err)
	}
	messages = append(messages, publicationResultMessage{Version: publicationResultVersion, Installation: request.Installation, Backup: request.Backup, Attempt: request.Attempt, RequestSHA256: sha, Sequence: uint64(len(messages) + 1), Object: PublicationUploadObservation{Key: candidate, Version: "fixed-native-poll-data", SHA256: hash(manifest), Bytes: int64(len(manifest))}})
	return publicationUploadPollData{Request: request, RequestSHA: sha, JobUID: string(job.UID), Generation: job.Generation, Job: job, Cursor: publicationUploadCursor{Sequence: uint64(len(messages)), Status: sql.NullString{String: "upload_candidate", Valid: true}}, Messages: messages}
}

// These are local typed observation/control-flow counterexamples. No fake
// current-SQL authority or C receipt is returned by the observation callback.
// The loop exposes no Create/Patch, grant, claim renewal or release operation.
func TestOriginalUploadPollStopsWithinOriginalWindowData(t *testing.T) {
	for _, mode := range []string{"pending-then-complete", "cancel-during-read", "cancel-between-reads", "claim-lost", "already-expired", "expires-during-read", "expires-between-reads", "unknown-send-ack", "unknown-read", "complete-missing-results", "failed-job", "invalid-data", "known-send-failure"} {
		t.Run(mode, func(t *testing.T) {
			complete := originalUploadPollFixtureData(t)
			pending := complete
			pending.Job = complete.Job.DeepCopy()
			pending.Job.Status = batchv1.JobStatus{}
			pending.Cursor = publicationUploadCursor{}
			pending.Messages = nil
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			until := time.Now().Add(2 * time.Second)
			var sendErr, want error
			wantReads := 1
			switch mode {
			case "pending-then-complete", "unknown-read":
				wantReads = 2
			case "cancel-during-read", "cancel-between-reads":
				want = context.Canceled
			case "claim-lost":
				want, wantReads = c.ErrClaimLost, 2
			case "already-expired":
				until, want, wantReads = time.Now().Add(-time.Second), ErrPublicationUploadWindowClosed, 0
			case "expires-during-read", "expires-between-reads":
				until, want = time.Now().Add(30*time.Millisecond), ErrPublicationUploadWindowClosed
			case "unknown-send-ack":
				sendErr = ErrJobUncertain
			case "complete-missing-results":
				want = ErrPublicationUploadMissingResults
			case "failed-job":
				want = ErrPublicationUploadFailed
			case "invalid-data":
				want = c.ErrExecutionRecord
			case "known-send-failure":
				sendErr, want, wantReads = c.ErrExecutionAuthority, c.ErrExecutionAuthority, 0
			}
			reads := 0
			started := time.Now()
			err := pollOriginalPublicationUpload(ctx, until, 100*time.Millisecond, sendErr, func(observationCtx context.Context) (publicationUploadPollData, error) {
				reads++
				deadline, ok := observationCtx.Deadline()
				if !ok || !deadline.Equal(until) {
					t.Fatal("poll changed original shortest window", deadline, until)
				}
				switch mode {
				case "cancel-during-read":
					cancel()
				case "cancel-between-reads":
					timer := time.AfterFunc(10*time.Millisecond, cancel)
					t.Cleanup(func() { timer.Stop() })
					return pending, nil
				case "expires-during-read":
					<-observationCtx.Done()
				case "expires-between-reads":
					return pending, nil
				case "claim-lost":
					if reads == 2 {
						return publicationUploadPollData{}, c.ErrClaimLost
					}
					return pending, nil
				case "pending-then-complete":
					if reads == 1 {
						return pending, nil
					}
				case "unknown-read":
					if reads == 1 {
						return publicationUploadPollData{}, ErrJobUncertain
					}
				case "complete-missing-results":
					complete.Cursor, complete.Messages = publicationUploadCursor{}, nil
				case "failed-job":
					complete.Job.Status.Failed = 1
				case "invalid-data":
					complete.RequestSHA = hash([]byte("foreign request"))
				}
				return complete, nil
			})
			if want == nil && err != nil || want != nil && !errors.Is(err, want) || reads != wantReads {
				t.Fatal("wrong poll outcome/count", mode, err, want, reads, wantReads)
			}
			if time.Since(started) > time.Second {
				t.Fatal("poll did not stop promptly", mode)
			}
		})
	}
}
