package systembackupapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	controller "clawreef/internal/systembackupcontroller"
	dispatch "clawreef/internal/systembackupdispatch"
	execution "clawreef/internal/systembackupexecution"
	read "clawreef/internal/systembackupread"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// SQL and encryption are real. Kubernetes is a controlled error boundary here;
// this does not establish live Job/Pod, remote pause or restore acceptance.
func TestExecutionJobLostCreateDoesNotSendTwice(t *testing.T) {
	db, w := submissionMySQL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p, err := w.Prepare(ctx, read.BackupTask, "createSystemBackup", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := p.Stage(realSubmissionSQL{ctx, tx, false}, TaskSubmissionIdentity{"installation_admission", "1", "createSystemBackup", "execution-jobs-001"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	queue := controller.SQLExecutionQueue{DB: db, InstallationID: "installation_admission", Owner: "controller-a", Policy: controller.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: time.Second}}
	claimed, err := queue.TakeBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := execution.NewPlanCipher("test-v1", map[string][]byte{"test-v1": bytes.Repeat([]byte{19}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	vault := execution.PlanStore{DB: db, InstallationID: queue.InstallationID, Cipher: cipher, CapacityReportFile: w.capacityFile}
	no := false
	zero := int32(0)
	limit := int64(60)
	job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "backup-unit-one", Namespace: "backup-execution-test"}, Spec: batchv1.JobSpec{BackoffLimit: &zero, ActiveDeadlineSeconds: &limit, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, ServiceAccountName: "capture", AutomountServiceAccountToken: &no, Containers: []corev1.Container{{Name: "capture", Image: "example.invalid/capture@sha256:" + strings.Repeat("a", 64), Command: []string{"/collector"}, SecurityContext: &corev1.SecurityContext{Privileged: &no}}}}}}}
	plan := execution.ExecutionPlan{Schema: "system-backup-execution-plan.v1", InstallationID: queue.InstallationID, TaskID: task.PublicID, ConfigSHA256: claimed.ConfigSHA256, ProfileSHA256: claimed.ProfileSHA256, Jobs: []execution.PlannedJob{{Phase: "capture", UnitKey: "ordinary", NamespaceUID: "namespace-test-uid", Job: job}}}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = vault.Save(ctx, claimed.Claim, dispatch.Plan{SchemaVersion: plan.Schema, CanonicalJSON: raw, SHA256: digestJSON(raw)}); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: job.Namespace, UID: "namespace-test-uid"}})
	var sends atomic.Int32
	var sent *batchv1.Job
	client.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		sends.Add(1)
		sent = a.(ktesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		return true, nil, context.DeadlineExceeded
	})
	driver := execution.JobDriver{Plans: vault, Client: client}
	if _, err = driver.Ensure(ctx, claimed.Claim, "capture", "ordinary"); !errors.Is(err, execution.ErrJobUncertain) {
		t.Fatal("lost response not recorded", err)
	}
	if _, err = driver.Ensure(ctx, claimed.Claim, "capture", "ordinary"); !errors.Is(err, execution.ErrJobUncertain) || sends.Load() != 1 {
		t.Fatal("missing original caused resend", sends.Load(), err)
	}
	var state string
	if err = db.QueryRow("SELECT send_state FROM system_backup_v2_job_send_intents WHERE task_public_id=?", task.PublicID).Scan(&state); err != nil || state != "sending" {
		t.Fatal("send intent lost", state, err)
	}
	// Original delayed response becomes observable; bind that exact UID.
	sent.UID = "original-job-uid"
	if err = client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), sent, sent.Namespace); err != nil {
		t.Fatal(err)
	}
	got, err := driver.Ensure(ctx, claimed.Claim, "capture", "ordinary")
	if err != nil || got.UID != sent.UID || sends.Load() != 1 {
		t.Fatal("failed original adoption", err, sends.Load())
	}
	var uid string
	if err = db.QueryRow("SELECT send_state,job_uid FROM system_backup_v2_job_send_intents WHERE task_public_id=?", task.PublicID).Scan(&state, &uid); err != nil || state != "bound" || uid != "original-job-uid" {
		t.Fatal("missing durable UID", state, uid, err)
	}
	// A replacement with the same name must never be adopted as the old Job.
	if err = client.Tracker().Delete(batchv1.SchemeGroupVersion.WithResource("jobs"), sent.Namespace, sent.Name); err != nil {
		t.Fatal(err)
	}
	replacement := sent.DeepCopy()
	replacement.UID = "replacement-job-uid"
	if err = client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), replacement, replacement.Namespace); err != nil {
		t.Fatal(err)
	}
	if _, err = driver.Ensure(ctx, claimed.Claim, "capture", "ordinary"); !errors.Is(err, execution.ErrPlan) || sends.Load() != 1 {
		t.Fatal("replacement UID adopted", err)
	}
}
