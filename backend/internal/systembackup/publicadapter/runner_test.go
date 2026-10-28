package publicadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fixture struct {
	in                                                                            d.Input
	x                                                                             Discovery
	events                                                                        []string
	discoveries, binds, ensures, reads                                            int
	sourceChecks                                                                  int
	pauseErr, stopErr, resumeErr, ensureErr                                       bool
	changedWriter, badObservation, badHash, badCheckpoint, noEvidence, noComplete bool
	loseFence, denyRecovery                                                       bool
	stopped                                                                       bool
	binding                                                                       d.JobBinding
	raw                                                                           []byte
	pauses                                                                        []flow.PauseRecord
	jobs                                                                          []d.JobBinding
	undispatched                                                                  []string
	cancelOnObserve                                                               context.CancelFunc
}

func setup(t *testing.T) (*fixture, d.Runner, d.Plan) {
	t.Helper()
	f := &fixture{}
	f.in = d.Input{Authority: d.Authority{InstallationID: "installation_test", TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", RequestID: "request-1", ConfigVersion: 2, AttemptNo: 3, Phase: "capture", ClaimOwner: "controller-1", ClaimRowVersion: 19, MaintenanceOwner: "capture-1", MaintenanceFencingToken: 29, DeadlineAt: time.Now().UTC().Add(time.Minute)}, ConfigSnapshot: json.RawMessage(`{"synthetic":true}`), ProfileID: "linux-test", ProfileRevision: strings.Repeat("a", 64)}
	f.in.Authority.ConfigSHA256 = digest(f.in.ConfigSnapshot)
	seconds := int64(30)
	job := batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: metav1.ObjectMeta{Name: "capture-one", Namespace: "cm-drill-b", Labels: map[string]string{kube.OwnerLabel: f.in.Authority.TaskPublicID}}, Spec: batchv1.JobSpec{ActiveDeadlineSeconds: &seconds, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{kube.OwnerLabel: f.in.Authority.TaskPublicID}}, Spec: corev1.PodSpec{ServiceAccountName: "b-worker", RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "capture", Image: "test@sha256:" + strings.Repeat("b", 64)}}}}}}
	job.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "invocation", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "users-invocation"}}}}}
	raw, _ := json.Marshal(job)
	source := json.RawMessage(`{"inventory":"synthetic"}`)
	f.x = Discovery{Source: source, SourceSHA256: digest(source), HoldUntil: f.in.Authority.DeadlineAt, Writers: []FrozenWriter{{"writer-1", flow.State{UID: "source-uid", Generation: 7, Running: true, Checkpoint: "source-original"}}}, Parts: []JobPart{{Part: "users", Category: "metadata", InvocationSHA256: strings.Repeat("c", 64), Intent: d.JobIntent{JobUnitKey: "users", Namespace: job.Namespace, Name: job.Name, Generation: 5, SpecJSON: raw, SpecSHA256: digest(raw)}}}}
	f.binding = d.JobBinding{JobUnitKey: "users", Namespace: job.Namespace, Name: job.Name, UID: "22222222-2222-4222-8222-222222222222", Generation: 5, RelayIdentityRef: "relay-ref", RelayIdentityVersion: "v2", RelayBoundAt: time.Now().UTC(), RelayExpiresAt: f.in.Authority.DeadlineAt}
	inv := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: f.in.Authority.TaskPublicID, Attempt: "3", Path: "users", CaptureContextHash: strings.Repeat("c", 64), EnvelopeID: "test-envelope"}, Deadline: f.in.Authority.DeadlineAt, ArtifactName: "users.enc", MaxFiles: 5, MaxFileBytes: 1 << 20, MaxArchiveBytes: 2 << 20, MaxCompressedBytes: 2 << 20, PolicyVersion: "synthetic-test"}, WorkspacePath: "/workspace", StagingPath: "/staging"}
	invraw, _ := json.Marshal(inv)
	f.x.Parts[0].InvocationJSON = invraw
	f.x.Parts[0].InvocationSHA256 = digest(invraw)
	f.x.Parts[0].InvocationConfigMap = "users-invocation"
	r, err := NewPublicRunner(Dependencies{Profiles: map[ProfileKey]Profile{{f.in.ProfileID, f.in.ProfileRevision}: f}, Results: f, Recovery: f, Admission: func(context.Context, d.Input) error { return nil }, ValidateInventory: fixtureInventory, RecoveryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Prepare(context.Background(), f.in, f)
	if err != nil {
		t.Fatal(err)
	}
	f.events = nil
	return f, r, p
}

func fixtureInventory(_ context.Context, _ d.Input, x Discovery) error {
	if len(x.Parts) == 0 || digest(x.Source) != x.SourceSHA256 {
		return d.ErrNotReady
	}
	return nil
}
func (f *fixture) Discover(context.Context, d.Input) (Discovery, error) {
	f.discoveries++
	return f.x, nil
}
func (f *fixture) CheckSource(context.Context, d.Input, Discovery) error {
	f.sourceChecks++
	return nil
}
func (f *fixture) BindWriters(context.Context, d.Input, Discovery) ([]flow.Writer, error) {
	f.binds++
	return []flow.Writer{fixtureWriter{f}}, nil
}
func (f *fixture) Check(ctx context.Context, a d.Authority) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a != f.in.Authority {
		return &Failure{"coordination_invalid"}
	}
	if f.loseFence && contains(f.events, "paused") {
		return &Failure{"fencing_token_lost"}
	}
	return nil
}
func (f *fixture) CheckRecovery(ctx context.Context, a d.Authority, id string, s d.WriterState) error {
	f.events = append(f.events, "recovery-check")
	if ctx.Err() != nil || a != f.in.Authority || id != "writer-1" || s != state(f.x.Writers[0].Original) || f.denyRecovery {
		return &Failure{"fencing_token_lost"}
	}
	return nil
}
func (f *fixture) PauseIntent(_ context.Context, _ d.Authority, _ string, s d.WriterState) error {
	f.events = append(f.events, "intent")
	if s != state(f.x.Writers[0].Original) {
		return errors.New("wrong state")
	}
	return nil
}
func (f *fixture) Paused(_ context.Context, _ d.Authority, _ string, a d.WriterACK) error {
	f.events = append(f.events, "paused")
	if a.UID != "source-uid" || a.Generation != 7 || !a.Stopped {
		return errors.New("wrong ACK")
	}
	return nil
}
func (f *fixture) Resumed(context.Context, d.Authority, string) error {
	f.events = append(f.events, "resumed")
	return nil
}
func (f *fixture) EnsureJob(_ context.Context, _ d.Authority, _ d.JobIntent) (d.JobBinding, error) {
	f.ensures++
	f.events = append(f.events, "ensure")
	if !contains(f.events, "check-paused") {
		return d.JobBinding{}, errors.New("dispatch before source barrier")
	}
	if f.ensureErr {
		return d.JobBinding{}, errors.New("ambiguous create")
	}
	return f.binding, nil
}
func (f *fixture) ObserveJob(context.Context, d.Authority, d.JobBinding) (d.JobObservation, error) {
	f.events = append(f.events, "observe-job")
	if f.cancelOnObserve != nil {
		f.cancelOnObserve()
	}
	cp := Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", TaskPublicID: f.in.Authority.TaskPublicID, AttemptNo: 3, Phase: "capture", ConfigSHA256: f.in.Authority.ConfigSHA256, InventorySHA256: f.x.SourceSHA256, Part: "users", JobUID: f.binding.UID, JobGeneration: 5, InvocationSHA256: f.x.Parts[0].InvocationSHA256, SealedRef: "opaque-staging-version", ContentSHA256: strings.Repeat("d", 64)}
	if f.badCheckpoint {
		cp.AttemptNo = 99
	}
	cp.InstallationID = f.in.Authority.InstallationID
	cp.ConfigVersion = f.in.Authority.ConfigVersion
	cpraw, _ := json.Marshal(cp)
	raw, _ := json.Marshal(d.ModuleResult{SchemaVersion: "system-backup-part-result.v1", Part: "users", Category: "metadata", Status: "completed", Checkpoint: cpraw, Statistics: map[string]uint64{"rows": 4}, Warnings: []d.Warning{}, EvidenceIDs: []string{}, FailureCategory: "none"})
	f.raw = raw
	b := f.binding
	if f.badObservation {
		b.UID = "33333333-3333-4333-8333-333333333333"
	}
	obs := d.JobObservation{Binding: b, Complete: !f.noComplete, ResultEvidence: &d.EvidenceRef{PublicID: "sev_result", SHA256: digest(raw)}}
	if f.noEvidence {
		obs.ResultEvidence = nil
	}
	if f.badHash {
		obs.ResultEvidence.SHA256 = strings.Repeat("0", 64)
	}
	return obs, nil
}
func (f *fixture) StopJob(ctx context.Context, _ d.Authority, b d.JobBinding) error {
	f.events = append(f.events, "stop")
	if ctx.Err() != nil || !sameBinding(b, f.binding) || f.stopErr {
		return errors.New("stop not proven")
	}
	f.stopped = true
	return nil
}
func (f *fixture) Read(context.Context, d.Authority, d.JobBinding, d.EvidenceRef) ([]byte, error) {
	f.reads++
	return f.raw, nil
}
func (f *fixture) Pending(context.Context, d.Authority) (RecoverySnapshot, error) {
	return RecoverySnapshot{Pauses: f.pauses, Jobs: f.jobs, Undispatched: f.undispatched}, nil
}

type fixtureWriter struct{ f *fixture }

func (w fixtureWriter) ID() string { return "writer-1" }
func (w fixtureWriter) Observe(context.Context) (flow.State, error) {
	s := w.f.x.Writers[0].Original
	if w.f.changedWriter {
		s.UID = "replacement"
	}
	return s, nil
}
func (w fixtureWriter) Pause(context.Context, flow.State) (flow.ACK, error) {
	w.f.events = append(w.f.events, "pause")
	if w.f.pauseErr {
		return flow.ACK{}, errors.New("pause uncertain")
	}
	return flow.ACK{UID: "source-uid", Generation: 7, Stopped: true}, nil
}
func (w fixtureWriter) CheckPaused(context.Context, flow.State) error {
	w.f.events = append(w.f.events, "check-paused")
	return nil
}
func (w fixtureWriter) Resume(ctx context.Context, s flow.State) error {
	w.f.events = append(w.f.events, "resume")
	if ctx.Err() != nil || (w.f.ensures > 0 && !w.f.stopped) || s != w.f.x.Writers[0].Original || w.f.resumeErr {
		return errors.New("resume unproven")
	}
	return nil
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func at(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func TestPrepareHasNoResourceSideEffectsAndCaptureUsesFrozenPlan(t *testing.T) {
	f, r, p := setup(t)
	if f.ensures != 0 || f.binds != 0 || f.reads != 0 {
		t.Fatal("Prepare performed work")
	}
	out, err := (d.Dispatcher{Runner: r, Ports: f}).Capture(context.Background(), f.in, p)
	if err != nil || len(out) != 1 || out[0].Status != "completed" || !reflect.DeepEqual(out[0].EvidenceIDs, []string{}) {
		t.Fatalf("result=%+v err=%v", out, err)
	}
	if f.discoveries != 1 || f.ensures != 1 || at(f.events, "intent") > at(f.events, "pause") || at(f.events, "check-paused") > at(f.events, "ensure") || at(f.events, "paused") > at(f.events, "observe-job") || at(f.events, "stop") > at(f.events, "resume") || at(f.events, "resumed") < at(f.events, "resume") {
		t.Fatal(f.events)
	}
}

func TestPlanBindingRejectsDriftBeforeAnyResourceWork(t *testing.T) {
	for _, name := range []string{"task", "attempt", "config", "profile", "bytes", "expired", "nil-ports", "missing-maintenance"} {
		t.Run(name, func(t *testing.T) {
			f, r, p := setup(t)
			in := f.in
			var ports d.Ports = f
			switch name {
			case "task":
				in.Authority.TaskPublicID = "sbk_44444444-4444-4444-8444-444444444444"
			case "attempt":
				in.Authority.AttemptNo++
			case "config":
				in.ConfigSnapshot = json.RawMessage(`{"different":true}`)
				in.Authority.ConfigSHA256 = digest(in.ConfigSnapshot)
			case "profile":
				in.ProfileRevision = "absent"
			case "bytes":
				p.CanonicalJSON = append(p.CanonicalJSON, ' ')
			case "expired":
				in.Authority.DeadlineAt = time.Now().Add(-time.Second)
			case "nil-ports":
				ports = nil
			case "missing-maintenance":
				in.Authority.MaintenanceFencingToken = 0
			}
			out, err := r.Capture(context.Background(), in, p, ports)
			if err == nil || out != nil || f.ensures != 0 {
				t.Fatalf("drift accepted: %v %v", out, err)
			}
		})
	}
}

func TestCaptureFailuresNeverReturnCompletedPartsAndRecoverSafely(t *testing.T) {
	for _, name := range []string{"pause", "UID", "job-UID", "hash", "checkpoint", "stop", "resume", "fence", "recovery-fence", "unknown-create", "cancel", "job-only", "evidence-only"} {
		t.Run(name, func(t *testing.T) {
			f, r, p := setup(t)
			switch name {
			case "pause":
				f.pauseErr = true
			case "UID":
				f.changedWriter = true
			case "job-UID":
				f.badObservation = true
			case "hash":
				f.badHash = true
			case "checkpoint":
				f.badCheckpoint = true
			case "stop":
				f.stopErr = true
			case "resume":
				f.resumeErr = true
			case "fence":
				f.loseFence = true
			case "recovery-fence":
				f.loseFence = true
				f.denyRecovery = true
			case "unknown-create":
				f.ensureErr = true
			case "job-only":
				f.noEvidence = true
			case "evidence-only":
				f.noComplete = true
			}
			ctx := context.Background()
			cancel := func() {}
			if name == "cancel" {
				var c context.CancelFunc
				ctx, c = context.WithCancel(ctx)
				c()
			}
			if name == "job-only" || name == "evidence-only" {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
			}
			defer cancel()
			out, err := r.Capture(ctx, f.in, p, f)
			if err == nil || out != nil {
				t.Fatalf("unsafe success %v %v", out, err)
			}
			if (name == "stop" || name == "recovery-fence" || name == "unknown-create") && contains(f.events, "resume") {
				t.Fatal("source resumed without stop/recovery proof", f.events)
			}
			if name == "fence" && err.Error() != "fencing_token_lost" {
				t.Fatalf("lost category: %v", err)
			}
			if name == "hash" && err.Error() != "checksum_mismatch" {
				t.Fatal(err)
			}
			if (name == "pause" || name == "UID" || name == "fence") && f.ensures != 0 {
				t.Fatal("dispatched without complete source barrier", f.events)
			}
			if contains(f.events, "resume") && at(f.events, "stop") > at(f.events, "resume") {
				t.Fatal(f.events)
			}
		})
	}
}

func TestRecoveryUsesPersistedOriginalStatesAndCurrentOwner(t *testing.T) {
	f, r, p := setup(t)
	f.in.Authority.ClaimOwner = "new-controller"
	f.in.Authority.ClaimRowVersion = 88
	f.in.Authority.MaintenanceOwner = "new-recovery"
	f.in.Authority.MaintenanceFencingToken = 99
	f.pauses = []flow.PauseRecord{{WriterID: "writer-1", Original: f.x.Writers[0].Original}}
	f.jobs = []d.JobBinding{f.binding}
	out, err := (d.Dispatcher{Runner: r, Ports: f}).Recover(context.Background(), f.in, p)
	if err != nil || !out.CollectorsStopped || !out.WritersResumed || f.discoveries != 1 || !contains(f.events, "resumed") {
		t.Fatal(out, err, f.events)
	}
	f.events = nil
	f.pauses[0].Original.UID = "wrong"
	if _, err := r.Recover(context.Background(), f.in, p, f); err == nil || contains(f.events, "stop") || contains(f.events, "resume") {
		t.Fatal("invalid full inventory mutated source", err, f.events)
	}
}

func TestSealedTakeoverReusesAuthenticatedResultsWithoutReadingSource(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(strconv.FormatBool(complete), func(t *testing.T) {
			f, r, p := setup(t)
			f.in.Jobs = []d.JobBinding{f.binding}
			f.jobs = []d.JobBinding{f.binding}
			f.noComplete = !complete
			out, err := r.Capture(context.Background(), f.in, p, f)
			if complete {
				if err != nil || len(out) != 1 || !f.stopped {
					t.Fatal(out, err)
				}
			} else if err == nil || out != nil {
				t.Fatal("incomplete set reused")
			}
			if f.sourceChecks != 0 || f.ensures != 0 || f.discoveries != 1 || contains(f.events, "pause") {
				t.Fatal("takeover recaptured source", f.events, f.sourceChecks)
			}
		})
	}
}

func TestRecoveryRejectsIncompleteJobInventoryBeforeAnyCompensation(t *testing.T) {
	f, r, p := setup(t)
	f.pauses = []flow.PauseRecord{{WriterID: "writer-1", Original: f.x.Writers[0].Original}}
	if out, err := r.Recover(context.Background(), f.in, p, f); err == nil || out.WritersResumed || contains(f.events, "resume") || contains(f.events, "stop") {
		t.Fatal(out, err, f.events)
	}
}

func TestRecoveryBeforeDispatchRequiresExplicitCompleteJournalProof(t *testing.T) {
	for _, mode := range []string{"never-dispatched", "duplicate", "foreign", "job-conflict", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f, r, p := setup(t)
			f.pauses = []flow.PauseRecord{{WriterID: "writer-1", Original: f.x.Writers[0].Original}}
			f.undispatched = []string{"users"}
			switch mode {
			case "duplicate":
				f.undispatched = []string{"users", "users"}
			case "foreign":
				f.undispatched = []string{"other"}
			case "job-conflict":
				f.jobs = []d.JobBinding{f.binding}
			case "unknown":
				f.undispatched = nil
			}
			out, err := r.Recover(context.Background(), f.in, p, f)
			if mode == "never-dispatched" {
				if err != nil || !out.CollectorsStopped || !out.WritersResumed || !contains(f.events, "resume") || contains(f.events, "ensure") || contains(f.events, "stop") {
					t.Fatal(out, err, f.events)
				}
			} else if err == nil || contains(f.events, "stop") || contains(f.events, "resume") {
				t.Fatal("incomplete/contradictory scope caused mutation", out, err, f.events)
			}
		})
	}
}

func TestRunningCancellationStopsJobBeforeOriginalStateResume(t *testing.T) {
	f, r, p := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancelOnObserve = cancel
	out, err := r.Capture(ctx, f.in, p, f)
	if !errors.Is(err, context.Canceled) || out != nil || f.ensures != 1 || !f.stopped || !contains(f.events, "resumed") || at(f.events, "stop") > at(f.events, "resume") {
		t.Fatal("active cancellation lost cleanup ordering", out, err, f.events)
	}
}

func TestConstructorRequiresRealCompositionAndNoPrivateFallback(t *testing.T) {
	if _, err := NewPublicRunner(Dependencies{}); !errors.Is(err, d.ErrNotReady) {
		t.Fatal(err)
	}
	var typedNil *fixture
	if _, err := NewPublicRunner(Dependencies{Profiles: map[ProfileKey]Profile{{"x", "r"}: typedNil}, Results: typedNil, Recovery: typedNil, Admission: func(context.Context, d.Input) error { return nil }, RecoveryTimeout: time.Second}); !errors.Is(err, d.ErrNotReady) {
		t.Fatal(err)
	}
	if classify(errors.New("private DSN password diagnostic")).Error() != "runner_failed" {
		t.Fatal("raw error leaked")
	}
	var dst map[string]any
	if decodeStrict([]byte(`{"key":1,"key":2}`), &dst) == nil {
		t.Fatal("duplicate key accepted")
	}
}
