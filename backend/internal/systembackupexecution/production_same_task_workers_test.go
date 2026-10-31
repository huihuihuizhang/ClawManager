package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	"github.com/google/uuid"
	authnv1 "k8s.io/api/authentication/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

type dOriginalWorkers struct {
	mu             sync.Mutex
	active         sync.WaitGroup
	tokens         map[string]*corev1.Pod
	errors         map[string]error
	completed      int
	running        int
	resumeChecks   int
	heldDispatches int
	projections    map[string]string
	cancel         context.CancelFunc
}

type dOriginalTracePorts struct {
	*c.ExecutionJobPorts
	t *testing.T
}

type dOriginalTraceAuthorizer struct {
	owner *PublicJobOwner
	t     *testing.T
	seen  sync.Map
}

func (p *dOriginalTraceAuthorizer) Authorize(ctx context.Context, peer string, request worker.ControlRequest) (worker.Lease, error) {
	value, err := p.owner.Authorize(ctx, peer, request)
	if err != nil {
		key := request.Action + ":" + err.Error()
		if _, loaded := p.seen.LoadOrStore(key, true); !loaded {
			p.t.Log("original worker authorization", request.Action, err)
		}
	}
	return value, err
}

func (p dOriginalTracePorts) EnsureJob(ctx context.Context, a d.Authority, i d.JobIntent) (d.JobBinding, error) {
	value, err := p.ExecutionJobPorts.EnsureJob(ctx, a, i)
	p.t.Log("original EnsureJob result", i.JobUnitKey, err)
	if err != nil {
		p.t.Log("original EnsureJob failure", i.JobUnitKey, err)
	}
	return value, err
}
func (p dOriginalTracePorts) Check(ctx context.Context, a d.Authority) error {
	err := p.ExecutionJobPorts.Check(ctx, a)
	if err != nil {
		p.t.Log("original ports Check failure", err)
	}
	return err
}
func (p dOriginalTracePorts) ObserveJob(ctx context.Context, a d.Authority, b d.JobBinding) (d.JobObservation, error) {
	value, err := p.ExecutionJobPorts.ObserveJob(ctx, a, b)
	if err != nil {
		p.t.Log("original ObserveJob failure", b.JobUnitKey, err)
	}
	return value, err
}
func (p dOriginalTracePorts) StopJob(ctx context.Context, a d.Authority, b d.JobBinding) error {
	err := p.ExecutionJobPorts.StopJob(ctx, a, b)
	if err != nil {
		p.t.Log("original deferred StopJob failure", b.JobUnitKey, err)
	}
	return err
}

// Native Go workers consume the ORIGINAL immutable invocation/mapping and
// issued mTLS Secret. The finite API/kubelet model schedules processes; original
// control, TokenReview, key-use journal, encrypted C stream and Evidence remain
// production code. This is code-call proof, not a Linux/node deployment.
func (f *dOriginalSixPartTask) installOriginalWorkers(ctx context.Context, t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	w := &dOriginalWorkers{tokens: map[string]*corev1.Pod{}, errors: map[string]error{}, projections: map[string]string{}, cancel: cancel}
	f.workers = w
	ports, ok := f.service.Runtime.Loop.Dispatch.Ports.(*c.ExecutionJobPorts)
	if !ok {
		t.Fatal("original job ports type")
	}
	f.service.Runtime.Loop.Dispatch.Ports = dOriginalTracePorts{ports, t}
	identity, ok := f.service.Runtime.Control.(WorkloadIdentity)
	if !ok {
		t.Fatal("original workload identity handler type")
	}
	identity.Next = worker.ControlHandler{Authorizer: &dOriginalTraceAuthorizer{owner: f.owner, t: t}}
	f.service.Runtime.Control = identity
	t.Cleanup(func() { cancel(); w.active.Wait() })
	client := f.owner.Client.(*kubefake.Clientset)
	ns := f.service.Config.Namespace
	client.PrependReactor("create", "tokenreviews", func(action ktest.Action) (bool, runtime.Object, error) {
		review := action.(ktest.CreateAction).GetObject().(*authnv1.TokenReview).DeepCopy()
		w.mu.Lock()
		pod := w.tokens[review.Spec.Token]
		w.mu.Unlock()
		if pod != nil && len(review.Spec.Audiences) == 1 && review.Spec.Audiences[0] == kube.WorkerTokenAudience {
			review.Status = authnv1.TokenReviewStatus{Authenticated: true, Audiences: []string{kube.WorkerTokenAudience}, User: authnv1.UserInfo{Username: "system:serviceaccount:" + ns + ":" + pod.Spec.ServiceAccountName, UID: f.owner.Security.ServiceAccountUID, Extra: map[string]authnv1.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}}
		}
		return true, review, nil
	})
	client.PrependReactor("create", "jobs", func(action ktest.Action) (bool, runtime.Object, error) {
		job := action.(ktest.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		if job.Namespace != ns || job.Labels[kube.OwnerLabel] != f.publicID || job.UID != "" || job.ResourceVersion != "" {
			return true, nil, fmt.Errorf("original worker create request identity")
		}
		job.UID = types.UID(uuid.NewString())
		var gatePhase, gateOwner string
		if err := f.control.QueryRowContext(ctx, "SELECT phase,owner FROM system_backup_gate WHERE scope=?", f.service.Config.ApplicationScope).Scan(&gatePhase, &gateOwner); err != nil || gatePhase != "held" || gateOwner != f.publicID {
			return true, nil, fmt.Errorf("original Job dispatched outside same-task held gate: %s", gatePhase)
		}
		w.mu.Lock()
		w.heldDispatches++
		w.running++
		w.mu.Unlock()
		job.ResourceVersion = "1"
		if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, ns); err != nil {
			return true, nil, err
		}
		controller := true
		labels := map[string]string{}
		for key, value := range job.Spec.Template.Labels {
			labels[key] = value
		}
		labels["batch.kubernetes.io/controller-uid"] = string(job.UID)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-pod", Namespace: ns, UID: types.UID(uuid.NewString()), ResourceVersion: "1", Labels: labels, Annotations: job.Spec.Template.Annotations, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &controller}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
		if pod.Spec.NodeName == "" {
			pod.Spec.NodeName = "node"
		}
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, ContainerID: "containerd://" + string(pod.UID), Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}}
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, ns); err != nil {
			return true, nil, err
		}
		token := "original-bound-worker-token-" + string(pod.UID)
		w.mu.Lock()
		w.tokens[token] = pod.DeepCopy()
		w.mu.Unlock()
		w.active.Add(1)
		go func() {
			defer w.active.Done()
			err := f.runOriginalWorker(ctx, t, job, pod, token)
			t.Log("original native worker exited", job.Name, err)
			if err != nil {
				f.provider.mu.Lock()
				t.Log("original provider calls", f.provider.generateCalls, f.provider.unwrapCalls)
				f.provider.mu.Unlock()
			}
			finished := pod.DeepCopy()
			finished.ResourceVersion = "2"
			finished.Status.Phase = corev1.PodSucceeded
			if err != nil {
				finished.Status.Phase = corev1.PodFailed
			}
			state := finished.Status.ContainerStatuses[0]
			state.Ready = false
			code := int32(0)
			if err != nil {
				code = 1
			}
			state.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: state.ContainerID, StartedAt: state.State.Running.StartedAt, FinishedAt: metav1.Now(), ExitCode: code}}
			finished.Status.ContainerStatuses[0] = state
			if stateErr := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), finished, ns); stateErr != nil {
				err = errors.Join(err, fmt.Errorf("write original worker Pod status: %w", stateErr))
			}
			terminal := job.DeepCopy()
			terminal.ResourceVersion = "2"
			terminal.Status.Succeeded = 1
			terminal.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
			if err != nil {
				terminal.Status.Succeeded = 0
				terminal.Status.Failed = 1
				terminal.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
			}
			if stateErr := client.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), terminal, ns); stateErr != nil {
				err = errors.Join(err, fmt.Errorf("write original worker Job status: %w", stateErr))
			}
			w.mu.Lock()
			w.errors[job.Name] = err
			w.running--
			if err == nil {
				w.completed++
			}
			w.mu.Unlock()
		}()
		return true, job, nil
	})
	// Runner uses Dynamic; WorkloadIdentity/StopWitness use the typed API.
	// Both projections resolve these SAME API objects, not two independent jobs.
	f.owner.Dynamic.(*dynfake.FakeDynamicClient).PrependReactor("*", "*", func(action ktest.Action) (bool, runtime.Object, error) {
		resource := action.GetResource().Resource
		if resource != "jobs" && resource != "configmaps" {
			return false, nil, nil
		}
		var object runtime.Object
		var err error
		switch request := action.(type) {
		case ktest.CreateAction:
			input := request.GetObject().(*unstructured.Unstructured)
			if resource == "jobs" {
				target := new(batchv1.Job)
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(input.Object, target)
				if err == nil {
					object, err = client.BatchV1().Jobs(ns).Create(ctx, target, metav1.CreateOptions{})
				}
			} else {
				target := new(corev1.ConfigMap)
				err = runtime.DefaultUnstructuredConverter.FromUnstructured(input.Object, target)
				if err == nil {
					object, err = client.CoreV1().ConfigMaps(ns).Create(ctx, target, metav1.CreateOptions{})
				}
			}
		case ktest.DeleteAction:
			if resource == "jobs" {
				err = client.BatchV1().Jobs(ns).Delete(ctx, request.GetName(), request.GetDeleteOptions())
			} else {
				err = client.CoreV1().ConfigMaps(ns).Delete(ctx, request.GetName(), request.GetDeleteOptions())
			}
			return true, nil, err
		case ktest.GetAction:
			if resource == "jobs" {
				object, err = client.BatchV1().Jobs(ns).Get(ctx, request.GetName(), metav1.GetOptions{})
			} else {
				object, err = client.CoreV1().ConfigMaps(ns).Get(ctx, request.GetName(), metav1.GetOptions{})
			}
		default:
			return true, nil, fmt.Errorf("unsupported local original API verb %s", action.GetVerb())
		}
		if err != nil {
			return true, nil, err
		}
		raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
		return true, &unstructured.Unstructured{Object: raw}, err
	})
}

func (f *dOriginalSixPartTask) checkOriginalStoppedBeforePhysicalResume(ctx context.Context) error {
	// Fake API actions do not carry request contexts; the setup heartbeat has
	// ended before Capture. Bound this read-only independent observation anew.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if f.workers == nil {
		return fmt.Errorf("source resume before original worker model installation")
	}
	f.workers.mu.Lock()
	running := f.workers.running
	f.workers.mu.Unlock()
	if running != 0 {
		return fmt.Errorf("source resume with %d native workers still active", running)
	}
	var stopped bool
	var unresolved int
	if err := f.control.QueryRowContext(ctx, "SELECT collectors_stopped_at IS NOT NULL FROM system_backup_v2_runtime_captures WHERE task_public_id=?", f.publicID).Scan(&stopped); err != nil || !stopped {
		return fmt.Errorf("source resume before original collector stop barrier")
	}
	if err := f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND (revoked=FALSE OR stopped_at IS NULL)", f.publicID).Scan(&unresolved); err != nil || unresolved != 0 {
		return fmt.Errorf("source resume before all original Job stop proofs")
	}
	f.workers.mu.Lock()
	f.workers.resumeChecks++
	f.workers.mu.Unlock()
	return nil
}

func (f *dOriginalSixPartTask) runOriginalWorker(ctx context.Context, t *testing.T, job *batchv1.Job, pod *corev1.Pod, token string) error {
	client := f.owner.Client
	var invocationName, identityName, mappingName string
	for _, volume := range pod.Spec.Volumes {
		switch volume.Name {
		case "worker-request":
			invocationName = volume.ConfigMap.Name
		case "worker-identity":
			identityName = volume.Secret.SecretName
		case "formal-mapping":
			mappingName = volume.ConfigMap.Name
		}
	}
	cm, err := client.CoreV1().ConfigMaps(job.Namespace).Get(ctx, invocationName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("worker invocation mount: %w", err)
	}
	var inv worker.Invocation
	if json.Unmarshal([]byte(cm.Data["invocation.json"]), &inv) != nil || !worker.ValidateRecordedInvocation(inv) {
		return fmt.Errorf("worker original invocation")
	}
	identity, err := client.CoreV1().Secrets(job.Namespace).Get(ctx, identityName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("worker original identity mount: %w", err)
	}
	directory := filepath.Join(f.directory, "workers", job.Name)
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	for name, raw := range identity.Data {
		if err = os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			return err
		}
	}
	tokenFile := filepath.Join(directory, "pod-token")
	if err = os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		return err
	}
	control, err := worker.NewControlClient(f.service.Config.ControlURL, filepath.Join(directory, "ca.crt"), filepath.Join(directory, "tls.crt"), filepath.Join(directory, "tls.key"))
	if err != nil {
		return fmt.Errorf("worker mTLS constructor: %w", err)
	}
	defer control.Close()
	if err = control.WithWorkloadToken(tokenFile); err != nil {
		return err
	}
	for {
		err = control.Ready(ctx, inv)
		if err == nil {
			break
		}
		if !errors.Is(err, worker.ErrNotReady) {
			return fmt.Errorf("worker original Ready: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	mapping, err := client.CoreV1().ConfigMaps(job.Namespace).Get(ctx, mappingName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	mappingFile := filepath.Join(directory, "materials.json")
	if err = os.WriteFile(mappingFile, []byte(mapping.Data["materials.json"]), 0600); err != nil {
		return err
	}
	materials, err := worker.LoadFormalCaptureMaterials(mappingFile, inv)
	if err != nil {
		return fmt.Errorf("worker original formal loader: %w", err)
	}
	context64, err := k.TransitContext(inv.ProviderKey.Request)
	if err != nil {
		return err
	}
	providerToken := "original-worker-provider-token-" + string(pod.UID)
	f.provider.mu.Lock()
	f.provider.workers[providerToken] = map[string]string{"namespace": pod.Namespace, "pod_uid": string(pod.UID), "service_account_uid": f.owner.Security.ServiceAccountUID, "context": context64}
	f.provider.contexts[context64] = true
	f.provider.mu.Unlock()
	providerFile := strings.Replace(f.provider.workerJWTFile, "{pod_uid}", string(pod.UID), 1)
	if err = os.MkdirAll(filepath.Dir(providerFile), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(providerFile, []byte(providerToken), 0600); err != nil {
		return err
	}
	keyJob, err := worker.NewDeliveredCaptureKeyJob(ctx, control, inv, materials.KMS, *materials.PermitDelivery)
	if err != nil {
		return fmt.Errorf("worker original key reservation: %w", err)
	}
	defer keyJob.Close()
	if err = f.checkOriginalIssuedProjection(ctx, job, pod, inv, *materials.PermitDelivery, providerFile); err != nil {
		return err
	}
	var leaseRaw []byte
	var lease worker.KeyUseLease
	if err = f.control.QueryRowContext(ctx, "SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND observed_uid=?", f.publicID, job.UID).Scan(&leaseRaw); err != nil {
		return err
	}
	if json.Unmarshal(leaseRaw, &lease) != nil {
		return fmt.Errorf("original key-use receipt")
	}
	t.Log("original key window seconds before source open", time.Until(lease.Until).Seconds())
	stage, err := f.owner.Staging.OpenRoot(f.publicID)
	if err != nil {
		return err
	}
	defer stage.Close()
	env := worker.FormalCaptureEnvironment{Staging: stage}
	switch {
	case inv.Request.ControlEvidence != nil:
		env.ControlEvidence, err = worker.OpenControlEvidenceCaptureSources(ctx, inv, keyJob, materials.ControlEvidence)
		if err == nil {
			defer env.ControlEvidence.Close()
			env.SourceAuthorize, env.SourceValidUntil = env.ControlEvidence.Authorize, env.ControlEvidence.ValidUntil()
		}
	case inv.Request.SourceRedis != nil || inv.Request.Teams != nil || inv.Request.Database != nil || inv.Request.SkillObjects != nil:
		var sources *worker.FormalCaptureSources
		sources, err = worker.OpenFormalCaptureSources(ctx, inv, keyJob, materials.Sources)
		if err == nil {
			defer sources.Close()
			env.Database, env.Teams, env.SourceRedis = sources.Database, sources.Teams, sources.SourceRedis
			env.SourceAuthorize, env.SourceValidUntil = sources.Authorize, sources.ValidUntil()
			if inv.Request.SkillObjects != nil {
				env.SkillObjects, err = sources.SkillObjects()
			}
		}
	case inv.Request.Resources != nil:
		env.Resources, err = worker.OpenResourceCaptureSources(ctx, inv, materials.Resources)
		if err == nil {
			defer env.Resources.Close()
		}
	default:
		env.Workspace, err = os.OpenRoot(f.workspaceDirectories[inv.ProviderKey.Request.Context.Part])
		if err == nil {
			defer env.Workspace.Close()
		}
	}
	if err != nil {
		return fmt.Errorf("worker original source open %s: %w", inv.Request.Operation, err)
	}
	result, err := worker.RunFormalCapture(ctx, inv, keyJob, env)
	if err != nil {
		return fmt.Errorf("worker original encrypted capture %s: %w", inv.Request.Operation, err)
	}
	if err = keyJob.ReportCandidate(ctx, inv, result); err != nil {
		return fmt.Errorf("worker original candidate: %w", err)
	}
	return nil
}

func (f *dOriginalSixPartTask) checkOriginalIssuedProjection(ctx context.Context, job *batchv1.Job, pod *corev1.Pod, inv worker.Invocation, pin k.PermitDeliveryPin, path string) error {
	rows, err := f.control.QueryContext(ctx, "SELECT inline_payload,content_checksum FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? AND public_id LIKE 'sev!_apermit!_%' ESCAPE '!'", f.publicID)
	if err != nil {
		return err
	}
	defer rows.Close()
	count, matched := 0, 0
	invHash, _ := inv.Hash()
	for rows.Next() {
		count++
		if count > 10 {
			return fmt.Errorf("unexpected original permit count")
		}
		var raw []byte
		var checksum string
		if err = rows.Scan(&raw, &checksum); err != nil {
			return err
		}
		var delivery k.DeliveredProviderPermit
		var body k.DeliveredPermitPayload
		if hash(raw) != checksum || json.Unmarshal(raw, &delivery) != nil || !ed25519.Verify(pin.Issuer, append([]byte(k.PermitDeliveryDomain), delivery.Payload...), delivery.Signature) || json.Unmarshal(delivery.Payload, &body) != nil {
			return fmt.Errorf("original SQL-issued permit signature/hash")
		}
		if body.Permit.Identity.PodUID != string(pod.UID) {
			continue
		}
		matched++
		if body.IssuerGrantSHA256 != pin.IssuerGrantSHA256 || body.Request != inv.ProviderKey.Request || body.Permit.Identity.JobUID != string(job.UID) || body.Permit.Identity.InvocationSHA256 != invHash || body.Permit.Identity.Namespace != pod.Namespace || body.Permit.Identity.ServiceAccountUID != f.owner.Security.ServiceAccountUID || body.Permit.JWT.IdentityFile != path {
			return fmt.Errorf("original SQL issuer did not bind actual Job/Pod projection")
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	if matched != 1 {
		return fmt.Errorf("missing original SQL-issued Pod permit")
	}
	f.workers.mu.Lock()
	defer f.workers.mu.Unlock()
	for _, existing := range f.workers.projections {
		if existing == path {
			return fmt.Errorf("original Jobs share a JWT projection")
		}
	}
	f.workers.projections[job.Name] = path
	return nil
}
