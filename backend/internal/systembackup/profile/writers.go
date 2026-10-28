package profile

import (
	"context"
	"fmt"
	"strings"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type databaseWriter struct {
	driver   *Driver
	task     control.Task
	original *sqlInstance
}

func (w *databaseWriter) ID() string {
	if w.original != nil {
		return fmt.Sprintf("stopped/%d", w.original.ID)
	}
	return "platform-database"
}
func (w *databaseWriter) state() flow.State {
	return flow.State{UID: w.task.ID + "/" + w.ID(), Generation: 1, Checkpoint: "application-gate.v1"}
}
func (w *databaseWriter) check(ctx context.Context, recovery bool) error {
	if !recovery && w.original == nil {
		p, e := w.driver.load(ctx, w.task)
		if e != nil {
			return e
		}
		if e = w.driver.checkApplications(ctx, w.task, p, "capture"); e != nil {
			return e
		}
	}
	tx, e := w.driver.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrProfile
	}
	defer tx.Rollback()
	if e = w.driver.Store.GateDrained(ctx, tx, w.task, recovery); e != nil {
		return e
	}
	if w.original != nil {
		var status string
		var generation int
		if w.driver.Source.QueryRowContext(ctx, "SELECT status,runtime_generation FROM instances WHERE id=?", w.original.ID).Scan(&status, &generation) != nil || status != "stopped" || generation != w.original.Generation {
			return ErrProfile
		}
	}
	return nil
}
func (w *databaseWriter) Observe(ctx context.Context) (flow.State, error) {
	return w.state(), w.check(ctx, false)
}
func (w *databaseWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if s != w.state() {
		return flow.ACK{}, ErrProfile
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, w.check(ctx, false)
}
func (w *databaseWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if s != w.state() {
		return ErrProfile
	}
	return w.check(ctx, false)
}
func (w *databaseWriter) Resume(ctx context.Context, s flow.State) error {
	if s != w.state() {
		return ErrProfile
	}
	return w.check(ctx, true)
}

func (d *Driver) writers(t control.Task, p plan) ([]flow.Writer, control.PauseJournal, error) {
	writers := []flow.Writer{&databaseWriter{driver: d, task: t}}
	j := control.PauseJournal{Store: d.Store, Task: t, Identity: p.Identity}
	// All closures refer to this complete registry; no source side effects occur
	// until the binder has finished constructing every writer.
	for _, value := range p.Instances {
		f := value
		if f.Input.WorkloadKind == "Stopped" {
			original := f.SQL
			writers = append(writers, &databaseWriter{driver: d, task: t, original: &original})
			continue
		}
		runtime := scope.Runtime{Type: f.SQL.Type, Mode: f.SQL.Mode, Backend: f.SQL.Backend, Variant: f.SQL.Variant, OS: f.SQL.OS}
		binding := f.Source
		binding.Deployment = f.Deployment != nil
		writerID := ""
		restarter := func() control.SourceRestarter {
			return control.SourceRestarter{Journal: j, Binding: binding, Writer: writerID}
		}
		guard := func(ctx context.Context, point string, state flow.State) error {
			recovery := point != "observe" && point != "observed" && point != "before-stop" && point != "check-stopped"
			if e := restarter().Guard(ctx, recovery, state); e != nil {
				return e
			}
			if f.Input.WorkloadKind == "Gateway" {
				pod, e := d.Client.CoreV1().Pods(f.Input.Namespace).Get(ctx, f.Input.PodName, metav1.GetOptions{})
				if e != nil || string(pod.UID) != f.Source.PodUID || pod.DeletionTimestamp != nil || !jsonEqual(pod.Spec, f.Pod.Spec) || d.AgentProbe(ctx, f.Input.Endpoint, f.Source.PodUID) != nil {
					return ErrProfile
				}
			}
			if f.Deployment != nil && point == "before-resume" {
				_, e := restarter().Claim(ctx, state)
				return e
			}
			return nil
		}
		stopProof := func(ctx context.Context, _ flow.State, pods []quiesce.PodIdentity) error {
			return d.Proof.Confirm(ctx, pods)
		}
		switch f.Input.WorkloadKind {
		case "Gateway":
			r := f.Input.Restart
			w := &services.BackupGatewayWriter{Agent: d.Agent, Source: services.BackupGatewaySource{Runtime: runtime, Endpoint: f.Input.Endpoint, PodUID: f.Source.PodUID, Workspace: f.Input.Workspace, RestartRef: fmt.Sprintf("instance-%d-restart", f.SQL.ID), InstanceID: f.SQL.ID, UserID: f.SQL.UserID, Generation: f.SQL.Generation, ResumeGeneration: f.SQL.Generation + 1, UID: r.UID, GID: r.GID, Port: r.GatewayPort}, Guard: guard,
				LoadRestart:  func(context.Context, string) (services.RuntimeAgentCreateGatewayRequest, error) { return r, nil },
				ClaimRestart: func(ctx context.Context, s flow.State) (bool, error) { return restarter().Claim(ctx, s) },
				CompleteRestart: func(ctx context.Context, s flow.State, gateway string, port int) error {
					return restarter().Complete(ctx, s, control.RestartResult{PodUID: f.Source.PodUID, GatewayID: gateway, Port: port})
				},
			}
			writerID = w.ID()
			writers = append(writers, w)
		case "Pod":
			original := f.Pod.DeepCopy()
			original.UID = ""
			original.ResourceVersion = ""
			original.Generation = 0
			original.CreationTimestamp = metav1.Time{}
			original.ManagedFields = nil
			original.Status = corev1.PodStatus{}
			original.Finalizers = nil
			w := &quiesce.PodWriter{Client: d.Client, Namespace: f.Input.Namespace, Name: f.Input.PodName, UID: string(f.Pod.UID), InstanceKey: fmt.Sprint(f.SQL.ID), FenceID: t.ID, RestartRef: fmt.Sprintf("instance-%d-restart", f.SQL.ID), Generation: int64(f.SQL.Generation), Runtime: runtime, Guard: guard, LoadRestart: func(context.Context, string) (*corev1.Pod, error) { return original.DeepCopy(), nil }, ClaimRestart: func(ctx context.Context, s flow.State) (bool, error) { return restarter().Claim(ctx, s) }, ConfirmStopped: stopProof,
				ConfirmResumed: func(ctx context.Context, _ flow.State) error {
					pod, e := d.Client.CoreV1().Pods(f.Input.Namespace).Get(ctx, f.Input.PodName, metav1.GetOptions{})
					if e != nil || !podReady(pod) {
						return ErrProfile
					}
					return nil
				},
				CompleteRestart: func(ctx context.Context, s flow.State, uid string) error {
					pod, e := d.Client.CoreV1().Pods(f.Input.Namespace).Get(ctx, f.Input.PodName, metav1.GetOptions{})
					if e != nil || string(pod.UID) != uid || !podReady(pod) {
						return ErrProfile
					}
					if uid == f.Source.PodUID {
						return j.CheckRecoveryFence(ctx, j.Identity, writerID, s)
					}
					return restarter().Complete(ctx, s, control.RestartResult{PodUID: uid, PodName: pod.Name, PodIP: pod.Status.PodIP})
				},
			}
			writerID = w.ID()
			writers = append(writers, w)
		case "Deployment":
			w := &quiesce.DeploymentWriter{Client: d.Client, Namespace: f.Input.Namespace, Name: f.Deployment.Name, UID: string(f.Deployment.UID), FenceID: t.ID, Runtime: runtime, Guard: guard, ConfirmStopped: stopProof,
				ConfirmResumed: func(ctx context.Context, s flow.State) error {
					selector, e := metav1.LabelSelectorAsSelector(f.Deployment.Spec.Selector)
					if e != nil {
						return ErrProfile
					}
					pods, e := d.Client.CoreV1().Pods(f.Input.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
					if e != nil || len(pods.Items) != 1 || !podReady(&pods.Items[0]) || !d.deploymentOwns(ctx, f, &pods.Items[0]) {
						return ErrProfile
					}
					pod := pods.Items[0]
					return restarter().Complete(ctx, s, control.RestartResult{PodUID: string(pod.UID), PodName: pod.Name, PodIP: pod.Status.PodIP})
				},
			}
			writerID = w.ID()
			writers = append(writers, w)
		default:
			return nil, j, ErrProfile
		}
	}
	owner, e := d.bindSix(t, p)
	if e != nil {
		return nil, j, e
	}
	if owner != nil {
		writers = append(writers, owner.Writers...)
	}
	seen := map[string]bool{}
	for _, w := range writers {
		if w == nil || w.ID() == "" || seen[w.ID()] {
			return nil, j, ErrProfile
		}
		seen[w.ID()] = true
		j.Writers = append(j.Writers, w.ID())
	}
	return writers, j, nil
}
func podReady(p *corev1.Pod) bool {
	if p == nil || p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func (d *Driver) checkSource(ctx context.Context, t control.Task, p plan) error {
	if e := d.checkApplications(ctx, t, p, "inventory"); e != nil {
		return e
	}
	if e := d.fence(ctx, t, false); e != nil {
		return e
	}
	users, actual, e := d.inventory(ctx)
	if e != nil || users != p.Users || len(actual) != len(p.Instances) {
		return ErrProfile
	}
	for idx, f := range p.Instances {
		if !jsonEqual(actual[idx], f.SQL) {
			return ErrProfile
		}
		if f.Pod != nil {
			pod, e := d.Client.CoreV1().Pods(f.Input.Namespace).Get(ctx, f.Input.PodName, metav1.GetOptions{})
			if e != nil || string(pod.UID) != string(f.Pod.UID) || !jsonEqual(pod.Spec, f.Pod.Spec) {
				return ErrProfile
			}
		}
		for _, m := range f.Mounts {
			current, e := d.claim(ctx, f.Input.Namespace, Claim{m.Name, m.UID})
			current.Volume = m.Volume
			if e != nil || !jsonEqual(current, m) {
				return ErrProfile
			}
		}
		if f.Input.WorkloadKind == "Stopped" && f.SQL.Pod != "" {
			_, e := d.Client.CoreV1().Pods(f.Input.Namespace).Get(ctx, f.SQL.Pod, metav1.GetOptions{})
			if !apierrors.IsNotFound(e) {
				return ErrProfile
			}
		}
	}
	if e := d.checkMountUsers(ctx, p); e != nil {
		return e
	}
	owner, e := d.bindSix(t, p)
	if e != nil {
		return e
	}
	if owner != nil {
		return owner.CheckSource(ctx)
	}
	return nil
}
func (d *Driver) EvidenceCheck(ctx context.Context, g control.WorkerGrant, point string) error {
	t, e := d.Store.Get(ctx, g.TaskID)
	if e != nil || t.ProfileRevision != g.ProfileRevision {
		return ErrProfile
	}
	p, e := d.load(ctx, t)
	if e != nil {
		return e
	}
	if t.Request.Kind != "backup" {
		return d.checkTarget(ctx, t, p)
	}
	if strings.HasPrefix(point, "ready/") && t.Status != "capturing" {
		return d.checkSource(ctx, t, p)
	}
	if e = d.checkMountUsers(ctx, p); e != nil {
		return e
	}
	for _, f := range p.Instances {
		for _, m := range f.Mounts {
			live, e := d.claim(ctx, f.Input.Namespace, Claim{m.Name, m.UID})
			live.Volume = m.Volume
			if e != nil || !jsonEqual(live, m) {
				return ErrProfile
			}
		}
		backing, e := d.backing(ctx, f.Input.Namespace, f.Volume)
		if e != nil {
			return e
		}
		if backing.NFS != nil {
			hash := kube.ContentHash(backing.NFS)
			if f.Volume.NFS != nil {
				hash = kube.ContentHash(f.Volume)
			}
			if d.ExternalNFSProof == nil || d.ExternalNFSProof(ctx, d.Config.ExclusiveNFSProofURL, hash) != nil {
				return ErrProfile
			}
		}
	}
	writers, j, e := d.writers(t, p)
	if e != nil {
		return e
	}
	records, e := j.PendingPauses(ctx, p.Identity)
	if e != nil || len(records) != len(writers) {
		return ErrProfile
	}
	byID := map[string]flow.State{}
	for _, r := range records {
		byID[r.WriterID] = r.Original
	}
	for _, w := range writers {
		state, ok := byID[w.ID()]
		if !ok || w.CheckPaused(ctx, state) != nil {
			return ErrProfile
		}
	}
	return nil
}
