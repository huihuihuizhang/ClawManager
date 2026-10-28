package systembackupexecution

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// platformProfile is deliberately a separate capability from runtime-instance
// capture. A platform profile cannot silently claim it quiesced Lite gateways.
func (s *DeploymentService) platformProfile(o *PublicJobOwner) (b.LinuxProfileConfig, error) {
	cfg := s.Config
	source := b.LinuxProfileConfig{Source: s.Source, RecoveryOnly: !s.ForwardEnabled, Database: cfg.SourceDatabase, ServerUUID: cfg.SourceServerUUID, Supported: map[b.AgentKind]bool{{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}: true}, HoldLimit: time.Duration(cfg.HoldSeconds) * time.Second}
	source.BuildWriters = func(ctx context.Context, in d.Input, inventory b.SourceInventory, frozen []b.FrozenWriter) ([]flow.Writer, error) {
		if len(inventory.Instances) != 0 {
			return nil, d.ErrNotReady
		}
		out := make([]flow.Writer, 0, len(cfg.Writers))
		for _, ref := range cfg.Writers {
			ref := ref
			id := "deployment/" + ref.Namespace + "/" + ref.Name
			w := &quiesce.DeploymentWriter{Platform: true, Client: o.Client, Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, FenceID: in.Authority.TaskPublicID + "/attempt/1", PollInterval: 200 * time.Millisecond}
			w.Guard = func(ctx context.Context, point string, state flow.State) error {
				recovery := point == "before-resume" || point == "recovery-check-stopped" || point == "check-resumed"
				if recovery {
					return o.Gate.CheckRecovery(ctx, in.Authority, id, d.WriterState{UID: state.UID, Generation: state.Generation, Running: state.Running, Checkpoint: state.Checkpoint})
				}
				if e := o.Gate.Check(ctx, in.Authority); e != nil {
					return e
				}
				return s.checkAutoscalers(ctx, ref)
			}
			w.PrepareStop = func(ctx context.Context, _ flow.State, pods []quiesce.PodIdentity) error {
				return o.StopWitnessIn(in.Authority, ref.Namespace).Arm(ctx, pods)
			}
			stopLogged := false
			w.ConfirmStopped = func(ctx context.Context, _ flow.State, pods []quiesce.PodIdentity) error {
				if e := o.StopWitnessIn(in.Authority, ref.Namespace).Confirm(ctx, pods); e != nil {
					if !stopLogged {
						log.Printf("[system-backup-public] source-stop-proof=%s", closedExecutionCode(e))
						stopLogged = true
					}
					return quiesce.ErrStopProofPending
				}
				return nil
			}
			w.ConfirmResumed = func(ctx context.Context, _ flow.State) error {
				dep, e := o.Client.AppsV1().Deployments(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
				if e != nil || string(dep.UID) != ref.UID || dep.Spec.Replicas == nil || dep.Status.ObservedGeneration != dep.Generation || dep.Status.ReadyReplicas != *dep.Spec.Replicas {
					return d.ErrNotReady
				}
				return nil
			}
			out = append(out, w)
		}
		if frozen != nil {
			wanted := map[string]bool{}
			for _, w := range frozen {
				wanted[w.ID] = true
			}
			if len(wanted) != len(out) {
				return nil, d.ErrNotReady
			}
			for _, w := range out {
				if !wanted[w.ID()] {
					return nil, d.ErrNotReady
				}
			}
		}
		return out, nil
	}
	source.BuildParts = func(in d.Input, _ b.SourceInventory, until time.Time) ([]b.JobPart, error) {
		token := strings.ReplaceAll(in.Authority.TaskPublicID, "_", "-")
		name := "capture-" + token
		invocation := s.workspaceInvocation(in, until)
		seconds := int64(time.Until(until).Seconds()) - 1
		if seconds < 1 {
			return nil, d.ErrNotReady
		}
		part, e := b.BuildCapturePart(in, until, b.CapturePartRequest{Part: "workspace", Category: "workspace", JobUnitKey: "workspace", Generation: 1, Invocation: invocation, Workload: kube.JobRequest{Identity: kube.Identity{Namespace: cfg.Namespace, Name: name, Owner: in.Authority.TaskPublicID}, Image: cfg.WorkerImage, ServiceAccount: cfg.Security.ServiceAccountName, Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.Workspace.Claim}}}, StagingClaim: cfg.StagingClaim, SourceSubPath: cfg.Workspace.SubPath, NodeName: cfg.Workspace.Node, DeadlineSeconds: seconds, WorkerControl: &kube.WorkerControl{URL: cfg.ControlURL, InvocationConfigMap: "request-" + token, IdentitySecret: "identity-" + token, BoundPodIdentity: true}}})
		if e != nil {
			return nil, e
		}
		return []b.JobPart{part}, nil
	}
	return source, nil
}
func (s *DeploymentService) checkAutoscalers(ctx context.Context, w PlatformDeployment) error {
	items, e := s.Runtime.Owner.Client.AutoscalingV2().HorizontalPodAutoscalers(w.Namespace).List(ctx, metav1.ListOptions{})
	if e != nil {
		return d.ErrNotReady
	}
	for _, hpa := range items.Items {
		if hpa.Spec.ScaleTargetRef.Kind == "Deployment" && hpa.Spec.ScaleTargetRef.Name == w.Name {
			return d.ErrNotReady
		}
	}
	// Config is immutable; collect and compare only metadata, never environment.
	nodes := s.Config.Security.NodeUIDs
	dep, e := s.Runtime.Owner.Client.AppsV1().Deployments(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
	if e != nil || string(dep.UID) != w.UID {
		return d.ErrNotReady
	}
	selector, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil || selector.Empty() {
		return d.ErrNotReady
	}
	pods, e := s.Runtime.Owner.Client.CoreV1().Pods(w.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil {
		return d.ErrNotReady
	}
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" {
			node, z := s.Runtime.Owner.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if z != nil || nodes[pod.Spec.NodeName] != string(node.UID) || node.Labels[corev1.LabelOSStable] != "linux" {
				return d.ErrNotReady
			}
		}
	}
	return nil
}

// Deployment diagnostics never serialize Pod env/Secret/source file contents.
func (s *DeploymentService) PublicCapability() json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"protocol": "public-v1", "scope": s.Config.CaptureScope, "parts": []string{"workspace"}, "acceptance_ready": false})
	return raw
}
