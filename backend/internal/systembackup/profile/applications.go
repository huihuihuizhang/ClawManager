package profile

import (
	"context"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ApplicationDeployment struct{ Namespace, Name, UID, Container, Image string }
type WriterProofRequest struct {
	Version, Nonce, Task, Mode, Database, ServerUUID, InventorySHA256 string
	RequiredUntil                                                     time.Time
	Process                                                           *control.AppProcess      `json:",omitempty"`
	Permits                                                           []control.MutationPermit `json:",omitempty"`
}

// WriterCoverage proves coverage outside this controller's view as well as
// pending remote effects. It is bound to an exact inventory and task window.
// A compliant service must enforce fencing; an operator's boolean is not proof.
func (c *CapabilityClient) WriterCoverage(ctx context.Context, endpoint string, request WriterProofRequest) error {
	if request.Task == "" || request.Database == "" || request.ServerUUID == "" || len(request.InventorySHA256) != 64 || !request.RequiredUntil.After(time.Now()) {
		return ErrProfile
	}
	switch request.Mode {
	case "inventory", "capture":
	case "resolve", "resolve-legacy":
		if request.Process == nil {
			return ErrProfile
		}
	default:
		return ErrProfile
	}
	n, e := nonce()
	if e != nil {
		return e
	}
	request.Nonce = n
	request.Version = "writer-coverage.v1"
	var response struct {
		Version, Nonce, RequestSHA256                string
		Complete, GateEnforced, RemoteEffectsStopped bool
		LegacyIdentityConfirmed                      bool
		ValidUntil                                   time.Time
	}
	if e = c.exchange(ctx, endpoint, request, &response); e != nil {
		return e
	}
	if response.Version != request.Version || response.Nonce != n || response.RequestSHA256 != kube.ContentHash(request) || !response.Complete || !response.GateEnforced || response.ValidUntil.Before(request.RequiredUntil) || request.Mode == "resolve" && !response.RemoteEffectsStopped {
		return ErrProfile
	}
	if request.Mode == "resolve-legacy" && (!response.LegacyIdentityConfirmed || !response.RemoteEffectsStopped) {
		return ErrProfile
	}
	return nil
}
func (d *Driver) applicationCoverage(ctx context.Context) ([]control.AppProcess, error) {
	if len(d.Config.Applications) == 0 {
		return nil, ErrProfile
	}
	registered, e := d.Store.Applications(ctx)
	if e != nil {
		return nil, e
	}
	var out []control.AppProcess
	seen := map[string]bool{}
	for _, a := range d.Config.Applications {
		if a.Container == "" || !strings.Contains(a.Image, "@sha256:") || a.UID == "" {
			return nil, ErrProfile
		}
		deployment, e := d.Client.AppsV1().Deployments(a.Namespace).Get(ctx, a.Name, metav1.GetOptions{})
		if e != nil || string(deployment.UID) != a.UID || deployment.DeletionTimestamp != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 || deployment.Status.ObservedGeneration != deployment.Generation || deployment.Status.UpdatedReplicas != *deployment.Spec.Replicas || deployment.Status.ReadyReplicas != *deployment.Spec.Replicas {
			return nil, ErrProfile
		}
		selector, e := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		if e != nil || selector.Empty() {
			return nil, ErrProfile
		}
		pods, e := d.Client.CoreV1().Pods(a.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
		if e != nil || len(pods.Items) != int(*deployment.Spec.Replicas) {
			return nil, ErrProfile
		}
		for _, pod := range pods.Items {
			if len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 {
				return nil, ErrProfile
			}
			owner := metav1.GetControllerOf(&pod)
			if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
				return nil, ErrProfile
			}
			rs, e := d.Client.AppsV1().ReplicaSets(a.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if e != nil || rs.UID != owner.UID {
				return nil, ErrProfile
			}
			dep := metav1.GetControllerOf(rs)
			if dep == nil || dep.UID != deployment.UID || dep.Name != a.Name || dep.Kind != "Deployment" {
				return nil, ErrProfile
			}
			found := false
			for _, c := range pod.Spec.Containers {
				if c.Name == a.Container && c.Image == a.Image {
					for _, env := range c.Env {
						if env.Name == "CLAWMANAGER_BACKUP_CONTROL_CONFIG" && env.Value != "" {
							found = true
						}
					}
				}
			}
			if !found {
				return nil, ErrProfile
			}
			node, e := d.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
			if e != nil {
				return nil, ErrProfile
			}
			observed, e := control.IdentifyApplication(&pod, node, a.Container)
			if e != nil {
				return nil, e
			}
			matches := 0
			for _, r := range registered {
				observed.ID = r.ID
				if jsonEqual(observed, r) {
					if seen[r.ID] {
						return nil, ErrProfile
					}
					seen[r.ID] = true
					out = append(out, r)
					matches++
				}
			}
			if matches != 1 {
				return nil, ErrProfile
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (d *Driver) checkApplications(ctx context.Context, t control.Task, p plan, mode string) error {
	apps, e := d.applicationCoverage(ctx)
	if e != nil || !jsonEqual(apps, p.Applications) || d.WriterProof == nil {
		return ErrProfile
	}
	return d.WriterProof(ctx, WriterProofRequest{Task: t.ID, Mode: mode, Database: d.Config.Source.Name, ServerUUID: d.Config.Source.ServerUUID, InventorySHA256: kube.ContentHash(apps), RequiredUntil: time.UnixMilli(t.Deadline)})
}
func (d *Driver) resolveMutations(ctx context.Context, t control.Task, p plan) error {
	if e := d.checkApplications(ctx, t, p, "capture"); e != nil {
		return e
	}
	permits, e := d.Store.PendingMutations(ctx)
	if e != nil {
		return e
	}
	apps, e := d.Store.Applications(ctx)
	if e != nil {
		return e
	}
	live := map[string]bool{}
	for _, a := range p.Applications {
		live[a.ID] = true
	}
	needed := map[string]bool{}
	for _, permit := range permits {
		if permit.Process != "" {
			continue
		}
		p, ok := d.Config.LegacyPermits[permit.Token]
		if !ok {
			continue
		}
		node, e := d.Client.CoreV1().Nodes().Get(ctx, p.Pod.Node, metav1.GetOptions{})
		if e != nil || string(node.UID) != p.NodeUID {
			continue
		}
		if d.Proof == nil || d.Proof.Confirm(ctx, []quiesce.PodIdentity{p.Pod}) != nil {
			continue
		}
		if e = d.Store.ResolveLegacyMutation(ctx, t, permit.Token, p, func(ctx context.Context, p control.AppProcess, v control.MutationPermit) error {
			if d.Proof.Confirm(ctx, []quiesce.PodIdentity{p.Pod}) != nil {
				return ErrProfile
			}
			return d.WriterProof(ctx, WriterProofRequest{Task: t.ID, Mode: "resolve-legacy", Database: d.Config.Source.Name, ServerUUID: d.Config.Source.ServerUUID, InventorySHA256: kube.ContentHash(p), RequiredUntil: time.UnixMilli(t.Deadline), Process: &p, Permits: []control.MutationPermit{v}})
		}); e != nil {
			return e
		}
	}
	for _, v := range permits {
		if v.Process != "" && !live[v.Process] {
			needed[v.Process] = true
		}
	}
	for _, a := range apps {
		if !needed[a.ID] {
			continue
		}
		// Failed CRI evidence means a possibly live process. Leave its permits
		// untouched and let gate drain remain pending, without deleting anything.
		node, e := d.Client.CoreV1().Nodes().Get(ctx, a.Pod.Node, metav1.GetOptions{})
		if e != nil || string(node.UID) != a.NodeUID {
			continue
		}
		if d.Proof == nil || d.Proof.Confirm(ctx, []quiesce.PodIdentity{a.Pod}) != nil {
			continue
		}
		e = d.Store.ResolveApplication(ctx, t, a, func(ctx context.Context, a control.AppProcess, permits []control.MutationPermit) error {
			if d.Proof.Confirm(ctx, []quiesce.PodIdentity{a.Pod}) != nil {
				return ErrProfile
			}
			return d.WriterProof(ctx, WriterProofRequest{Task: t.ID, Mode: "resolve", Database: d.Config.Source.Name, ServerUUID: d.Config.Source.ServerUUID, InventorySHA256: kube.ContentHash(p.Applications), RequiredUntil: time.UnixMilli(t.Deadline), Process: &a, Permits: permits})
		})
		if e != nil {
			return e
		}
	}
	return nil
}
