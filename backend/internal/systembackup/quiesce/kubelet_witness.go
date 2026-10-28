package quiesce

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"clawreef/internal/systembackup/flow"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// ExitWitness is an explicit kubelet termination acknowledgement, not Pod
// absence. Node UID, original container IDs, finished timestamps and the API
// resource version are retained. Force deletion with no ACK cannot mint one.
type ExitWitness struct {
	Namespace, PodName, PodUID, Node, NodeUID, ResourceVersion string
	Containers                                                 map[string]time.Time
}
type ExitWitnessStore interface {
	Save(context.Context, ExitWitness) error
	Load(context.Context, string) (ExitWitness, error)
}
type KubeletStopWitness struct {
	Client kubernetes.Interface
	// Watches has no global HTTP timeout. The bounded tracking context owns
	// stream lifetime; ordinary API calls retain their short request timeout.
	Watches   kubernetes.Interface
	Namespace string
	NodeUIDs  map[string]string
	Store     ExitWitnessStore
	Timeout   time.Duration
}

func (w KubeletStopWitness) valid() bool {
	return w.Client != nil && w.Namespace != "" && len(w.NodeUIDs) > 0 && w.Store != nil && w.Timeout > 0 && w.Timeout <= 5*time.Minute
}
func witnessFor(pod *corev1.Pod, original PodIdentity, nodeUID string) (ExitWitness, bool) {
	p := ExitWitness{Containers: map[string]time.Time{}}
	if pod == nil || string(pod.UID) != original.UID || pod.Name != original.Name || pod.Spec.NodeName != original.Node || pod.ResourceVersion == "" || nodeUID == "" {
		return p, false
	}
	expected := map[string]bool{}
	for _, id := range original.Containers {
		if id == "" || expected[id] {
			return p, false
		}
		expected[id] = true
	}
	statuses := append(append(append([]corev1.ContainerStatus(nil), pod.Status.ContainerStatuses...), pod.Status.InitContainerStatuses...), pod.Status.EphemeralContainerStatuses...)
	for _, s := range statuses {
		if !expected[s.ContainerID] {
			if s.State.Running != nil || s.State.Waiting != nil {
				return p, false
			}
			continue
		}
		if s.State.Terminated == nil || s.State.Running != nil || s.State.Waiting != nil || s.State.Terminated.ContainerID != s.ContainerID || s.State.Terminated.FinishedAt.IsZero() {
			return p, false
		}
		p.Containers[s.ContainerID] = s.State.Terminated.FinishedAt.Time.UTC()
	}
	if len(expected) == 0 || len(p.Containers) != len(expected) {
		return p, false
	}
	p.Namespace = pod.Namespace
	p.PodName = pod.Name
	p.PodUID = string(pod.UID)
	p.Node = original.Node
	p.NodeUID = nodeUID
	p.ResourceVersion = pod.ResourceVersion
	return p, true
}

// Arm establishes the watch BEFORE a stop request. Every watch is bounded and
// records only explicit terminations. Gone/expired/closed streams are unknown.
func (w KubeletStopWitness) Arm(ctx context.Context, pods []PodIdentity) error {
	if !w.valid() {
		return flow.ErrNotReady
	}
	for _, p := range pods {
		if e := w.Confirm(ctx, []PodIdentity{p}); e == nil {
			continue
		}
		pod, e := w.Client.CoreV1().Pods(w.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if e != nil || string(pod.UID) != p.UID || pod.Spec.NodeName != p.Node {
			return flow.ErrQuiesce
		}
		nodeUID := w.NodeUIDs[p.Node]
		node, e := w.Client.CoreV1().Nodes().Get(ctx, p.Node, metav1.GetOptions{})
		if e != nil || nodeUID == "" || string(node.UID) != nodeUID || node.DeletionTimestamp != nil {
			return flow.ErrQuiesce
		}
		if proof, ok := witnessFor(pod, p, nodeUID); ok {
			if e = w.Store.Save(ctx, proof); e != nil {
				return e
			}
			continue
		}
		tracking, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.Timeout)
		watchClient := w.Watches
		if watchClient == nil {
			watchClient = w.Client
		}
		stream, e := watchClient.CoreV1().Pods(w.Namespace).Watch(tracking, metav1.ListOptions{FieldSelector: "metadata.name=" + p.Name, ResourceVersion: pod.ResourceVersion})
		if e != nil {
			cancel()
			return flow.ErrQuiesce
		}
		go func(original PodIdentity) {
			defer cancel()
			defer stream.Stop()
			for {
				select {
				case <-tracking.Done():
					return
				case event, ok := <-stream.ResultChan():
					if !ok || event.Type == watch.Error {
						return
					}
					observed, ok := event.Object.(*corev1.Pod)
					if !ok || string(observed.UID) != original.UID {
						return
					}
					proof, ready := witnessFor(observed, original, nodeUID)
					if ready {
						node, e := w.Client.CoreV1().Nodes().Get(tracking, original.Node, metav1.GetOptions{})
						if e == nil && string(node.UID) == nodeUID && node.DeletionTimestamp == nil {
							// SQL response loss/transient contention must not discard the
							// one termination acknowledgement before the Pod is removed.
							for {
								if e = w.Store.Save(tracking, proof); e == nil {
									break
								}
								timer := time.NewTimer(100 * time.Millisecond)
								select {
								case <-tracking.Done():
									timer.Stop()
									return
								case <-timer.C:
								}
							}
						}
						return
					}
					if event.Type == watch.Deleted {
						return
					}
				}
			}
		}(p)
	}
	return nil
}
func (w KubeletStopWitness) Confirm(ctx context.Context, pods []PodIdentity) error {
	if !w.valid() {
		return flow.ErrNotReady
	}
	for _, p := range pods {
		proof, e := w.Store.Load(ctx, p.UID)
		if e != nil || proof.Namespace != w.Namespace || proof.PodName != p.Name || proof.PodUID != p.UID || proof.Node != p.Node || proof.NodeUID != w.NodeUIDs[p.Node] || proof.ResourceVersion == "" || len(proof.Containers) != len(p.Containers) {
			return flow.ErrQuiesce
		}
		for _, id := range p.Containers {
			if proof.Containers[id].IsZero() {
				return flow.ErrQuiesce
			}
		}
	}
	return nil
}
func WitnessBytes(p ExitWitness) []byte { raw, _ := json.Marshal(p); return raw }
func SameExitWitness(a, b ExitWitness) bool {
	if a.Namespace != b.Namespace || a.PodName != b.PodName || a.PodUID != b.PodUID || a.Node != b.Node || a.NodeUID != b.NodeUID || len(a.Containers) != len(b.Containers) {
		return false
	}
	ids := make([]string, 0, len(a.Containers))
	for id := range a.Containers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !a.Containers[id].Equal(b.Containers[id]) {
			return false
		}
	}
	return true
}
