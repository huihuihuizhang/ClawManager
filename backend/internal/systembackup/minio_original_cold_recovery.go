package systembackup

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Actual original recovery provenance, never a caller Passed flag or an
// updated capture source. The original input/custody record stays unchanged.
type minioGateColdRecoveryTarget struct {
	pod, podUID, containerID, node, requestSHA string
	until                                      time.Time
}

func (g *MinIOReadServiceGate) CheckOriginalWholeHistoryScope(ctx context.Context) error {
	if g == nil {
		return ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || g.recovering || g.held || g.restored || len(g.in.OutputAccounts) != 0 || !reflect.DeepEqual(g.in.BusinessBuckets, g.original.BucketNames) || g.guard(ctx) != nil || g.recheckState(ctx, false) != nil {
		return ErrMinIOReadGate
	}
	return nil
}

// D's actual sealed recovery owner supplies the authenticated B roundtrip and
// exact original recovery request, plus its real fresh authority check. This
// API establishes only a target for SAME-source native permission restoration.
// It never renews a capture/history observation or changes original custody.
func (g *MinIOReadServiceGate) RestoreAfterOriginalCold(ctx context.Context, request q.NodeObservationRequest, native *q.VerifiedNodeObservation, podName, podUID, containerID string, ownerUntil time.Time, fresh TeamSourceCheck) error {
	if g == nil || native == nil || ctx == nil || fresh == nil || fresh(ctx) != nil || podName == "" || podUID == "" || containerID == "" || !time.Now().Before(ownerUntil) {
		return ErrMinIOReadGate
	}
	response := native.Response()
	if response.Action != request.Action || request.Action != "recovered" && request.Action != "recovery-reconciled" || request.Binding.OperationID != g.in.Operation || request.Binding.InventorySHA256 != g.in.InventorySHA256 || request.Binding.Namespace != g.in.Namespace || request.Binding.NamespaceUID != g.in.NamespaceUID || request.RecoveredGeneration != request.Binding.Generation || request.Anchor == "" || request.Anchor != response.Anchor {
		return ErrMinIOReadGate
	}
	request.Version, request.Nonce, request.Deadline = response.Version, response.Nonce, response.ValidUntil
	raw, e := json.Marshal(request)
	if e != nil || minioGateBytesHash(raw) != response.RequestSHA256 {
		return ErrMinIOReadGate
	}
	if request.Action == "recovery-reconciled" {
		if native.RecheckOriginalRecoveryScope(ctx, request, nil, response.BootID, time.Now()) != nil {
			return ErrMinIOReadGate
		}
	} else if native.Recheck(ctx, request.Binding, request.Action, response.BootID, time.Now()) != nil {
		return ErrMinIOReadGate
	}
	oldFound, newFound := false, false
	for _, pod := range request.Pods {
		if pod.UID == g.in.PodUID && pod.Name == g.in.Pod && pod.Node == request.Binding.Node {
			for _, cid := range pod.Containers {
				if cid == g.original.ContainerID {
					oldFound = true
				}
			}
		}
	}
	for _, pod := range request.RecoveredPods {
		if pod.UID == podUID && pod.Name == podName && pod.Node == request.Binding.Node {
			for _, cid := range pod.Containers {
				if cid == containerID {
					newFound = true
				}
			}
		}
	}
	if !oldFound || !newFound {
		return ErrMinIOReadGate
	}
	pod, e := g.kube.CoreV1().Pods(g.in.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if e != nil || string(pod.UID) != podUID || pod.Spec.NodeName != request.Binding.Node || pod.DeletionTimestamp != nil {
		return ErrMinIOReadGate
	}
	matched := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == g.in.Container && status.ContainerID == containerID && status.ImageID == g.in.ImageID && status.State.Running != nil && status.Ready {
			matched = true
		}
	}
	if !matched || fresh(ctx) != nil {
		return ErrMinIOReadGate
	}
	until := ownerUntil
	if deadline, ok := ctx.Deadline(); !ok {
		return ErrMinIOReadGate
	} else if deadline.Before(until) {
		until = deadline
	}
	if response.ValidUntil.Before(until) {
		until = response.ValidUntil
	}
	g.mu.Lock()
	if g.origin != g || g.custody == nil || g.poisoned || !time.Now().Before(until) {
		g.mu.Unlock()
		return ErrMinIOReadGate
	}
	if previous := g.coldRecovery; previous != nil && (previous.podUID != podUID || previous.containerID != containerID || previous.node != request.Binding.Node) {
		g.mu.Unlock()
		return ErrMinIOReadGate
	}
	g.coldRecovery = &minioGateColdRecoveryTarget{pod: podName, podUID: podUID, containerID: containerID, node: request.Binding.Node, requestSHA: response.RequestSHA256, until: until}
	// These are SAME fixed native builtin credentials. Their old local capture
	// window is not a native credential expiration. Fresh real recovery owner
	// limits are for restoration only; native status/policy/secret probes still
	// execute before writes in RestoreWithFreshAuthority. No credential rotates.
	creds := g.credentials
	for n := range creds {
		creds[n].SecretKey = append([]byte(nil), creds[n].SecretKey...)
		creds[n].NotBefore = time.Now().UTC().Add(-time.Second)
		creds[n].Until = until
	}
	g.recovering = true
	g.containerID = containerID
	g.mu.Unlock()
	defer func() {
		for n := range creds {
			clear(creds[n].SecretKey)
		}
	}()
	return g.restoreWithOriginalRecovery(ctx, creds[0], creds[1], creds[2], fresh, true)
}
