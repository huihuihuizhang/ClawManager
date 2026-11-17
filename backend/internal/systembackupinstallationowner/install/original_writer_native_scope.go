package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path"
	"sort"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalWholeNodeScope struct {
	set              *PreparedOriginalWriterSet
	request          q.NodeObservationRequest
	prepare, current *q.VerifiedNodeObservation
	boot             string
	claim            c.OriginalAdoptionReservation
}

type originalPhysicalVolumePin struct{ Namespace, ClaimName, ClaimUID, ClaimSpecSHA256, PVName, PVUID, PVSpecSHA256, Node string }

func (s *PreparedOriginalWriterSet) prepareNativeScopes(ctx context.Context) ([]*originalWholeNodeScope, error) {
	if s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil {
		return nil, ErrInstall
	}
	pods := map[string][]q.PodIdentity{}
	roots := map[string][]string{}
	namespaces := map[string]map[string]bool{}
	addPod := func(p q.PodIdentity, namespace string) {
		pods[p.Node] = append(pods[p.Node], p)
		if namespaces[p.Node] == nil {
			namespaces[p.Node] = map[string]bool{}
		}
		namespaces[p.Node][namespace] = true
	}
	addRoot := func(node, root string) error {
		if node == "" || root == "/" || !path.IsAbs(root) || path.Clean(root) != root || strings.ContainsAny(root, "\\\x00\r\n") {
			return ErrInstall
		}
		roots[node] = append(roots[node], root)
		return nil
	}
	volumeScope := func(pod *corev1.Pod) ([]string, *originalCSIPodScope, error) {
		paths, classes, err := s.classifyPodPersistentVolumes(ctx, pod)
		if err != nil {
			return nil, nil, err
		}
		if len(classes) == 0 {
			return paths, nil, nil
		}
		if len(paths) != 0 {
			return nil, nil, OriginalWriterSourceFailure{Dependency: "original_mixed_csi_host_scope_required"}
		}
		coverage, err := s.prepareCSIPodScope(ctx, pod, classes)
		return nil, coverage, err
	}
	for _, w := range s.deployments {
		// Native Redis captures logical DUMP/absolute TTL, not live AOF files.
		if w.redis != nil {
			continue
		}
		if w.minio != nil {
			continue
		}
		for _, p := range w.pods {
			pod, err := s.owner.operator.installer.kube.CoreV1().Pods(w.namespace).Get(ctx, p.Name, metav1.GetOptions{})
			if err != nil || string(pod.UID) != p.UID {
				return nil, ErrInstall
			}
			paths, coverage, err := volumeScope(pod)
			if err != nil {
				return nil, err
			}
			if s.minioHistory != nil && s.minioHistory.writer == w && coverage != nil {
				root, rootErr := s.originalMinIOCSIPrepareRoot(ctx, pod)
				if rootErr != nil || addRoot(p.Node, root) != nil {
					return nil, ErrInstall
				}
			}
			// A Longhorn actor fences storage, not the original process or its
			// replacement. Retain every cold Pod in the native process anchor so
			// partial and complete recovery use the same original identities.
			addPod(p, pod.Namespace)
			for _, root := range paths {
				if addRoot(p.Node, root) != nil {
					return nil, ErrInstall
				}
			}
		}
	}
	for _, w := range s.proPods {
		pod, err := s.owner.operator.installer.kube.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
		if err != nil || string(pod.UID) != w.original.UID || originalObjectSHA(pod.Spec) != w.specSHA {
			return nil, ErrInstall
		}
		paths, _, err := volumeScope(pod)
		if err != nil {
			return nil, err
		}
		addPod(w.process, pod.Namespace)
		for _, root := range paths {
			if addRoot(w.process.Node, root) != nil {
				return nil, ErrInstall
			}
		}
	}
	for _, g := range s.gateways {
		for _, root := range g.selection.SourcePaths {
			if addRoot(g.request.Binding.Node, root) != nil {
				return nil, ErrInstall
			}
		}
	}
	// Shared Agents remain running/frozen and are NEVER cold Pods. Their
	// actual captured volume roots must nevertheless be pinned by the same
	// original readonly prepare anchor, before the first source mutation.
	for _, shared := range s.sharedRuntimes {
		paths, coverage, err := volumeScope(&shared.pod)
		if err != nil {
			return nil, err
		}
		if coverage != nil {
			continue
		}
		if len(paths) == 0 {
			return nil, ErrInstall
		}
		for _, root := range paths {
			if addRoot(shared.pod.Spec.NodeName, root) != nil {
				return nil, ErrInstall
			}
		}
	}

	for _, o := range s.stoppedObservations {
		for _, v := range o.baseline.Volumes {
			if addRoot(v.Node, v.SourcePath) != nil {
				return nil, ErrInstall
			}
		}
	}
	var result []*originalWholeNodeScope
	names, err := originalColdNativeNodes(pods, roots)
	if err != nil {
		return nil, err
	}
	for _, nodeName := range names {
		paths := originalNonOverlappingRoots(roots[nodeName])
		originalPods := pods[nodeName]
		if len(originalPods) == 0 {
			// A node containing only a CURRENT stopped Pro source is covered by
			// its dedicated complete absence reader, never a fabricated Pod.
			for _, root := range paths {
				covered := false
				for _, o := range s.stoppedObservations {
					for _, v := range o.baseline.Volumes {
						if v.Node == nodeName && v.SourcePath == root {
							covered = true
						}
					}
				}
				if !covered {
					return nil, OriginalWriterSourceFailure{Dependency: "originally_empty_platform_node_absence_producer_required"}
				}
			}
			continue
		}
		node, err := s.owner.operator.installer.kube.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
			return nil, ErrInstall
		}
		sort.Slice(originalPods, func(i, j int) bool { return originalPods[i].UID < originalPods[j].UID })
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, ErrInstall
		}
		p := s.owner
		binding := q.ObservationBinding{Kind: q.NodeObservationWholePodColdCut, InstallationID: p.operator.installer.plan.Target.InstallationID, OperationID: p.operation, ReservationID: hex.EncodeToString(id[:]), InventorySHA256: s.inventorySHA, Namespace: p.operator.installer.plan.Target.Namespace, NamespaceUID: p.operator.installer.plan.Target.NamespaceUID, Node: nodeName, NodeUID: string(node.UID), Generation: p.token.Generation, FenceEpoch: p.token.FencingToken, ExpiresAt: p.until.UTC().Truncate(time.Microsecond)}
		if len(paths) == 0 {
			binding.Kind = q.NodeObservationColdProcesses
		}
		for namespace := range namespaces[nodeName] {
			actual, err := p.operator.installer.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
			if err != nil || actual.UID == "" || actual.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			if namespace == binding.Namespace {
				if string(actual.UID) != binding.NamespaceUID {
					return nil, ErrInstall
				}
				continue
			}
			pinned := false
			for _, tenant := range s.selection.TenantNamespaces {
				if tenant.Namespace == namespace && tenant.NamespaceUID == string(actual.UID) {
					pinned = true
				}
			}
			if !pinned {
				return nil, ErrInstall
			}
			binding.AdditionalNamespaces = append(binding.AdditionalNamespaces, q.ObservationNamespace{Name: namespace, UID: string(actual.UID)})
		}
		sort.Slice(binding.AdditionalNamespaces, func(i, j int) bool {
			return binding.AdditionalNamespaces[i].Name < binding.AdditionalNamespaces[j].Name
		})
		request := q.NodeObservationRequest{Action: "prepare", Binding: binding, Pods: originalPods, SourcePaths: paths}
		proof, err := s.wholePodClient.ObserveVerified(ctx, request)
		if err != nil {
			return nil, ErrInstall
		}
		response := proof.Response()
		claim := c.OriginalAdoptionReservation{Version: c.OriginalAdoptionReservationVersion, OperationID: p.operation, ReservationID: binding.ReservationID, InstallationID: binding.InstallationID, ServerUUID: p.operator.installer.plan.Target.ServerUUID, Database: p.operator.installer.plan.Target.Database, Scope: c.CaptureGateScope, GateOwner: p.token.Owner, GateGeneration: p.token.Generation, AcquisitionEpoch: p.token.FencingToken, AcquisitionRowVersion: p.token.RowVersion, Phase: c.GateAcquiring, WriterID: "node/" + nodeName, SourceWritersSHA256: s.inventorySHA, ControlKind: "platform-quiesce", NativeRequestSHA256: response.RequestSHA256, NotBefore: p.operator.sqlTime.UTC().Truncate(time.Microsecond), ExpiresAt: binding.ExpiresAt}
		if _, err = c.OriginalAdoptionReservationIdentitySHA256(claim); err != nil {
			return nil, ErrInstall
		}
		native := &originalWholeNodeScope{set: s, request: request, prepare: proof, boot: response.BootID, claim: claim}
		if s.journal.append(ctx, claim.WriterID, "native_node_prepare", nil, struct {
			Request     q.NodeObservationRequest
			Observation q.NodeObservationResponse
			Claim       c.OriginalAdoptionReservation
		}{request, response, claim}) != nil {
			return nil, ErrInstall
		}
		result = append(result, native)
	}
	return result, nil
}

// Every cold process must reach an actual native observer. A node without
// filesystem sources uses the separate process-only kind, never a host cut.
func originalColdNativeNodes(pods map[string][]q.PodIdentity, roots map[string][]string) ([]string, error) {
	seen := map[string]bool{}
	for node, originals := range pods {
		if len(originals) != 0 {
			seen[node] = true
		}
	}
	for node := range roots {
		seen[node] = true
	}
	names := make([]string, 0, len(seen))
	for node := range seen {
		names = append(names, node)
	}
	sort.Strings(names)
	return names, nil
}

func originalNonOverlappingRoots(roots []string) []string {
	ordered := append([]string(nil), roots...)
	sort.Strings(ordered)
	out := []string{}
	for _, root := range ordered {
		contained := false
		for _, parent := range out {
			if root == parent || strings.HasPrefix(root, parent+"/") {
				contained = true
				break
			}
		}
		if !contained {
			out = append(out, root)
		}
	}
	return out
}

// Derive host paths from the exact original Pod's persistent volumes. A
// Longhorn CSI volume has no host root: its fence is the signed engine hold, so
// this whole-node path still refuses it and the caller reports the dependency.
func (s *PreparedOriginalWriterSet) actualPodPersistentRoots(ctx context.Context, pod *corev1.Pod) ([]string, error) {
	roots, longhorn, err := s.classifyPodPersistentVolumes(ctx, pod)
	if err != nil {
		return nil, err
	}
	if len(longhorn) > 0 {
		return nil, OriginalWriterSourceFailure{Dependency: "persistent_volume_native_fence_required"}
	}
	return roots, nil
}

func (s *PreparedOriginalWriterSet) recheckVolumePins(ctx context.Context) error {
	for _, v := range s.volumes {
		claim, err := s.owner.operator.installer.kube.CoreV1().PersistentVolumeClaims(v.Namespace).Get(ctx, v.ClaimName, metav1.GetOptions{})
		if err != nil || string(claim.UID) != v.ClaimUID || originalObjectSHA(claim.Spec) != v.ClaimSpecSHA256 || claim.DeletionTimestamp != nil {
			return ErrInstall
		}
		pv, err := s.owner.operator.installer.kube.CoreV1().PersistentVolumes().Get(ctx, v.PVName, metav1.GetOptions{})
		if err != nil || string(pv.UID) != v.PVUID || originalObjectSHA(pv.Spec) != v.PVSpecSHA256 || pv.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	return nil
}

func (n *originalWholeNodeScope) observeStopped(ctx context.Context) error {
	if n.set.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil {
		return ErrInstall
	}
	r := n.request
	r.Action = "stopped"
	r.SourcePaths = nil
	r.Anchor = n.prepare.Response().Anchor
	if r.Binding.Kind == q.NodeObservationWholePodColdCut && len(n.set.sharedLifecycle) > 0 {
		scopes, err := n.set.sharedRuntimeFrozenScopes(r.Binding.Node)
		if err != nil {
			return err
		}
		r.SharedFrozenScopes = scopes
	}
	proof, err := n.set.wholePodClient.ObserveVerified(ctx, r)
	if err != nil || proof.Recheck(ctx, r.Binding, "stopped", n.boot, time.Now()) != nil {
		return ErrInstall
	}
	if n.set.journal.append(ctx, n.claim.WriterID, "native_node_stopped", nil, proof.Response()) != nil {
		return ErrInstall
	}
	n.current = proof
	return nil
}
