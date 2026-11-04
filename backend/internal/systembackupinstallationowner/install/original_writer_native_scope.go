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
	addPod := func(p q.PodIdentity) { pods[p.Node] = append(pods[p.Node], p) }
	addRoot := func(node, root string) error {
		if node == "" || root == "/" || !path.IsAbs(root) || path.Clean(root) != root || strings.ContainsAny(root, "\\\x00\r\n") {
			return ErrInstall
		}
		roots[node] = append(roots[node], root)
		return nil
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
			addPod(p)
			pod, err := s.owner.operator.installer.kube.CoreV1().Pods(w.namespace).Get(ctx, p.Name, metav1.GetOptions{})
			if err != nil || string(pod.UID) != p.UID {
				return nil, ErrInstall
			}
			paths, err := s.actualPodPersistentRoots(ctx, pod)
			if err != nil {
				return nil, err
			}
			for _, root := range paths {
				if addRoot(p.Node, root) != nil {
					return nil, ErrInstall
				}
			}
		}
	}
	for _, w := range s.proPods {
		addPod(w.process)
		pod, err := s.owner.operator.installer.kube.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
		if err != nil || string(pod.UID) != w.original.UID || originalObjectSHA(pod.Spec) != w.specSHA {
			return nil, ErrInstall
		}
		paths, err := s.actualPodPersistentRoots(ctx, pod)
		if err != nil {
			return nil, err
		}
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
	for _, o := range s.stoppedObservations {
		for _, v := range o.baseline.Volumes {
			if addRoot(v.Node, v.SourcePath) != nil {
				return nil, ErrInstall
			}
		}
	}
	var result []*originalWholeNodeScope
	names := []string{}
	for node := range roots {
		names = append(names, node)
	}
	sort.Strings(names)
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

// Derive host paths from the exact original Pod's persistent volumes. Unknown
// CSI/NFS/provider storage is a real unsupported source, not an empty scope.
func (s *PreparedOriginalWriterSet) actualPodPersistentRoots(ctx context.Context, pod *corev1.Pod) ([]string, error) {
	if pod == nil || pod.Spec.NodeName == "" {
		return nil, ErrInstall
	}
	k := s.owner.operator.installer.kube
	var roots []string
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			roots = append(roots, v.HostPath.Path)
			continue
		}
		if v.PersistentVolumeClaim != nil {
			claim, err := k.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if err != nil || claim.Status.Phase != corev1.ClaimBound || claim.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			pv, err := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if err != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != pod.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			root := ""
			if pv.Spec.HostPath != nil {
				root = pv.Spec.HostPath.Path
			}
			if pv.Spec.Local != nil {
				if root != "" {
					return nil, ErrInstall
				}
				root = pv.Spec.Local.Path
			}
			if root == "" {
				return nil, OriginalWriterSourceFailure{Dependency: "persistent_volume_native_fence_required"}
			}
			if pv.Spec.NodeAffinity == nil || pv.Spec.NodeAffinity.Required == nil {
				return nil, OriginalWriterSourceFailure{Dependency: "hostpath_data_node_affinity_required"}
			}
			nodes, err := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, ErrInstall
			}
			matched := 0
			for n := range nodes.Items {
				yes, e := originalPVMatchesNode(pv.Spec.NodeAffinity.Required, &nodes.Items[n])
				if e != nil {
					return nil, ErrInstall
				}
				if yes {
					matched++
					if nodes.Items[n].Name != pod.Spec.NodeName {
						return nil, ErrInstall
					}
				}
			}
			if matched != 1 {
				return nil, ErrInstall
			}
			pin := originalPhysicalVolumePin{pod.Namespace, claim.Name, string(claim.UID), originalObjectSHA(claim.Spec), pv.Name, string(pv.UID), originalObjectSHA(pv.Spec), pod.Spec.NodeName}
			found := false
			for _, old := range s.volumes {
				if old.ClaimUID == pin.ClaimUID {
					if old != pin {
						return nil, ErrInstall
					}
					found = true
				}
			}
			if !found {
				s.volumes = append(s.volumes, pin)
			}
			roots = append(roots, root)
			continue
		}
		if v.EmptyDir != nil || v.Secret != nil || v.ConfigMap != nil || v.Projected != nil || v.DownwardAPI != nil {
			continue
		}
		return nil, OriginalWriterSourceFailure{Dependency: "unmapped_persistent_volume_source"}
	}
	return originalNonOverlappingRoots(roots), nil
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
