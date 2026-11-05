package systembackupexecution

import (
	"context"
	"path"
	"sort"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// These are fields of the EXISTING original-owner signed Core/config, not a
// new authority. They bind only SQL-derived instance paths and actual provider
// resource identities. They do NOT prove fsid/inode, writer pause or ownership.
type OriginalNFSInstancePath struct {
	InstanceID, UserID, Generation int
	SubPath                        string
}

type OriginalNFSProvider struct {
	Namespace, NamespaceUID, Service, ServiceUID, EndpointsUID string
	Pod, PodUID, Claim, ClaimUID, PV, PVUID                    string
	Node, NodeUID, ExportMountPath                             string
	PVSpec                                                     *core.PersistentVolumeSpec
}

func (n *NFSWorkspace) originalPathsValid() bool {
	if n == nil || len(n.OriginalPaths) == 0 || len(n.OriginalPaths) > 9998 || n.Provider == nil {
		return false
	}
	p := n.Provider
	for _, s := range []string{p.Namespace, p.NamespaceUID, p.Service, p.ServiceUID, p.EndpointsUID, p.Pod, p.PodUID, p.Claim, p.ClaimUID, p.PV, p.PVUID, p.Node, p.NodeUID} {
		if s == "" || strings.ContainsAny(s, "\x00\r\n/\\") {
			return false
		}
	}
	if p.PVSpec == nil || p.PVSpec.ClaimRef == nil || string(p.PVSpec.ClaimRef.UID) != p.ClaimUID || p.PVSpec.ClaimRef.Namespace != p.Namespace || p.PVSpec.ClaimRef.Name != p.Claim || !cleanMountRoot(p.ExportMountPath) {
		return false
	}
	for i, v := range n.OriginalPaths {
		if v.InstanceID <= 0 || v.UserID <= 0 || v.Generation <= 0 || !nfsCleanRelative(v.SubPath) || i > 0 && n.OriginalPaths[i-1].InstanceID >= v.InstanceID {
			return false
		}
		for _, old := range n.OriginalPaths[:i] {
			if old.SubPath == v.SubPath || strings.HasPrefix(old.SubPath, v.SubPath+"/") || strings.HasPrefix(v.SubPath, old.SubPath+"/") {
				return false
			}
		}
	}
	return true
}

func nfsCleanRelative(p string) bool {
	return p != "" && p != "." && p != ".." && !path.IsAbs(p) && path.Clean(p) == p && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00\r\n:")
}

// Every use compares the scoped path with the ACTUAL original SQL identity,
// never merely with a path from a caller or with a namespace name.
func originalNFSInstanceSubPath(cfg WorkspaceCapture, root string, instance b.InstanceIdentity) (string, error) {
	if !cfg.NFS.originalPathsValid() || !cleanMountRoot(root) || !strings.HasPrefix(instance.Workspace, root+"/") || path.Clean(instance.Workspace) != instance.Workspace {
		return "", d.ErrNotReady
	}
	want := path.Join(cfg.SubPath, strings.TrimPrefix(instance.Workspace, root+"/"))
	i := sort.Search(len(cfg.NFS.OriginalPaths), func(i int) bool { return cfg.NFS.OriginalPaths[i].InstanceID >= instance.ID })
	if i == len(cfg.NFS.OriginalPaths) {
		return "", d.ErrNotReady
	}
	p := cfg.NFS.OriginalPaths[i]
	if p.InstanceID != instance.ID || p.UserID != instance.UserID || p.Generation != instance.Generation || p.SubPath != want || !nfsCleanRelative(want) {
		return "", d.ErrNotReady
	}
	return want, nil
}

// Actual API recheck is consumed before building primary NFS worker volumes.
// Provider namespace is distinct from consumer namespace. No Service/Pod/PVC
// is adopted by matching names, and no physical native proof is created here.
func (n *NFSWorkspace) recheckOriginalProvider(ctx context.Context, k kubernetes.Interface) error {
	if n == nil || len(n.OriginalPaths) == 0 {
		return nil
	} // Preserve existing installed subtree profile.
	if !n.originalPathsValid() || ctx == nil || ctx.Err() != nil || k == nil {
		return d.ErrNotReady
	}
	p := n.Provider
	ns, e := k.CoreV1().Namespaces().Get(ctx, p.Namespace, meta.GetOptions{})
	if e != nil || string(ns.UID) != p.NamespaceUID || ns.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	svc, e := k.CoreV1().Services(p.Namespace).Get(ctx, p.Service, meta.GetOptions{})
	if e != nil || string(svc.UID) != p.ServiceUID || svc.DeletionTimestamp != nil || svc.Spec.ClusterIP != n.Server || len(svc.Spec.Selector) == 0 {
		return d.ErrNotReady
	}
	ep, e := k.CoreV1().Endpoints(p.Namespace).Get(ctx, p.Service, meta.GetOptions{})
	if e != nil || string(ep.UID) != p.EndpointsUID || ep.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	addresses := []core.EndpointAddress{}
	for _, s := range ep.Subsets {
		if len(s.NotReadyAddresses) != 0 {
			return d.ErrNotReady
		}
		addresses = append(addresses, s.Addresses...)
	}
	if len(addresses) != 1 || addresses[0].TargetRef == nil {
		return d.ErrNotReady
	}
	ref := addresses[0].TargetRef
	if ref.Kind != "Pod" || ref.Namespace != p.Namespace || ref.Name != p.Pod || string(ref.UID) != p.PodUID {
		return d.ErrNotReady
	}
	pod, e := k.CoreV1().Pods(p.Namespace).Get(ctx, p.Pod, meta.GetOptions{})
	if e != nil || string(pod.UID) != p.PodUID || pod.DeletionTimestamp != nil || pod.Status.PodIP != addresses[0].IP || pod.Spec.NodeName != p.Node {
		return d.ErrNotReady
	}
	for key, value := range svc.Spec.Selector {
		if pod.Labels[key] != value {
			return d.ErrNotReady
		}
	}
	matched := 0
	for _, c := range pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.MountPath == p.ExportMountPath && m.SubPathExpr == "" && m.SubPath == "" {
				for _, v := range pod.Spec.Volumes {
					if v.Name == m.Name && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == p.Claim {
						matched++
					}
				}
			}
		}
	}
	if matched != 1 {
		return d.ErrNotReady
	}
	claim, e := k.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, p.Claim, meta.GetOptions{})
	if e != nil || string(claim.UID) != p.ClaimUID || claim.DeletionTimestamp != nil || claim.Status.Phase != core.ClaimBound || claim.Spec.VolumeName != p.PV {
		return d.ErrNotReady
	}
	pv, e := k.CoreV1().PersistentVolumes().Get(ctx, p.PV, meta.GetOptions{})
	if e != nil || string(pv.UID) != p.PVUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != p.ClaimUID || pv.Spec.ClaimRef.Namespace != p.Namespace || pv.Spec.ClaimRef.Name != p.Claim || kube.ContentHash(pv.Spec) != kube.ContentHash(*p.PVSpec) {
		return d.ErrNotReady
	}
	node, e := k.CoreV1().Nodes().Get(ctx, p.Node, meta.GetOptions{})
	if e != nil || string(node.UID) != p.NodeUID || node.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	return ctx.Err()
}
