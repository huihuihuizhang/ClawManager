package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackupinstallationowner/install"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// The mount author produces installation DATA only. The original Node owner
// must still resolve CRI, open the device/mount FDs and qualify the ext4/NFS
// filesystem. Actual SQL task/lease/attempt fields are bound at registration.
func originalLonghornRecoveryURI(cfg DeploymentConfig, materials productionCaptureMaterials, now time.Time) (string, error) {
	if cfg.RuntimeSources == nil || cfg.RuntimeSources.SharedObserver == nil || cfg.RuntimeSources.LonghornHold != nil || materials.Discovery == nil || materials.Discovery.ControllerServiceAccountUID == "" {
		return "", install.ErrInstall
	}
	o := cfg.RuntimeSources.SharedObserver
	ca, err := pinnedDeploymentFile(o.CAFile, o.CASHA256, 262144)
	if err != nil {
		return "", install.ErrInstall
	}
	cert, err := pinnedDeploymentFile(o.CertificateFile, o.CertificateSHA256, 262144)
	if err != nil {
		return "", install.ErrInstall
	}
	key, err := pinnedDeploymentFile(o.KeyFile, o.KeySHA256, 262144)
	if err != nil {
		return "", install.ErrInstall
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) != 1 {
		return "", install.ErrInstall
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return "", install.ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return "", install.ErrInstall
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", install.ErrInstall
	}
	want := "spiffe://" + cfg.TrustDomain + "/system-backup/" + url.PathEscape(cfg.InstallationID) + "/namespace/" + url.PathEscape(cfg.NamespaceUID) + "/controller-service-account/" + url.PathEscape(materials.Discovery.ControllerServiceAccountUID)
	if leaf.URIs[0].String() != want {
		return "", install.ErrInstall
	}
	return want, nil
}

func originalLonghornInstallationBinding(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, source originalLonghornSource, node string) (q.ObservationBinding, error) {
	var zero q.ObservationBinding
	if cfg.RuntimeSources == nil || cfg.RuntimeSources.SharedObserver == nil || cfg.Security.NodeUIDs[node] == "" {
		return zero, install.ErrInstall
	}
	endpoint, found := cfg.RuntimeSources.SharedObserver.Endpoints[node]
	if !found || endpoint.URL == "" || endpoint.ServerURI == "" {
		return zero, install.ErrInstall
	}
	n, err := api.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil || n.DeletionTimestamp != nil || string(n.UID) != cfg.Security.NodeUIDs[node] || n.Status.NodeInfo.OperatingSystem != "linux" {
		return zero, install.ErrInstall
	}
	ready := false
	for _, c := range n.Status.Conditions {
		ready = ready || c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue
	}
	if !ready {
		return zero, install.ErrInstall
	}
	return q.ObservationBinding{Kind: q.LonghornExt4Protocol, InstallationID: cfg.InstallationID,
		Namespace: source.Namespace, NamespaceUID: source.NamespaceUID, Node: node, NodeUID: string(n.UID)}, nil
}

func originalLonghornProviderProcess(pod *corev1.Pod) (corev1.ContainerStatus, error) {
	var zero corev1.ContainerStatus
	if pod == nil || pod.DeletionTimestamp != nil || pod.UID == "" || pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning ||
		len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 {
		return zero, install.ErrInstall
	}
	s := pod.Status.ContainerStatuses[0]
	parts := strings.Split(s.ContainerID, "://")
	if !s.Ready || s.Name != pod.Spec.Containers[0].Name || s.State.Running == nil || len(parts) != 2 || (parts[0] != "containerd" && parts[0] != "cri-o") || !formalCandidateDigest(parts[1]) {
		return zero, install.ErrInstall
	}
	return s, nil
}

func observeOriginalLonghornHoldMaterials(ctx context.Context, clients *productionMetadataClients, cfg DeploymentConfig, scope *productionPersistentMountScope, sources map[string]originalLonghornSource, recoveryURI string) (q.LonghornExt4Materials, error) {
	out := q.LonghornExt4Materials{Version: q.LonghornExt4Protocol, RecoveryURI: recoveryURI,
		Sources: []q.LonghornExt4SourceCoordinates{}, Clients: []q.LonghornRWXClientCoordinates{}}
	if clients == nil || clients.API == nil || clients.Dynamic == nil || scope == nil || recoveryURI == "" || len(sources) == 0 {
		return out, install.ErrInstall
	}
	parts := make([]string, 0, len(sources))
	for part := range sources {
		parts = append(parts, part)
	}
	sort.Strings(parts)
	seen := map[string]bool{}
	for _, part := range parts {
		source := sources[part]
		raw, err := json.Marshal(source)
		if err != nil {
			return out, install.ErrInstall
		}
		digest := hash(raw)
		if seen[digest] {
			continue // Several capture parts may share this exact volume/source.
		}
		seen[digest] = true
		if len(seen) > 8 || source.Source.Kind != "PersistentVolumeClaim" || !strings.HasPrefix(source.Handle, "pvc-") || strings.ContainsAny(source.Handle, "/\\\r\n\x00") {
			return out, install.ErrInstall
		}
		if err := checkRecoveredLonghornVolume(ctx, clients.API, source); err != nil {
			return out, err
		}
		pv, err := clients.API.CoreV1().PersistentVolumes().Get(ctx, source.Source.PVName, metav1.GetOptions{})
		if err != nil || pv.Spec.CSI == nil || pv.Spec.CSI.FSType != "ext4" || pv.Spec.CSI.ReadOnly || pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem {
			return out, install.ErrInstall
		}
		var provider *corev1.Pod
		mountPoint := ""
		var endpoint, nfsSource string
		switch source.AccessMode {
		case corev1.ReadWriteOnce:
			// This task's RWO source is a real running tenant Deployment. A
			// future keeper is supplied by the existing task registration owner.
			var tenant *runningTenantProMount
			for n := range scope.RunningTenantPro {
				m := &scope.RunningTenantPro[n]
				if m.Source.Namespace == source.Namespace && m.NamespaceUID == source.NamespaceUID && m.Identity == source.Source {
					if tenant != nil {
						return out, install.ErrInstall
					}
					tenant = m
				}
			}
			if tenant == nil || tenant.check(ctx, clients.API, cfg.Namespace) != nil {
				return out, install.ErrInstall
			}
			provider, err = clients.API.CoreV1().Pods(source.Namespace).Get(ctx, tenant.Source.Pod, metav1.GetOptions{})
			if err != nil {
				return out, err
			}
			volumes := map[string]bool{}
			for _, v := range provider.Spec.Volumes {
				if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == source.Source.Name && !v.PersistentVolumeClaim.ReadOnly {
					volumes[v.Name] = true
				}
			}
			for _, c := range provider.Spec.Containers {
				for _, m := range c.VolumeMounts {
					if volumes[m.Name] && !m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" && cleanMountRoot(m.MountPath) {
						if mountPoint != "" && mountPoint != m.MountPath {
							return out, install.ErrInstall
						}
						mountPoint = m.MountPath
					}
				}
			}
			if mountPoint == "" {
				return out, install.ErrInstall
			}
		case corev1.ReadWriteMany:
			volumes := clients.Dynamic.Resource(schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}).Namespace(source.ProviderNamespace)
			volume, e := volumes.Get(ctx, source.Handle, metav1.GetOptions{})
			if e != nil || volume.GetUID() == "" || volume.GetDeletionTimestamp() != nil {
				return out, install.ErrInstall
			}
			status, ok := volume.Object["status"].(map[string]any)
			if !ok || status["shareState"] != "running" {
				return out, writerAPIReadFailure(install.ErrInstall, ctx, "longhorn_share_manager_state", "LonghornVolume", nil)
			}
			share, _ := status["shareEndpoint"].(string)
			u, e := url.Parse(share)
			if e != nil || u.Scheme != "nfs" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || !path.IsAbs(u.Path) || path.Clean(u.Path) != u.Path || u.Path == "/" {
				return out, install.ErrInstall
			}
			manager, e := clients.Dynamic.Resource(schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "sharemanagers"}).Namespace(source.ProviderNamespace).Get(ctx, source.Handle, metav1.GetOptions{})
			if e != nil || manager.GetUID() == "" || manager.GetDeletionTimestamp() != nil {
				return out, install.ErrInstall
			}
			provider, err = clients.API.CoreV1().Pods(source.ProviderNamespace).Get(ctx, "share-manager-"+source.Handle, metav1.GetOptions{})
			if err != nil {
				return out, err
			}
			owner := metav1.GetControllerOf(provider)
			if owner == nil || owner.Kind != "ShareManager" || owner.APIVersion != "longhorn.io/v1beta2" || owner.Name != source.Handle || owner.UID != manager.GetUID() {
				return out, install.ErrInstall
			}
			endpoint = u.Hostname()
			if net.ParseIP(endpoint) == nil {
				if !strings.HasSuffix(endpoint, "."+source.ProviderNamespace+".svc.cluster.local") {
					return out, install.ErrInstall
				}
				s, e := clients.API.CoreV1().Services(source.ProviderNamespace).Get(ctx, strings.Split(endpoint, ".")[0], metav1.GetOptions{})
				if e != nil || s.DeletionTimestamp != nil || len(s.Spec.Selector) == 0 {
					return out, install.ErrInstall
				}
				for k, v := range s.Spec.Selector {
					if provider.Labels[k] != v {
						return out, install.ErrInstall
					}
				}
				endpoint = s.Spec.ClusterIP
			}
			if net.ParseIP(endpoint) == nil {
				return out, install.ErrInstall
			}
			nfsSource = u.Hostname() + ":" + u.Path
		default:
			return out, install.ErrInstall
		}
		process, err := originalLonghornProviderProcess(provider)
		if err != nil {
			return out, err
		}
		binding, err := originalLonghornInstallationBinding(ctx, clients.API, cfg, source, provider.Spec.NodeName)
		if err != nil {
			return out, err
		}
		identity, err := q.LonghornExt4SourceIdentity(digest, source.ProviderUID, binding.NodeUID)
		if err != nil {
			return out, err
		}
		out.Sources = append(out.Sources, q.LonghornExt4SourceCoordinates{LonghornNamespace: source.ProviderNamespace,
			Binding: binding, Identity: identity, VolumeHandle: source.Handle, PVCName: source.Source.Name, PVCUID: source.Source.UID, PVUID: source.Source.PVUID,
			OriginalSourceSHA256: digest, ProviderNamespaceUID: source.ProviderUID, ProviderNamespace: provider.Namespace,
			ProviderPodName: provider.Name, ProviderPodUID: string(provider.UID), ProviderContainerID: process.ContainerID, MountPoint: mountPoint})
		if source.AccessMode == corev1.ReadWriteMany {
			clientPins, err := observeOriginalLonghornRWXTemplates(ctx, clients.API, cfg, source, digest, endpoint, nfsSource)
			if err != nil {
				return out, err
			}
			out.Clients = append(out.Clients, clientPins...)
		}
	}
	if len(out.Clients) > 128 {
		return out, install.ErrInstall
	}
	return out, ctx.Err()
}

func observeOriginalLonghornRWXTemplates(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, source originalLonghornSource, digest, endpoint, nfsSource string) ([]q.LonghornRWXClientCoordinates, error) {
	pods, err := api.CoreV1().Pods(source.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || pods.Continue != "" {
		return nil, install.ErrInstall
	}
	byNode := map[string]q.LonghornRWXClientCoordinates{}
	for _, pod := range pods.Items {
		volumes := map[string]bool{}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == source.Source.Name {
				volumes[v.Name] = true
			}
		}
		if len(volumes) == 0 {
			continue
		}
		statuses := map[string]corev1.ContainerStatus{}
		for _, s := range append(append(append([]corev1.ContainerStatus{}, pod.Status.ContainerStatuses...), pod.Status.InitContainerStatuses...), pod.Status.EphemeralContainerStatuses...) {
			statuses[s.Name] = s
		}
		for _, c := range append(append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...), ephemeralLonghornContainers(pod.Spec.EphemeralContainers)...) {
			if statuses[c.Name].State.Running == nil {
				continue
			}
			for _, m := range c.VolumeMounts {
				if !volumes[m.Name] {
					continue
				}
				if !cleanMountRoot(m.MountPath) || m.SubPathExpr != "" || pod.DeletionTimestamp != nil || pod.UID == "" || statuses[c.Name].ContainerID == "" {
					return nil, install.ErrInstall
				}
				binding, err := originalLonghornInstallationBinding(ctx, api, cfg, source, pod.Spec.NodeName)
				if err != nil {
					return nil, err
				}
				identity, err := q.LonghornExt4SourceIdentity(digest, source.ProviderUID, binding.NodeUID)
				if err != nil {
					return nil, err
				}
				value := q.LonghornRWXClientCoordinates{Binding: binding, Identity: identity, VolumeHandle: source.Handle,
					PVCName: source.Source.Name, PVCUID: source.Source.UID, PVUID: source.Source.PVUID, OriginalSourceSHA256: digest,
					ProviderNamespaceUID: source.ProviderUID, PodNamespace: source.Namespace, MountPoint: m.MountPath, Endpoint: endpoint, NFSSource: nfsSource}
				// Native v3 installs one client template per source/Node identity.
				// Reject ambiguous mount roots instead of silently dropping one.
				if previous, found := byNode[pod.Spec.NodeName]; found && previous != value {
					return nil, install.ErrInstall
				}
				byNode[pod.Spec.NodeName] = value
			}
		}
	}
	nodes := make([]string, 0, len(byNode))
	for node := range byNode {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	out := make([]q.LonghornRWXClientCoordinates, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, byNode[node])
	}
	return out, nil
}
