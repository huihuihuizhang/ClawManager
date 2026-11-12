package install

import (
	owner "clawreef/internal/systembackupinstallationowner"
	"context"
	"database/sql"
	"k8s.io/client-go/kubernetes"
	"net"
	"net/url"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Public identity comparisons only. No Pod env, Secret, JWT, provider token,
// signed owner bytes or credential material is returned or journaled here.
type originalVaultProviderScope struct {
	NamespaceUID, DeploymentUID, DeploymentSpecSHA256, PodUID, PodSpecSHA256 string
	ReplicaSetUID, NodeUID, ServiceAccountUID, ImageID, ContainerID          string
	ServiceUID, ServiceSpecSHA256, EndpointSlicesSHA256                      string
	ClaimUID, ClaimSpecSHA256, PVUID, PVSpecSHA256, VolumeHandle             string
	AttachmentUID, AttachmentSHA256                                          string
}

const originalProviderVaultImage = "10.130.14.23:5000/clawmanager-backup-vault@sha256:2194d86d9ddbb17a6d017c3b2e555e1d4431195f18c3cb2827e3f61320fb6855"

// Finite native entrypoint of the independently inspected immutable original
// Vault image. An alternate shell, init program, injected preload or mounted
// executable is an additional writer, never covered by provider availability.
func originalVaultNativeEntry(spec corev1.PodSpec, c corev1.Container) bool {
	command, args := c.Command, c.Args
	// The persistent original installer writes the native argv entirely in
	// Command. Accept that exact spelling without changing the observed spec
	// or admitting a shell, dev mode, extra flags or an alternate executable.
	if reflect.DeepEqual(command, []string{"/bin/vault", "server", "-config=/config/server.json"}) && len(args) == 0 {
		command, args = []string{"/bin/vault"}, []string{"server", "-config=/config/server.json"}
	}
	if c.Lifecycle != nil || len(c.EnvFrom) != 0 || len(command) > 1 || len(command) == 1 && command[0] != "/bin/vault" {
		return false
	}
	for _, env := range c.Env {
		switch env.Name {
		case "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV":
			return false
		}
	}
	for _, mount := range c.VolumeMounts {
		for _, root := range []string{"/", "/bin", "/sbin", "/usr", "/app/start.sh", "/docker-entrypoint.sh"} {
			if mount.MountPath == root || root != "/" && strings.HasPrefix(mount.MountPath, root+"/") {
				return false
			}
		}
	}
	if len(command) == 0 && len(args) == 0 {
		args = []string{"server", "-config=/vault/config/vault.hcl"}
	}
	if len(args) < 2 || args[0] != "server" {
		return false
	}
	config := ""
	if len(args) == 2 && strings.HasPrefix(args[1], "-config=") {
		config = strings.TrimPrefix(args[1], "-config=")
	}
	if len(args) == 3 && args[1] == "-config" {
		config = args[2]
	}
	if !path.IsAbs(config) || path.Clean(config) != config || strings.ContainsAny(config, "\\\x00\r\n") {
		return false
	}
	for _, mount := range c.VolumeMounts {
		if !mount.ReadOnly || config != mount.MountPath && !strings.HasPrefix(config, mount.MountPath+"/") {
			continue
		}
		for _, volume := range spec.Volumes {
			if volume.Name == mount.Name && (volume.ConfigMap != nil || volume.Secret != nil || volume.Projected != nil) {
				return true
			}
		}
	}
	return false
}

// This is the exact finite initializer from the original persistent installer,
// not permission to run arbitrary init writers. The private claim's independent
// alias/attachment/business-use census below remains mandatory.
func originalVaultInstallerInit(spec corev1.PodSpec, input VaultProviderWorkloadSelection) bool {
	if len(spec.InitContainers) == 0 {
		return true
	}
	if len(spec.InitContainers) != 1 || input.DataMountPath != "/data" || spec.SecurityContext == nil {
		return false
	}
	pod := spec.SecurityContext
	if pod.RunAsUser == nil || *pod.RunAsUser != 65532 || pod.RunAsGroup == nil || *pod.RunAsGroup != 65532 || pod.RunAsNonRoot == nil || !*pod.RunAsNonRoot || pod.FSGroup == nil || *pod.FSGroup != 65532 {
		return false
	}
	volume := ""
	for _, v := range spec.Volumes {
		if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == input.Claim && !v.PersistentVolumeClaim.ReadOnly {
			if volume != "" {
				return false
			}
			volume = v.Name
		}
	}
	if volume == "" {
		return false
	}
	no, yes := false, true
	want := corev1.Container{Name: "prepare-raft-directory", Image: originalProviderVaultImage, ImagePullPolicy: corev1.PullNever,
		Command:                []string{"/bin/sh", "-ec", "umask 077; mkdir -p /data/raft; test -d /data/raft; test -w /data/raft"},
		TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
		Resources:       corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("16Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
		VolumeMounts:    []corev1.VolumeMount{{Name: volume, MountPath: "/data"}}}
	return reflect.DeepEqual(spec.InitContainers[0], want)
}

func originalVaultMountSpec(spec corev1.PodSpec, input VaultProviderWorkloadSelection) bool {
	if input.Container == "" || !path.IsAbs(input.DataMountPath) || path.Clean(input.DataMountPath) != input.DataMountPath || strings.ContainsAny(input.DataMountPath, "\\\x00\r\n") || input.DataMountPath == "/" || len(spec.Containers) != 1 || !originalVaultInstallerInit(spec, input) || len(spec.EphemeralContainers) != 0 || spec.HostPID || spec.HostIPC || spec.HostNetwork || spec.ShareProcessNamespace != nil && *spec.ShareProcessNamespace {
		return false
	}
	container := spec.Containers[0]
	if container.Name != input.Container || !originalVaultNativeEntry(spec, container) || len(container.VolumeDevices) != 0 || container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
		return false
	}
	volumes := map[string]corev1.Volume{}
	claims := 0
	for _, volume := range spec.Volumes {
		if volumes[volume.Name].Name != "" {
			return false
		}
		volumes[volume.Name] = volume
		if volume.PersistentVolumeClaim != nil {
			if volume.PersistentVolumeClaim.ClaimName != input.Claim || volume.PersistentVolumeClaim.ReadOnly {
				return false
			}
			claims++
		} else if volume.Secret == nil && volume.ConfigMap == nil && volume.Projected == nil && volume.DownwardAPI == nil && volume.EmptyDir == nil {
			return false
		}
	}
	if claims != 1 {
		return false
	}
	dataMounts := 0
	for _, mount := range container.VolumeMounts {
		volume, found := volumes[mount.Name]
		if !found || mount.SubPath != "" || mount.SubPathExpr != "" || mount.MountPropagation != nil && *mount.MountPropagation != corev1.MountPropagationNone {
			return false
		}
		if volume.PersistentVolumeClaim != nil {
			if mount.MountPath != input.DataMountPath || mount.ReadOnly {
				return false
			}
			dataMounts++
		} else if volume.EmptyDir == nil && !mount.ReadOnly {
			return false
		}
	}
	return dataMounts == 1
}

func originalVaultUsesClaim(spec corev1.PodSpec, claim string) bool {
	for _, volume := range spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim {
			return true
		}
	}
	return false
}

// This initial dependency profile supports only the field's dedicated RWO
// Longhorn filesystem volume. It does not claim CSI source snapshots/cold cuts.
// Longhorn's CSI volumeHandle names its backend volume; attachment and complete
// PV alias census are checked below. Other drivers require their own reviewed
// backend identity mapping instead of treating different PV names as isolation.
func originalVaultPrivateCSI(pv *corev1.PersistentVolume) bool {
	return pv != nil && pv.Spec.CSI != nil && pv.Spec.CSI.Driver == "driver.longhorn.io" && pv.Spec.CSI.VolumeHandle != "" && !pv.Spec.CSI.ReadOnly && (pv.Spec.CSI.FSType == "" || pv.Spec.CSI.FSType == "ext4" || pv.Spec.CSI.FSType == "xfs") && len(pv.Spec.AccessModes) == 1 && pv.Spec.AccessModes[0] == corev1.ReadWriteOnce && (pv.Spec.VolumeMode == nil || *pv.Spec.VolumeMode == corev1.PersistentVolumeFilesystem)
}

type VaultProviderWorkloadSelection struct {
	Deployment, DeploymentUID, Container, ImageID       string
	Service, ServiceUID, Claim, ClaimUID, DataMountPath string
}
type VaultProviderScopeData = originalVaultProviderScope

func VaultProviderWorkloadCoordinates(s OriginalVaultProviderSelection) VaultProviderWorkloadSelection {
	return VaultProviderWorkloadSelection{s.Deployment, s.DeploymentUID, s.Container, s.ImageID, s.Service, s.ServiceUID, s.Claim, s.ClaimUID, s.DataMountPath}
}
func (p *originalVaultProviderDependency) readScope(ctx context.Context) (originalVaultProviderScope, error) {
	if p == nil || p.origin != p || p.set == nil {
		return originalVaultProviderScope{}, ErrInstall
	}
	i := p.set.owner.operator.installer
	return ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, VaultProviderWorkloadCoordinates(p.selection), p.binding.Provider.Endpoint)
}

// ObserveInstalledVaultProviderScope returns observed comparison DATA only.
// Its concrete callers independently authenticate installer/task/recovery
// authority. It never manufactures an Installer, owner, grant or source hold.
func ObserveInstalledVaultProviderScope(ctx context.Context, source *sql.DB, k kubernetes.Interface, target owner.Target, input VaultProviderWorkloadSelection, endpointURL string) (VaultProviderScopeData, error) {
	var out originalVaultProviderScope
	if ctx == nil || ctx.Err() != nil || source == nil || nilClient(k) || target.Namespace == "" || target.NamespaceUID == "" {
		return out, ErrInstall
	}
	ns := target.Namespace
	endpoint, e := url.Parse(endpointURL)
	if e != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || input.Service == "" || input.ServiceUID == "" || input.Claim == "" || input.ClaimUID == "" {
		return out, ErrInstall
	}
	service, e := k.CoreV1().Services(ns).Get(ctx, input.Service, metav1.GetOptions{})
	if e != nil || string(service.UID) != input.ServiceUID || service.DeletionTimestamp != nil || service.Spec.Type != corev1.ServiceTypeClusterIP || service.Spec.ClusterIP == "" || service.Spec.ClusterIP == corev1.ClusterIPNone || service.Spec.ExternalName != "" || len(service.Spec.ExternalIPs) != 0 || len(service.Spec.Selector) == 0 || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Protocol != corev1.ProtocolTCP {
		return out, ErrInstall
	}
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	if strconv.Itoa(int(service.Spec.Ports[0].Port)) != port {
		return out, ErrInstall
	}
	host := endpoint.Hostname()
	validHost := host == service.Name || host == service.Name+"."+ns || host == service.Name+"."+ns+".svc"
	clusterIPs := map[string]bool{}
	for _, ip := range service.Spec.ClusterIPs {
		if net.ParseIP(ip) == nil {
			return out, ErrInstall
		}
		clusterIPs[ip] = true
		validHost = validHost || host == ip
	}
	if len(clusterIPs) == 0 {
		clusterIPs[service.Spec.ClusterIP] = true
		validHost = validHost || host == service.Spec.ClusterIP
	}
	if !validHost {
		return out, ErrInstall
	}
	resolved, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil || len(resolved) == 0 {
		return out, ErrInstall
	}
	for _, ip := range resolved {
		if !clusterIPs[ip.IP.String()] {
			return out, ErrInstall
		}
	}
	deployment, e := k.AppsV1().Deployments(ns).Get(ctx, input.Deployment, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != input.DeploymentUID || deployment.DeletionTimestamp != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.Replicas != 1 || deployment.Status.ReadyReplicas != 1 || deployment.Status.UpdatedReplicas != 1 || !originalVaultMountSpec(deployment.Spec.Template.Spec, input) {
		return out, ErrInstall
	}
	selector, e := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if e != nil || selector.Empty() {
		return out, ErrInstall
	}
	pods, e := k.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if e != nil || len(pods.Items) > 10000 {
		return out, ErrInstall
	}
	var pod *corev1.Pod
	for n := range pods.Items {
		candidate := &pods.Items[n]
		if selector.Matches(labels.Set(candidate.Labels)) {
			if pod != nil {
				return out, ErrInstall
			}
			pod = candidate
		}
	}
	if pod == nil || pod.UID == "" || pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil || !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(pod.Labels)) || !originalVaultMountSpec(pod.Spec, input) || len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" || pod.OwnerReferences[0].Controller == nil || !*pod.OwnerReferences[0].Controller || len(pod.Status.ContainerStatuses) != 1 {
		return out, ErrInstall
	}
	status := pod.Status.ContainerStatuses[0]
	imageParts := strings.Split(input.ImageID, "@sha256:")
	if input.ImageID != originalProviderVaultImage || len(imageParts) != 2 || !digestPattern.MatchString(imageParts[1]) || status.Name != input.Container || !status.Ready || status.State.Running == nil || status.ContainerID == "" || status.ImageID != input.ImageID || status.RestartCount != 0 {
		return out, ErrInstall
	}
	replicaSet, e := k.AppsV1().ReplicaSets(ns).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if e != nil || replicaSet.UID == "" || replicaSet.UID != pod.OwnerReferences[0].UID || replicaSet.DeletionTimestamp != nil || len(replicaSet.OwnerReferences) != 1 || replicaSet.OwnerReferences[0].Kind != "Deployment" || replicaSet.OwnerReferences[0].UID != deployment.UID || replicaSet.OwnerReferences[0].Name != deployment.Name || replicaSet.OwnerReferences[0].Controller == nil || !*replicaSet.OwnerReferences[0].Controller {
		return out, ErrInstall
	}
	for n := range pods.Items {
		other := &pods.Items[n]
		if other.UID != pod.UID && originalVaultUsesClaim(other.Spec, input.Claim) {
			return out, ErrInstall
		}
	}
	deployments, e := k.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if e != nil || len(deployments.Items) > 10000 {
		return out, ErrInstall
	}
	for _, other := range deployments.Items {
		if other.UID != deployment.UID && originalVaultUsesClaim(other.Spec.Template.Spec, input.Claim) {
			return out, ErrInstall
		}
	}
	retained, e := k.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{})
	if e != nil || len(retained.Items) > 10000 {
		return out, ErrInstall
	}
	for _, other := range retained.Items {
		if !originalVaultUsesClaim(other.Spec.Template.Spec, input.Claim) {
			continue
		}
		if len(other.OwnerReferences) != 1 || other.OwnerReferences[0].Kind != "Deployment" || other.OwnerReferences[0].UID != deployment.UID {
			return out, ErrInstall
		}
	}
	var businessUses uint64
	if source.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances WHERE pvc_name=?", input.Claim).Scan(&businessUses) != nil || businessUses != 0 {
		return out, ErrInstall
	}
	claim, e := k.CoreV1().PersistentVolumeClaims(ns).Get(ctx, input.Claim, metav1.GetOptions{})
	if e != nil || string(claim.UID) != input.ClaimUID || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound {
		return out, ErrInstall
	}
	pv, e := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != ns || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID || !originalVaultPrivateCSI(pv) {
		return out, ErrInstall
	}
	allClaims, e := k.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if e != nil || len(allClaims.Items) > 10000 {
		return out, ErrInstall
	}
	for _, other := range allClaims.Items {
		if other.UID != claim.UID && other.Spec.VolumeName == pv.Name {
			return out, ErrInstall
		}
	}
	allPV, e := k.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if e != nil || len(allPV.Items) > 10000 {
		return out, ErrInstall
	}
	for _, other := range allPV.Items {
		if other.UID != pv.UID && other.Spec.CSI != nil && other.Spec.CSI.Driver == pv.Spec.CSI.Driver && other.Spec.CSI.VolumeHandle == pv.Spec.CSI.VolumeHandle {
			return out, ErrInstall
		}
	}
	attachments, e := k.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if e != nil || len(attachments.Items) > 10000 {
		return out, ErrInstall
	}
	for _, attachment := range attachments.Items {
		if attachment.Spec.Source.PersistentVolumeName == nil || *attachment.Spec.Source.PersistentVolumeName != pv.Name {
			continue
		}
		if out.AttachmentUID != "" || attachment.DeletionTimestamp != nil || attachment.Spec.Attacher != pv.Spec.CSI.Driver || attachment.Spec.NodeName != pod.Spec.NodeName || !attachment.Status.Attached || attachment.Status.AttachError != nil || attachment.Status.DetachError != nil {
			return out, ErrInstall
		}
		out.AttachmentUID, out.AttachmentSHA256 = string(attachment.UID), originalObjectSHA(attachment.Spec)
	}
	if out.AttachmentUID == "" {
		return out, ErrInstall
	}
	node, e := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if e != nil || node.UID == "" || node.DeletionTimestamp != nil || node.Status.NodeInfo.OperatingSystem != "linux" {
		return out, ErrInstall
	}
	account, e := k.CoreV1().ServiceAccounts(ns).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if e != nil || account.UID == "" || account.DeletionTimestamp != nil {
		return out, ErrInstall
	}
	namespace, e := k.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if e != nil || string(namespace.UID) != target.NamespaceUID || namespace.DeletionTimestamp != nil {
		return out, ErrInstall
	}
	slices, e := k.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"kubernetes.io/service-name": service.Name}.String()})
	if e != nil || len(slices.Items) < 1 || len(slices.Items) > 8 {
		return out, ErrInstall
	}
	addresses := map[string]bool{}
	for _, ip := range pod.Status.PodIPs {
		addresses[ip.IP] = true
	}
	if len(addresses) == 0 {
		return out, ErrInstall
	}
	endpoints := 0
	slicePins := []string{}
	for _, slice := range slices.Items {
		if slice.DeletionTimestamp != nil || len(slice.OwnerReferences) != 1 || slice.OwnerReferences[0].Kind != "Service" || slice.OwnerReferences[0].UID != service.UID || len(slice.Ports) != 1 || slice.Ports[0].Port == nil || slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP {
			return out, ErrInstall
		}
		target := service.Spec.Ports[0].TargetPort
		portMatch := target.IntVal > 0 && target.IntVal == *slice.Ports[0].Port
		if target.StrVal != "" {
			for _, declared := range pod.Spec.Containers[0].Ports {
				portMatch = portMatch || declared.Name == target.StrVal && declared.ContainerPort == *slice.Ports[0].Port
			}
		}
		if !portMatch {
			return out, ErrInstall
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.UID != pod.UID || endpoint.TargetRef.Namespace != ns || endpoint.TargetRef.Name != pod.Name || endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating || endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving {
				return out, ErrInstall
			}
			for _, ip := range endpoint.Addresses {
				if !addresses[ip] {
					return out, ErrInstall
				}
			}
			endpoints++
		}
		slicePins = append(slicePins, string(slice.UID)+"/"+slice.ResourceVersion+"/"+originalObjectSHA(slice.Endpoints)+"/"+originalObjectSHA(slice.Ports))
	}
	if endpoints < 1 || endpoints > len(addresses) {
		return out, ErrInstall
	}
	sort.Strings(slicePins)
	out.NamespaceUID, out.DeploymentUID, out.DeploymentSpecSHA256 = string(namespace.UID), string(deployment.UID), originalObjectSHA(deployment.Spec)
	out.PodUID, out.PodSpecSHA256, out.ReplicaSetUID = string(pod.UID), originalObjectSHA(pod.Spec), string(replicaSet.UID)
	out.NodeUID, out.ServiceAccountUID, out.ImageID, out.ContainerID = string(node.UID), string(account.UID), status.ImageID, status.ContainerID
	out.ServiceUID, out.ServiceSpecSHA256, out.EndpointSlicesSHA256 = string(service.UID), originalObjectSHA(service.Spec), originalObjectSHA(slicePins)
	out.ClaimUID, out.ClaimSpecSHA256, out.PVUID, out.PVSpecSHA256, out.VolumeHandle = string(claim.UID), originalObjectSHA(claim.Spec), string(pv.UID), originalObjectSHA(pv.Spec), pv.Spec.CSI.VolumeHandle
	return out, nil
}
