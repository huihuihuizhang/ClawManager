package systembackupexecution

import (
	"context"
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type sourceRecoveredPod struct {
	Namespace, Name, UID, ResourceVersion, Node, NodeUID, SpecSHA256 string
	Containers                                                       []string
	Volumes                                                          []sourceRecoveredVolume
}

// These are positive Kubernetes API bindings, not a claim that an API client
// inspected a process's kernel mount namespace. Lite's separate native receipt
// scopes the actual instance lifecycle inside its shared Pod.
type sourceRecoveredVolume struct {
	Name, Kind, DeclarationSHA256                                     string
	Claim, ClaimUID, ClaimVersion, PV, PVUID, PVVersion, PVSpecSHA256 string
	NFSServer, NFSExport                                              string
}

// Pre-capture observations of the original authorized platform template. These
// coordinates are included in SourceSHA256 before any source stop; Resume
// cannot repair a missing pin by adopting a current PVC/PV or NFS coordinate.
type sourceRecoveryPlatformMount struct {
	WriterID, Namespace, DeploymentUID, OriginalSpecSHA256 string
	Source                                                 corev1.Volume
	Claim                                                  *kube.MountIdentity `json:",omitempty"`
}

func (s *DeploymentService) freezePlatformSourceRecoveryMounts(ctx context.Context, owner *PublicJobOwner, writers []b.FrozenWriter) ([]sourceRecoveryPlatformMount, error) {
	// Apply the same original template policy before capture, so an already
	// unsupported admission rewrite is refused before stopping business writers.
	if err := checkOriginalSourceDeploymentTemplates(ctx, owner, writers); err != nil {
		return nil, err
	}
	return s.currentPlatformSourceRecoveryMounts(ctx, owner, writers)
}

// During capture the original Pods have deliberately been terminated. Recheck
// the original Deployment specification and storage coordinates, then compare
// these observations with the pre-stop pins; never adopt replacement pins.
func (s *DeploymentService) currentPlatformSourceRecoveryMounts(ctx context.Context, owner *PublicJobOwner, writers []b.FrozenWriter) ([]sourceRecoveryPlatformMount, error) {
	platform := map[string]PlatformDeployment{}
	for _, ref := range s.Config.Writers {
		platform["deployment/"+ref.Namespace+"/"+ref.Name] = ref
	}
	var out []sourceRecoveryPlatformMount
	for _, writer := range writers {
		ref, exists := platform[writer.ID]
		if !exists {
			continue
		}
		var cp sourceRecoveryCheckpoint
		if json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil || cp.Version != "deployment-quiesce.v1" || cp.Namespace != ref.Namespace || cp.Name != ref.Name || writer.Original.UID != ref.UID {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		dep, err := owner.Client.AppsV1().Deployments(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil || string(dep.UID) != ref.UID || dep.DeletionTimestamp != nil {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		spec := dep.Spec.DeepCopy()
		spec.Replicas = nil
		if kube.ContentHash(spec) != cp.SpecSHA256 {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		for _, volume := range dep.Spec.Template.Spec.Volumes {
			pin := sourceRecoveryPlatformMount{WriterID: writer.ID, Namespace: ref.Namespace, DeploymentUID: ref.UID, OriginalSpecSHA256: cp.SpecSHA256, Source: *volume.DeepCopy()}
			switch {
			case volume.PersistentVolumeClaim != nil:
				claim, err := owner.Client.CoreV1().PersistentVolumeClaims(ref.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
				if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
					return nil, c.ErrSourceRecoveryProofRequired
				}
				pv, err := owner.Client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
				if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != ref.Namespace || pv.Spec.ClaimRef.Name != claim.Name {
					return nil, c.ErrSourceRecoveryProofRequired
				}
				pin.Claim = &kube.MountIdentity{Volume: volume.Name, Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
			case volume.NFS != nil:
				if volume.NFS.Server == "" || !path.IsAbs(volume.NFS.Path) || path.Clean(volume.NFS.Path) != volume.NFS.Path {
					return nil, c.ErrSourceRecoveryProofRequired
				}
			case volume.HostPath != nil, volume.CSI != nil, volume.Ephemeral != nil:
				return nil, c.ErrSourceRecoveryProofRequired
			default:
				continue
			}
			out = append(out, pin)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WriterID == out[j].WriterID {
			return out[i].Source.Name < out[j].Source.Name
		}
		return out[i].WriterID < out[j].WriterID
	})
	return out, nil
}

func checkOriginalSourceDeploymentTemplates(ctx context.Context, owner *PublicJobOwner, writers []b.FrozenWriter) error {
	for _, writer := range writers {
		var cp sourceRecoveryCheckpoint
		if json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil || cp.Version != "deployment-quiesce.v1" {
			continue
		}
		dep, err := owner.Client.AppsV1().Deployments(cp.Namespace).Get(ctx, cp.Name, metav1.GetOptions{})
		if err != nil || string(dep.UID) != writer.Original.UID || dep.DeletionTimestamp != nil {
			return c.ErrSourceRecoveryProofRequired
		}
		spec := dep.Spec.DeepCopy()
		spec.Replicas = nil
		if kube.ContentHash(spec) != cp.SpecSHA256 {
			return c.ErrSourceRecoveryProofRequired
		}
		for _, original := range cp.Pods {
			pod, err := owner.Client.CoreV1().Pods(cp.Namespace).Get(ctx, original.Name, metav1.GetOptions{})
			if err != nil || string(pod.UID) != original.UID || pod.Spec.NodeName != original.Node || !kube.SourceRecoveryPodSpecMatches(dep.Spec.Template.Spec, pod.Spec) {
				return c.ErrSourceRecoveryProofRequired
			}
		}
	}
	return nil
}

type sourceRecoveryPhysicalFacts struct {
	Version, Kind string
	Runtime       *c.SourceRecoveryRuntime `json:",omitempty"`
	Recovered     []sourceRecoveredPod
	StopWitnesses []c.SourceRecoverySQLReference
}

type sourceRecoveryCheckpoint struct {
	Version, Namespace, Name, FenceID, SpecSHA256, RestartRef string
	Replicas                                                  int32
	Pods                                                      []quiesce.PodIdentity
	Process                                                   quiesce.PodIdentity
}

func sourceRecoveryStateSHA(writer b.FrozenWriter) string {
	raw, _ := json.Marshal(d.WriterState{UID: writer.Original.UID, Generation: writer.Original.Generation, Running: writer.Original.Running, Checkpoint: writer.Original.Checkpoint})
	return hash(raw)
}

// observeSourceRecovery is the concrete post-Resume producer. Its only expected
// set is desc.Writers from controller-authenticated original encrypted bytes.
// Config lists classify existing owners; they never expand that expected set.
func (x *productionSourceBinding) observeSourceRecovery(ctx context.Context, in d.Input, desc b.Discovery) ([]c.SourceRecoveryObservation, error) {
	if x == nil || x.service == nil || x.owner == nil || x.service.RuntimeControl == nil || x.service.Config.RuntimeSources == nil || x.owner.Gate.Recovery.Check(ctx, in.Authority) != nil {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	s, o := x.service, x.owner
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if hash(desc.Source) != desc.SourceSHA256 || decodeMetadataCanonical(desc.Source, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.Version != productionCaptureMetadataVersion {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	instances := map[int]b.InstanceIdentity{}
	for _, instance := range source.Instances {
		if instance.ID <= 0 || instances[instance.ID].ID != 0 {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		instances[instance.ID] = instance
	}
	platform := map[string]PlatformDeployment{}
	for _, ref := range s.Config.Writers {
		platform["deployment/"+ref.Namespace+"/"+ref.Name] = ref
	}
	participants := map[string]bool{}
	for _, id := range s.Config.RuntimeSources.LeaseParticipants {
		participants[id] = true
	}
	out := make([]c.SourceRecoveryObservation, 0, len(desc.Writers))
	seen := map[string]bool{}
	for _, writer := range desc.Writers {
		if writer.ID == "" || seen[writer.ID] {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		seen[writer.ID] = true
		ob := c.SourceRecoveryObservation{WriterID: writer.ID, OriginalSHA256: sourceRecoveryStateSHA(writer)}
		if participants[writer.ID] {
			participant, err := o.Gate.ObserveSourceRecoveryParticipant(ctx, in, writer)
			if err != nil {
				return nil, err
			}
			out = append(out, participant)
			continue
		}
		facts := sourceRecoveryPhysicalFacts{Version: "source-recovery-physical-observation.v1"}
		var cp sourceRecoveryCheckpoint
		ref, isPlatform := platform[writer.ID]
		if !isPlatform {
			runtime, err := s.RuntimeControl.ObserveSourceRecoveryRuntime(ctx, in, writer)
			if err != nil {
				return nil, err
			}
			instance, exists := instances[runtime.Spec.Source.ID]
			if !exists || instance != runtime.Spec.Source {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			delete(instances, instance.ID)
			facts.Runtime, facts.Kind = &runtime, runtime.Spec.Kind
			ob.References = append(ob.References, runtime.References...)
			if runtime.Spec.Kind == "gateway" {
				pod, err := o.Client.CoreV1().Pods(runtime.Spec.RuntimeNamespace()).Get(ctx, runtime.Spec.RuntimePod(), metav1.GetOptions{})
				if err != nil || string(pod.UID) != runtime.Spec.UID {
					return nil, c.ErrSourceRecoveryProofRequired
				}
				observed, err := x.observeRecoveredPod(ctx, pod, metadata)
				if err != nil || x.checkRecoveredInstanceMount(pod, instance, runtime.SpecSHA256, metadata) != nil {
					return nil, c.ErrSourceRecoveryProofRequired
				}
				facts.Recovered = []sourceRecoveredPod{observed}
				ob.Scope = "native_instance_pid_namespace_and_mount_lifecycle_with_kubernetes_volume_bindings"
				ob.Facts, _ = json.Marshal(facts)
				out = append(out, ob)
				continue
			}
		}
		if json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil || cp.Namespace != s.Config.Namespace || cp.FenceID != in.Authority.TaskPublicID+"/attempt/"+strconv.FormatUint(in.Authority.AttemptNo, 10) || !formalCandidateDigest(cp.SpecSHA256) || !writer.Original.Running {
			// Originally stopped writers require an independent positive native
			// stopped observation. Empty lists or SQL stopped are insufficient.
			return nil, c.ErrSourceRecoveryProofRequired
		}
		originalPods := cp.Pods
		if cp.Process.UID != "" {
			originalPods = []quiesce.PodIdentity{cp.Process}
		}
		if len(originalPods) == 0 {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		witnesses, err := x.sourceStopReferences(ctx, in, cp.Namespace, originalPods)
		if err != nil {
			return nil, err
		}
		facts.StopWitnesses = witnesses
		ob.References = append(ob.References, witnesses...)
		var pods []*corev1.Pod
		if cp.Version == "deployment-quiesce.v1" {
			if isPlatform && (cp.Namespace != ref.Namespace || cp.Name != ref.Name || writer.Original.UID != ref.UID) {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			pods, err = x.recoveredDeploymentPods(ctx, writer, cp)
			if err == nil && facts.Runtime != nil && !sourceRecoveredDeploymentReceiptMatches(facts.Runtime, pods, cp.Namespace) {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			facts.Kind = "deployment"
		} else if cp.Version == "pod-quiesce.v1" && !isPlatform {
			pod, e := o.Client.CoreV1().Pods(cp.Namespace).Get(ctx, cp.Name, metav1.GetOptions{})
			if e != nil || len(pod.OwnerReferences) != 0 || kube.ContentHash(pod.Spec) != cp.SpecSHA256 || pod.Annotations["backup.clawmanager.io/source-resume-fence"] != cp.FenceID {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			var resumed b.RestartObservation
			if json.Unmarshal(facts.Runtime.Resumed, &resumed) != nil || string(pod.UID) != resumed.PodUID {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			pods, facts.Kind = []*corev1.Pod{pod}, "pod"
		} else {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		if err != nil || len(pods) == 0 {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		oldContainers := map[string]bool{}
		for _, pod := range originalPods {
			for _, id := range pod.Containers {
				oldContainers[id] = true
			}
		}
		for _, pod := range pods {
			var observed sourceRecoveredPod
			var e error
			if isPlatform {
				observed, e = x.observeRecoveredPod(ctx, pod, metadata, writer)
			} else {
				observed, e = x.observeRecoveredPod(ctx, pod, metadata)
			}
			if e != nil {
				return nil, e
			}
			for _, id := range observed.Containers {
				if oldContainers[id] {
					return nil, c.ErrSourceRecoveryProofRequired
				}
			}
			if facts.Runtime != nil && x.checkRecoveredInstanceMount(pod, facts.Runtime.Spec.Source, facts.Runtime.SpecSHA256, metadata) != nil {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			facts.Recovered = append(facts.Recovered, observed)
		}
		ob.Scope = "original_kubelet_exit_witness_and_recovered_ready_pod_container_volume_api_bindings"
		ob.Facts, _ = json.Marshal(facts)
		out = append(out, ob)
	}
	if len(instances) != 0 || o.Gate.Recovery.Check(ctx, in.Authority) != nil {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	return out, nil
}

func sourceRecoveredDeploymentReceiptMatches(runtime *c.SourceRecoveryRuntime, pods []*corev1.Pod, namespace string) bool {
	var resumed struct{ PodName, PodUID string }
	return runtime != nil && runtime.Spec.Kind == "deployment" && json.Unmarshal(runtime.Resumed, &resumed) == nil && resumed.PodName != "" && resumed.PodUID != "" && len(pods) == 1 && pods[0].Namespace == namespace && pods[0].Namespace == runtime.Spec.Source.Namespace && pods[0].Name == resumed.PodName && string(pods[0].UID) == resumed.PodUID
}

func (x *productionSourceBinding) sourceStopReferences(ctx context.Context, in d.Input, namespace string, pods []quiesce.PodIdentity) ([]c.SourceRecoverySQLReference, error) {
	out := []c.SourceRecoverySQLReference{}
	for _, pod := range pods {
		var raw []byte
		var digest string
		var witness quiesce.ExitWitness
		if x.owner.Gate.Authority.DB.QueryRowContext(ctx, "SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=?", in.Authority.TaskPublicID, pod.UID).Scan(&raw, &digest) != nil || len(raw) > 65536 || hash(raw) != digest || json.Unmarshal(raw, &witness) != nil || witness.Namespace != namespace || witness.PodName != pod.Name || witness.PodUID != pod.UID || witness.Node != pod.Node || witness.NodeUID == "" || witness.NodeUID != x.owner.Security.NodeUIDs[pod.Node] || witness.ResourceVersion == "" || len(witness.Containers) != len(pod.Containers) || len(pod.Containers) == 0 {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		seen := map[string]bool{}
		for _, id := range pod.Containers {
			if id == "" || seen[id] || witness.Containers[id].IsZero() {
				return nil, c.ErrSourceRecoveryProofRequired
			}
			seen[id] = true
		}
		out = append(out, c.SourceRecoverySQLReference{Kind: "runtime_stop", Identity: pod.UID, SHA256: digest})
	}
	return out, nil
}

func (x *productionSourceBinding) recoveredDeploymentPods(ctx context.Context, writer b.FrozenWriter, cp sourceRecoveryCheckpoint) ([]*corev1.Pod, error) {
	dep, err := x.owner.Client.AppsV1().Deployments(cp.Namespace).Get(ctx, cp.Name, metav1.GetOptions{})
	if err != nil || string(dep.UID) != writer.Original.UID || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != cp.Replicas || cp.Replicas < 1 || cp.Replicas > 1000 || dep.Status.ObservedGeneration != dep.Generation || dep.Status.ReadyReplicas != cp.Replicas || dep.Annotations["backup.clawmanager.io/source-resume-fence"] != cp.FenceID {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	spec := dep.Spec.DeepCopy()
	spec.Replicas = nil
	if kube.ContentHash(spec) != cp.SpecSHA256 {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	sets, err := x.owner.Client.AppsV1().ReplicaSets(cp.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 1001})
	if err != nil || sets.Continue != "" || len(sets.Items) > 1000 {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	owned := map[string]bool{}
	for _, rs := range sets.Items {
		owner := metav1.GetControllerOf(&rs)
		if rs.UID == "" || owner == nil || owner.Kind != "Deployment" || owner.APIVersion != "apps/v1" || owner.Name != dep.Name || owner.UID != dep.UID {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		if !sourceRecoveryReplicaTemplateMatches(dep.Spec.Template, rs.Spec.Template) {
			continue
		}
		owned[string(rs.UID)] = true
	}
	items, err := x.owner.Client.CoreV1().Pods(cp.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 1001})
	if err != nil || items.Continue != "" || len(items.Items) != int(cp.Replicas) {
		return nil, c.ErrSourceRecoveryProofRequired
	}
	out := []*corev1.Pod{}
	for i := range items.Items {
		pod := &items.Items[i]
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || !owned[string(owner.UID)] || !kube.SourceRecoveryPodSpecMatches(dep.Spec.Template.Spec, pod.Spec) {
			return nil, c.ErrSourceRecoveryProofRequired
		}
		out = append(out, pod)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func sourceRecoveryReplicaTemplateMatches(original, replica corev1.PodTemplateSpec) bool {
	copy := replica.DeepCopy()
	delete(copy.Labels, "pod-template-hash")
	return kube.ContentHash(original) == kube.ContentHash(copy)
}

func (x *productionSourceBinding) observeRecoveredPod(ctx context.Context, pod *corev1.Pod, metadata productionCaptureMetadata, platform ...b.FrozenWriter) (sourceRecoveredPod, error) {
	var out sourceRecoveredPod
	if pod == nil || pod.Namespace != x.owner.Namespace || pod.UID == "" || pod.ResourceVersion == "" || pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) == 0 || len(pod.Status.ContainerStatuses) != len(pod.Spec.Containers) || len(pod.Spec.EphemeralContainers) != 0 {
		return out, c.ErrSourceRecoveryProofRequired
	}
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready {
		return out, c.ErrSourceRecoveryProofRequired
	}
	node, err := x.owner.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.DeletionTimestamp != nil || node.UID == "" || string(node.UID) != x.owner.Security.NodeUIDs[pod.Spec.NodeName] {
		return out, c.ErrSourceRecoveryProofRequired
	}
	out = sourceRecoveredPod{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), ResourceVersion: pod.ResourceVersion, Node: pod.Spec.NodeName, NodeUID: string(node.UID), SpecSHA256: kube.ContentHash(pod.Spec)}
	seen := map[string]bool{}
	for _, status := range pod.Status.ContainerStatuses {
		if !status.Ready || status.State.Running == nil || status.State.Terminated != nil || status.State.Waiting != nil || status.ContainerID == "" || seen[status.Name] {
			return out, c.ErrSourceRecoveryProofRequired
		}
		seen[status.Name] = true
		out.Containers = append(out.Containers, status.ContainerID)
	}
	for _, container := range pod.Spec.Containers {
		if !seen[container.Name] {
			return out, c.ErrSourceRecoveryProofRequired
		}
	}
	for _, status := range pod.Status.InitContainerStatuses {
		if status.State.Running != nil {
			return out, c.ErrSourceRecoveryProofRequired
		}
	}
	sort.Strings(out.Containers)
	for _, volume := range pod.Spec.Volumes {
		ob := sourceRecoveredVolume{Name: volume.Name, DeclarationSHA256: kube.ContentHash(volume.VolumeSource)}
		switch {
		case volume.PersistentVolumeClaim != nil:
			claim, e := x.owner.Client.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if e != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
				return out, c.ErrSourceRecoveryProofRequired
			}
			pv, e := x.owner.Client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != pod.Namespace || pv.Spec.ClaimRef.Name != claim.Name {
				return out, c.ErrSourceRecoveryProofRequired
			}
			pinned := false
			for _, pin := range metadata.MountIdentities {
				if pin.Kind == "PersistentVolumeClaim" && pin.Name == claim.Name && pin.UID == string(claim.UID) && pin.PVName == pv.Name && pin.PVUID == string(pv.UID) && pin.SHA256 == kube.ContentHash(pv.Spec) {
					pinned = true
				}
			}
			if len(platform) != 0 {
				pinned = false
				for _, mount := range metadata.PlatformMounts {
					if sourceRecoveryPlatformPinMatches(mount, platform[0], pod.Namespace, volume) && mount.Claim != nil {
						pin := mount.Claim
						if pin.Name == claim.Name && pin.UID == string(claim.UID) && pin.PVName == pv.Name && pin.PVUID == string(pv.UID) && pin.SHA256 == kube.ContentHash(pv.Spec) {
							pinned = true
						}
					}
				}
			}
			if !pinned {
				return out, c.ErrSourceRecoveryProofRequired
			}
			ob.Kind, ob.Claim, ob.ClaimUID, ob.ClaimVersion = "PersistentVolumeClaim", claim.Name, string(claim.UID), claim.ResourceVersion
			ob.PV, ob.PVUID, ob.PVVersion, ob.PVSpecSHA256 = pv.Name, string(pv.UID), pv.ResourceVersion, kube.ContentHash(pv.Spec)
		case volume.NFS != nil:
			pinned := false
			for _, mount := range metadata.Mounts {
				if mount.Source.NFS != nil && mount.Source.NFS.Server == volume.NFS.Server && mount.Source.NFS.Path == volume.NFS.Path {
					pinned = true
				}
			}
			if len(platform) != 0 {
				pinned = false
				for _, mount := range metadata.PlatformMounts {
					if sourceRecoveryPlatformPinMatches(mount, platform[0], pod.Namespace, volume) && mount.Source.NFS != nil {
						pinned = true
					}
				}
			}
			if !pinned {
				return out, c.ErrSourceRecoveryProofRequired
			}
			ob.Kind, ob.NFSServer, ob.NFSExport = "NFS", volume.NFS.Server, volume.NFS.Path
		case volume.HostPath != nil, volume.CSI != nil, volume.Ephemeral != nil:
			return out, c.ErrSourceRecoveryProofRequired
		default:
			continue
		}
		out.Volumes = append(out.Volumes, ob)
	}
	return out, nil
}

func sourceRecoveryPlatformPinMatches(pin sourceRecoveryPlatformMount, writer b.FrozenWriter, namespace string, volume corev1.Volume) bool {
	var cp sourceRecoveryCheckpoint
	return json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) == nil && cp.Version == "deployment-quiesce.v1" && pin.WriterID == writer.ID && pin.Namespace == namespace && pin.Namespace == cp.Namespace && pin.DeploymentUID == writer.Original.UID && pin.OriginalSpecSHA256 == cp.SpecSHA256 && kube.ContentHash(pin.Source) == kube.ContentHash(volume)
}

func (x *productionSourceBinding) checkRecoveredInstanceMount(pod *corev1.Pod, instance b.InstanceIdentity, specSHA string, metadata productionCaptureMetadata) error {
	var original *productionInstanceMount
	for i := range metadata.Mounts {
		mount := &metadata.Mounts[i]
		if mount.InstanceID == instance.ID && mount.MountID == "workspace" {
			if original != nil {
				return c.ErrSourceRecoveryProofRequired
			}
			original = mount
		}
	}
	if original == nil || original.SourceSpecSHA256 != specSHA || !path.IsAbs(instance.Workspace) || path.Clean(instance.Workspace) != instance.Workspace {
		return c.ErrSourceRecoveryProofRequired
	}
	found := false
	for _, container := range pod.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			ancestor := instance.Workspace == mount.MountPath || strings.HasPrefix(instance.Workspace, mount.MountPath+"/")
			descendant := strings.HasPrefix(mount.MountPath, instance.Workspace+"/")
			if !ancestor && !descendant {
				continue
			}
			if mount.SubPathExpr != "" || !path.IsAbs(mount.MountPath) || path.Clean(mount.MountPath) != mount.MountPath {
				return c.ErrSourceRecoveryProofRequired
			}
			actual, wanted := mount.SubPath, original.SubPath
			if ancestor && instance.Workspace != mount.MountPath {
				actual = path.Join(mount.SubPath, strings.TrimPrefix(instance.Workspace, mount.MountPath+"/"))
			}
			if descendant {
				wanted = path.Join(original.SubPath, strings.TrimPrefix(mount.MountPath, instance.Workspace+"/"))
			}
			if actual != wanted {
				return c.ErrSourceRecoveryProofRequired
			}
			matched := false
			for _, volume := range pod.Spec.Volumes {
				if volume.Name != mount.Name {
					continue
				}
				if original.Source.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim != nil && original.Source.PersistentVolumeClaim.ClaimName == volume.PersistentVolumeClaim.ClaimName {
					matched = true
				}
				if original.Source.NFS != nil && volume.NFS != nil && original.Source.NFS.Server == volume.NFS.Server && original.Source.NFS.Path == volume.NFS.Path {
					matched = true
				}
			}
			if !matched {
				return c.ErrSourceRecoveryProofRequired
			}
			found = found || ancestor
		}
	}
	if !found {
		return c.ErrSourceRecoveryProofRequired
	}
	return nil
}
