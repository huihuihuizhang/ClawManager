package install

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"

	"clawreef/internal/services"
	corev1 "k8s.io/api/core/v1"
)

// This is an original source coordinate produced from actual SQL/Kubernetes
// and authenticated protocol reads, not a native stop or loaded-image proof.
type OriginalSharedRuntimeAgentSelection struct {
	Namespace, Pod, PodUID, Deployment string
}

// OriginalSharedRuntimeVolumeMount is one observed container mount of a data
// volume. SubPath is the literal Pod value, never a resolved host path.
type OriginalSharedRuntimeVolumeMount struct {
	Container, MountPath, SubPath string
}

// OriginalSharedRuntimeVolume is the observed identity of one Longhorn CSI data
// volume used by a shared runtime Agent. It is plain coordinates: no hold,
// grant, signature or frozen state. The signed Longhorn materials later bind
// the same handle and the stop path still requires execution evidence.
type OriginalSharedRuntimeVolume struct {
	VolumeName, ClaimName, ClaimUID, PVName, PVUID, Handle string
	Namespace, Pod, PodUID, Node, NodeUID                  string
	Mounts                                                 []OriginalSharedRuntimeVolumeMount
}

func originalSharedEndpointMatchesPod(endpoint string, pod *corev1.Pod) bool {
	u, err := url.Parse(endpoint)
	return pod != nil && err == nil && u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && u.Port() == "19090" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) && !pod.Spec.HostNetwork
}

func (p *OriginalWriterMaintenance) collectOriginalSharedAgentSelection(ctx context.Context, options OriginalWriterSelectionOptions, config originalWriterSourceConfig, s *OriginalWriterSetSelection, pods []corev1.Pod, roles map[string]OriginalDeploymentSelection, physical *PreparedOriginalWriterSet, database string) (map[string]string, error) {
	aliases := map[string]string{}
	if config.RuntimeSources == nil || config.RuntimeSources.SharedRuntimeProtocol != services.RuntimeSharedBackupProtocol || p.check(ctx) != nil {
		return nil, ErrInstall
	}
	var err error
	s.SharedRuntimeProtocol = services.RuntimeSharedBackupProtocol
	s.AgentCredential, err = originalSelectionCurrentPin(config.RuntimeSources.AgentTokenFile, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	s.AgentCA = BootstrapSourceFilePin{File: config.RuntimeSources.AgentCAFile, SHA256: config.RuntimeSources.AgentCASHA256}
	token, err := readBootstrapSourcePin(s.AgentCredential, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	defer clear(token)
	ca, err := readBootstrapSourcePin(s.AgentCA, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	client, err := services.NewRuntimeAgentClientWithPinnedCA(string(token), ca)
	if err != nil {
		return nil, ErrInstall
	}
	callbacks, err := services.NewRuntimeSharedBackupCallbacks(client)
	if err != nil {
		return nil, ErrInstall
	}
	projection, err := p.readSharedRuntimeSQL(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	ordered := append([]corev1.Pod(nil), pods...)
	sort.Slice(ordered, func(i, j int) bool { return string(ordered[i].UID) < string(ordered[j].UID) })
	for _, pod := range ordered {
		if len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 {
			continue
		}
		// Actual independently pinned content-qualified runtime images select
		// the Agent universe, INCLUDING an Agent with no instance binding.
		image := originalRuntimeImageForContainer(options.runtimeStartupProfiles, &pod.Spec.Containers[0], &pod.Status.ContainerStatuses[0])
		if image == nil {
			continue
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || pod.Status.ContainerStatuses[0].State.Running == nil || !pod.Status.ContainerStatuses[0].Ready {
			return nil, ErrInstall
		}
		dep, err := p.originalSelectionPodDeployment(ctx, &pod, roles)
		if err != nil || dep == database {
			return nil, ErrInstall
		}
		var row originalSharedRuntimePodRow
		for _, actual := range projection.Pods {
			if actual.UID == string(pod.UID) {
				if row.ID != 0 || actual.Pod != pod.Name || actual.Namespace != pod.Namespace || actual.Deployment != dep {
					return nil, ErrInstall
				}
				row = actual
			}
		}
		if row.ID == 0 || !originalSharedEndpointMatchesPod(row.Endpoint, &pod) {
			return nil, ErrInstall
		}
		caps, _, err := callbacks.Capabilities(ctx, row.Endpoint)
		if err != nil || caps.Namespace != pod.Namespace || caps.PodUID != string(pod.UID) || caps.Deployment != dep {
			return nil, ErrInstall
		}
		if _, ok := s.WholePodEndpoints[pod.Spec.NodeName]; !ok {
			return nil, ErrInstall
		}
		roots, longhorn, err := physical.classifyPodPersistentVolumes(ctx, &pod)
		if err != nil || len(roots)+len(longhorn) == 0 {
			return nil, ErrInstall
		}
		if len(longhorn) > 0 {
			// Author-time observation only. The real stop path still refuses
			// Longhorn until the signed coverage and Node grant are installed.
			records, err := physical.originalSharedRuntimeVolumeRecords(ctx, &pod, longhorn)
			if err != nil {
				return nil, ErrInstall
			}
			s.SharedRuntimeVolumes = append(s.SharedRuntimeVolumes, records...)
		}
		selected := roles[dep]
		selected.Role = "agent"
		roles[dep] = selected
		s.SharedRuntimeAgents = append(s.SharedRuntimeAgents, OriginalSharedRuntimeAgentSelection{Namespace: pod.Namespace, Pod: pod.Name, PodUID: string(pod.UID), Deployment: dep})
		for _, binding := range projection.Bindings {
			if binding.RuntimePodID == row.ID {
				aliases[fmt.Sprintf("gateway/%s/%d", row.UID, binding.InstanceID)] = "shared-runtime/" + row.UID
			}
		}
	}
	if len(s.SharedRuntimeAgents) == 0 {
		return nil, ErrInstall
	}
	return aliases, nil
}

func (s *PreparedOriginalWriterSet) validateOriginalSharedAgentSelection(ctx context.Context) error {
	if len(s.selection.SharedRuntimeAgents) != len(s.sharedRuntimes) {
		return ErrInstall
	}
	selected := map[string]OriginalSharedRuntimeAgentSelection{}
	seen := map[string]bool{}
	for _, agent := range s.selection.SharedRuntimeAgents {
		if agent.PodUID == "" || seen[agent.PodUID] {
			return ErrInstall
		}
		seen[agent.PodUID] = true
		selected[agent.PodUID] = agent
		matched := false
		for _, actual := range s.sharedRuntimes {
			if agent.Namespace == actual.row.Namespace && agent.PodUID == actual.row.UID && agent.Pod == actual.row.Pod && agent.Deployment == actual.row.Deployment {
				matched = true
			}
		}
		if !matched {
			return ErrInstall
		}
	}
	recorded := map[string]bool{}
	for _, volume := range s.selection.SharedRuntimeVolumes {
		if volume.PodUID == "" || volume.VolumeName == "" || volume.ClaimName == "" || volume.ClaimUID == "" || volume.PVName == "" || volume.PVUID == "" || volume.Handle == "" ||
			volume.Namespace == "" || volume.Pod == "" || volume.Node == "" || volume.NodeUID == "" || len(volume.Mounts) == 0 {
			return ErrInstall
		}
		agent, ok := selected[volume.PodUID]
		if !ok || agent.Namespace != volume.Namespace || agent.Pod != volume.Pod {
			return ErrInstall
		}
		key := volume.PodUID + "\x00" + volume.VolumeName
		if recorded[key] {
			return ErrInstall
		}
		recorded[key] = true
	}
	matched := map[string]bool{}
	for i := range s.sharedRuntimes {
		pod := &s.sharedRuntimes[i].pod
		if s.checkOriginalSharedRuntimeVolumes(ctx, pod) != nil {
			return ErrInstall
		}
		for _, volume := range s.selectedOriginalSharedRuntimeVolumes(string(pod.UID)) {
			matched[volume.PodUID+"\x00"+volume.VolumeName] = true
		}
	}
	if len(matched) != len(recorded) {
		return ErrInstall
	}
	return nil
}

// actualOriginalSharedRuntimeVolumes re-observes the current Longhorn volumes
// of one shared runtime Pod. nil means the Pod has no Longhorn data volume, so
// an old host-only selection still compares equal with zero records.
func (s *PreparedOriginalWriterSet) actualOriginalSharedRuntimeVolumes(ctx context.Context, pod *corev1.Pod) ([]OriginalSharedRuntimeVolume, error) {
	if s == nil || s.owner == nil || s.owner.operator == nil || s.owner.operator.installer == nil {
		return nil, ErrInstall
	}
	_, longhorn, err := classifyPodPersistentVolumes(ctx, s.owner.operator.installer.kube, pod, nil)
	if err != nil {
		return nil, err
	}
	if len(longhorn) == 0 {
		return nil, nil
	}
	return s.originalSharedRuntimeVolumeRecords(ctx, pod, longhorn)
}

func (s *PreparedOriginalWriterSet) selectedOriginalSharedRuntimeVolumes(podUID string) []OriginalSharedRuntimeVolume {
	var out []OriginalSharedRuntimeVolume
	for _, volume := range s.selection.SharedRuntimeVolumes {
		if volume.PodUID == podUID {
			out = append(out, volume)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VolumeName < out[j].VolumeName })
	return out
}

// checkOriginalSharedRuntimeVolumes compares the reviewed records with a fresh
// classifier read of the same Pod. PVC/PV UID, handle, Node UID or mount drift
// is a refusal; it never silently adopts the new identity.
func (s *PreparedOriginalWriterSet) checkOriginalSharedRuntimeVolumes(ctx context.Context, pod *corev1.Pod) error {
	actual, err := s.actualOriginalSharedRuntimeVolumes(ctx, pod)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, s.selectedOriginalSharedRuntimeVolumes(string(pod.UID))) {
		return ErrInstall
	}
	return nil
}
