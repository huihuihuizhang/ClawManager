package install

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"

	"clawreef/internal/services"
	corev1 "k8s.io/api/core/v1"
)

// This is an original source coordinate produced from actual SQL/Kubernetes
// and authenticated protocol reads, not a native stop or loaded-image proof.
type OriginalSharedRuntimeAgentSelection struct {
	Namespace, Pod, PodUID, Deployment string
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
		paths, err := physical.actualPodPersistentRoots(ctx, &pod)
		if err != nil || len(paths) == 0 {
			return nil, ErrInstall
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

func (s *PreparedOriginalWriterSet) validateOriginalSharedAgentSelection() error {
	if len(s.selection.SharedRuntimeAgents) != len(s.sharedRuntimes) {
		return ErrInstall
	}
	seen := map[string]bool{}
	for _, selected := range s.selection.SharedRuntimeAgents {
		if selected.PodUID == "" || seen[selected.PodUID] {
			return ErrInstall
		}
		seen[selected.PodUID] = true
		matched := false
		for _, actual := range s.sharedRuntimes {
			if selected.Namespace == actual.row.Namespace && selected.PodUID == actual.row.UID && selected.Pod == actual.row.Pod && selected.Deployment == actual.row.Deployment {
				matched = true
			}
		}
		if !matched {
			return ErrInstall
		}
	}
	return nil
}
