package systembackupexecution

import (
	"context"
	"path"
	"sort"
	"strings"

	"clawreef/internal/services"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Actual pinned deployment configuration, never a page/API input or a native
// result. The lifecycle owner independently qualifies every actual host path.
type FormalSharedRuntimeObserverConfig struct {
	CAFile, CASHA256, CertificateFile, CertificateSHA256, KeyFile, KeySHA256 string
	Endpoints                                                                map[string]q.ProofEndpoint
	WholeNodeEndpoints                                                       map[string]q.ProofEndpoint
	Nodes                                                                    []c.RuntimeSharedNodeSources
}

func (s *DeploymentService) sharedRuntimeControlConfig(agent services.BackupGatewayAgent) (*c.RuntimeSharedTaskConfig, error) {
	if s.Config.RuntimeSources == nil || s.Config.RuntimeSources.SharedRuntimeProtocol != "shared-container-freeze.v1" || s.Config.RuntimeSources.SharedObserver == nil {
		return nil, d.ErrNotReady
	}
	config := s.Config.RuntimeSources.SharedObserver
	check := func() error {
		for _, pin := range []struct{ file, digest string }{{config.CAFile, config.CASHA256}, {config.CertificateFile, config.CertificateSHA256}, {config.KeyFile, config.KeySHA256}} {
			raw, err := pinnedDeploymentFile(pin.file, pin.digest, 262144)
			clear(raw)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	native, err := q.NewSharedRuntimeNodeClient(config.Endpoints, config.CAFile, config.CertificateFile, config.KeyFile)
	if err != nil || check() != nil {
		return nil, d.ErrNotReady
	}
	whole, err := q.NewNodeObservationClient(config.WholeNodeEndpoints, config.CAFile, config.CertificateFile, config.KeyFile)
	if err != nil || check() != nil {
		return nil, d.ErrNotReady
	}
	actual, ok := agent.(services.RuntimeAgentClient)
	if !ok {
		return nil, d.ErrNotReady
	}
	if _, err := services.NewRuntimeSharedBackupCallbacks(actual); err != nil {
		return nil, err
	}
	out := &c.RuntimeSharedTaskConfig{Protocol: services.RuntimeSharedBackupProtocol, NamespaceUID: s.Config.NamespaceUID, WorkspaceRoot: s.Config.RuntimeSources.WorkspaceRoot, Agent: actual, Native: native, WholeNode: whole, Nodes: append([]c.RuntimeSharedNodeSources(nil), config.Nodes...)}
	for _, ref := range s.Config.RuntimeSources.Deployments {
		if ref.Namespace != s.Config.Namespace {
			return nil, d.ErrNotReady
		}
		out.Agents = append(out.Agents, c.RuntimeSharedAgentDeployment{Name: ref.Name, UID: ref.UID})
	}
	if len(out.Agents) == 0 || len(out.Nodes) == 0 {
		return nil, d.ErrNotReady
	}
	seen := map[string]bool{}
	for _, node := range out.Nodes {
		if node.Name == "" || node.UID == "" || seen[node.Name] || len(node.Paths) == 0 || !sort.StringsAreSorted(node.Paths) {
			return nil, d.ErrNotReady
		}
		seen[node.Name] = true
		for i, p := range node.Paths {
			if !path.IsAbs(p) || path.Clean(p) != p || p == "/" || strings.ContainsAny(p, "\x00\r\n\\") || i > 0 && (p == node.Paths[i-1] || strings.HasPrefix(p, node.Paths[i-1]+"/")) {
				return nil, d.ErrNotReady
			}
		}
	}
	return out, nil
}

// Shared workspace checks never call legacy BackupCapabilities/slot endpoints.
// Mount coverage remains the existing independently produced six-part scope.
func (s *DeploymentService) checkSharedRuntimeWorkspace(ctx context.Context, instances []b.InstanceIdentity) error {
	if s.RuntimeControl == nil || s.captureMaterials == nil || s.captureMaterials.Discovery == nil {
		return d.ErrNotReady
	}
	if _, err := persistentMountsForInstances(s.captureMaterials.Discovery.PersistentMounts, instances); err != nil {
		return err
	}
	for _, source := range instances {
		if source.Mode != "lite" || source.Status != "running" {
			continue
		}
		pod, err := s.RuntimeControl.ResolveSharedTaskPod(ctx, source)
		if err != nil {
			return err
		}
		current, err := s.Runtime.Owner.Client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil || current.UID != pod.UID || current.DeletionTimestamp != nil {
			return d.ErrNotReady
		}
	}
	return nil
}
