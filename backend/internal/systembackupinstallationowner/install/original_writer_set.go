package install

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const OriginalWriterSetSelectionVersion = "original-writer-set-selection.v1"

// Independently selected actual INPUTS. Roles and filenames are not proofs.
// No task, final config, grant, observed response or readiness bool is accepted.
type OriginalWriterSetSelection struct {
	GatewayRecoveryMode                                      string
	ApplicationScope                                         string
	Participants                                             []OriginalMaintenanceParticipant
	RunningPro                                               []OriginalProPodSelection
	Version                                                  string
	Policy                                                   c.GatePolicy
	JournalDirectory                                         string
	AgentCredential, AgentCA                                 BootstrapSourceFilePin
	ObserverCA, ObserverCertificate, ObserverKey             BootstrapSourceFilePin
	GatewayEndpoints, WholePodEndpoints, StoppedProEndpoints map[string]q.ProofEndpoint
	Deployments                                              []OriginalDeploymentSelection
	Gateways                                                 []OriginalGatewaySelection
	StoppedPro                                               []OriginalStoppedProSelection
}

// This public failure identifies the concrete original source branch. The
// original complete inventory is retained internally and never filtered.
type OriginalWriterSourceFailure struct {
	InstanceID               int
	Mode, Status, Dependency string
}

func (e OriginalWriterSourceFailure) Error() string {
	return fmt.Sprintf("original writer %d (%s/%s): %s", e.InstanceID, e.Mode, e.Status, e.Dependency)
}

type PreparedOriginalWriterSet struct {
	historyMounted        *originalMountedHistoryInputs
	mu                    sync.Mutex
	nodes                 []*originalWholeNodeScope
	volumes               []originalPhysicalVolumePin
	application           originalApplicationGate
	proPods               []*originalProPodMaintenance
	origin                *PreparedOriginalWriterSet
	owner                 *OriginalWriterMaintenance
	selection             OriginalWriterSetSelection
	selectionPin          BootstrapSourceFilePin
	initial               originalMaintenanceKubernetesCensus
	inventorySHA          string
	journal               *originalWriterJournal
	agent                 services.RuntimeAgentClient
	gatewayClient         *q.GatewayNodeObservationClient
	wholePodClient        *q.NodeObservationClient
	stoppedProClient      *q.StoppedProNodeObservationClient
	gateways              []*originalGatewayMaintenance
	deployments           []*originalDeploymentMaintenance
	stoppedObservations   []*originalStoppedProObservation
	stopped               []*originalStoppedProMaintenance
	used                  bool
	actualHold            *OriginalWriterHold
	recovering            bool
	recoveryAuthorization *OriginalWriterRecoveryAuthorization
}

func (*PreparedOriginalWriterSet) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// PrepareOriginalWriterSet is the production all-source preflight caller. It
// performs no source stop or gate acquisition. All original instances are
// visited before any actor is allowed to mutate a source.
func (i *Installer) PrepareOriginalWriterSet(ctx context.Context, password []byte, enrollment EnrollmentPin, selectionPin BootstrapSourceFilePin) (*PreparedOriginalWriterSet, error) {
	raw, err := readBootstrapSourcePin(selectionPin, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	var selection OriginalWriterSetSelection
	if decodeExact(raw, &selection) != nil || selection.Version != OriginalWriterSetSelectionVersion || selection.Policy.Validate() != nil {
		return nil, ErrInstall
	}
	p, err := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, selection.Policy)
	if err != nil {
		return nil, err
	}
	if len(selection.Gateways) > 0 && selection.GatewayRecoveryMode != OriginalGatewaySameIncarnationRecovery {
		return nil, ErrInstall
	}
	p.gatewayRecoveryMode = selection.GatewayRecoveryMode
	census, pods, actualDeployments, _, err := p.readKubernetesCensus(ctx)
	if err != nil {
		return nil, err
	}
	// These reconcilers need their own real durable stop/resume producer before
	// they may be admitted. Presence is not silently treated as read-only.
	if len(census.StatefulSets)+len(census.DaemonSets)+len(census.Jobs)+len(census.CronJobs)+len(census.Autoscalers) != 0 {
		return nil, OriginalWriterSourceFailure{Dependency: "complete_non_deployment_reconciler_gate_required"}
	}
	selected := map[string]OriginalDeploymentSelection{}
	databaseCount := 0
	for _, dep := range selection.Deployments {
		if dep.Name == "" || dep.UID == "" || selected[dep.Name].UID != "" || dep.Role != "writer" && dep.Role != "agent" && dep.Role != "database" {
			return nil, ErrInstall
		}
		selected[dep.Name] = dep
		if dep.Role == "database" {
			databaseCount++
		}
	}
	if len(selected) != len(actualDeployments) || databaseCount != 1 {
		return nil, ErrInstall
	}
	for _, dep := range actualDeployments {
		if selected[dep.Name].UID != string(dep.UID) || dep.DeletionTimestamp != nil {
			return nil, ErrInstall
		}
	}
	// Bind the one kept database Deployment to this actual authenticated SQL
	// server's hostname, in addition to the Installer's existing UUID/TLS pin.
	var hostname string
	if i.db.QueryRowContext(ctx, "SELECT @@hostname").Scan(&hostname) != nil || hostname == "" {
		return nil, ErrInstall
	}
	databaseMatched := false
	for _, pod := range pods {
		role := ""
		if len(pod.OwnerReferences) == 1 && pod.OwnerReferences[0].Kind == "ReplicaSet" {
			rs, e := i.kube.AppsV1().ReplicaSets(census.Namespace).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
			if e != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Deployment" || selected[rs.OwnerReferences[0].Name].UID != string(rs.OwnerReferences[0].UID) {
				return nil, ErrInstall
			}
			role = selected[rs.OwnerReferences[0].Name].Role
		} else if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
			known := false
			for _, source := range p.instances {
				if source.Status == "running" && source.Pod == pod.Name && source.Namespace == pod.Namespace {
					plan, e := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
					known = e == nil && plan.Mode == "pro"
				}
			}
			if !known {
				return nil, OriginalWriterSourceFailure{Dependency: "unregistered_standalone_pod_writer"}
			}
		}
		if role == "database" {
			if databaseMatched || pod.Status.Phase != corev1.PodRunning || pod.Name != hostname && pod.Spec.Hostname != hostname {
				return nil, ErrInstall
			}
			databaseMatched = true
		}
	}
	if !databaseMatched {
		return nil, ErrInstall
	}
	set := &PreparedOriginalWriterSet{owner: p, selection: selection, selectionPin: selectionPin, initial: census}
	set.origin = set
	success := false
	defer func() {
		if !success {
			set.closePrivate()
		}
	}()
	set.historyMounted, err = readOriginalMountedHistoryInputs(ctx, i, pods, actualDeployments, p.until)
	if err != nil {
		return nil, OriginalWriterSourceFailure{Dependency: "original_mounted_config_material_read_or_identity_rejected"}
	}
	// The hash is over the complete ACTUAL original projection and explicit
	// input pin. It is not a caller-provided subset or a stop acknowledgement.
	set.inventorySHA = originalObjectSHA(struct {
		Version, SelectionSHA256, MountedHistorySHA256 string
		Instances                                      []domain.SourceInstance
		API                                            originalMaintenanceKubernetesCensus
	}{"original-writer-set-definition.v2", selectionPin.SHA256, set.historyMounted.revision, p.instances, census})
	j, err := newOriginalWriterJournal(ctx, p, selection.JournalDirectory, set.inventorySHA)
	if err != nil {
		return nil, err
	}
	set.journal = j
	for _, pin := range []BootstrapSourceFilePin{selection.ObserverCA, selection.ObserverCertificate, selection.ObserverKey} {
		data, e := readBootstrapSourcePin(pin, 262144)
		clear(data)
		if e != nil {
			return nil, ErrInstall
		}
	}
	set.wholePodClient, err = q.NewNodeObservationClient(selection.WholePodEndpoints, selection.ObserverCA.File, selection.ObserverCertificate.File, selection.ObserverKey.File)
	if err != nil {
		return nil, ErrInstall
	}
	set.stoppedProClient, err = q.NewStoppedProNodeObservationClient(selection.StoppedProEndpoints, selection.ObserverCA.File, selection.ObserverCertificate.File, selection.ObserverKey.File)
	if err != nil {
		return nil, ErrInstall
	}
	if len(selection.Gateways) > 0 {
		token, e := readBootstrapSourcePin(selection.AgentCredential, 262144)
		if e != nil {
			return nil, ErrInstall
		}
		defer clear(token)
		ca, e := readBootstrapSourcePin(selection.AgentCA, 262144)
		if e != nil {
			return nil, ErrInstall
		}
		set.agent, e = services.NewRuntimeAgentClientWithPinnedCA(string(token), ca)
		if e != nil {
			return nil, ErrInstall
		}
		set.gatewayClient, e = q.NewGatewayNodeObservationClient(selection.GatewayEndpoints, selection.ObserverCA.File, selection.ObserverCertificate.File, selection.ObserverKey.File)
		if e != nil {
			return nil, ErrInstall
		}
	}
	gateways := map[int]OriginalGatewaySelection{}
	for _, s := range selection.Gateways {
		if s.InstanceID <= 0 || gateways[s.InstanceID].InstanceID != 0 {
			return nil, ErrInstall
		}
		gateways[s.InstanceID] = s
	}
	stopped := map[int]OriginalStoppedProSelection{}
	for _, s := range selection.StoppedPro {
		if s.InstanceID <= 0 || stopped[s.InstanceID].InstanceID != 0 {
			return nil, ErrInstall
		}
		stopped[s.InstanceID] = s
	}
	var sourceFailures []OriginalWriterSourceFailure
	runningPro := map[int]OriginalProPodSelection{}
	for _, s := range selection.RunningPro {
		if s.InstanceID <= 0 || runningPro[s.InstanceID].InstanceID != 0 {
			return nil, ErrInstall
		}
		runningPro[s.InstanceID] = s
	}
	agentUses := map[string]bool{}
	for _, source := range p.instances {
		plan, e := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
		if e != nil {
			sourceFailures = append(sourceFailures, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "unsupported_actual_runtime"})
			continue
		}
		if plan.Mode == "lite" {
			s, ok := gateways[source.ID]
			if !ok {
				sourceFailures = append(sourceFailures, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "original_gateway_material_and_native_endpoint_required"})
				continue
			}
			g, e := p.prepareGateway(ctx, source, s, set.agent, set.gatewayClient, j)
			if e != nil {
				return nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "original_gateway_sql_kubernetes_material_or_native_preflight_rejected"}
			}
			if selected[g.row.Deployment].Role != "agent" {
				return nil, ErrInstall
			}
			agentUses[g.row.Deployment] = true
			set.gateways = append(set.gateways, g)
			delete(gateways, source.ID)
		} else if source.Status == "stopped" {
			s, ok := stopped[source.ID]
			if !ok {
				sourceFailures = append(sourceFailures, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "current_stopped_pro_volume_selection_required"})
				continue
			}
			observed, e := p.prepareStoppedPro(ctx, s)
			if e != nil {
				return nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "current_stopped_pro_unique_node_volume_and_absent_controller_preflight_rejected"}
			}
			set.stoppedObservations = append(set.stoppedObservations, observed)
			delete(stopped, source.ID)
		} else {
			s, ok := runningPro[source.ID]
			if !ok {
				sourceFailures = append(sourceFailures, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "original_pro_pod_recovery_key_selection_required"})
				continue
			}
			w, e := p.prepareProPod(ctx, source, s, j)
			if e != nil {
				return nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "original_pro_pod_snapshot_seal_or_native_preflight_rejected"}
			}
			set.proPods = append(set.proPods, w)
			delete(runningPro, source.ID)
		}
	}
	if len(sourceFailures) > 0 {
		return nil, sourceFailures[0]
	}
	if len(gateways)+len(stopped)+len(runningPro) != 0 {
		return nil, ErrInstall
	}
	for _, dep := range selection.Deployments {
		if dep.Role == "writer" {
			w, e := p.prepareDeployment(ctx, dep, j)
			if e != nil {
				return nil, e
			}
			set.deployments = append(set.deployments, w)
		} else if dep.Role == "agent" && !agentUses[dep.Name] {
			return nil, OriginalWriterSourceFailure{Dependency: "unreferenced_shared_agent_writer_requires_native_gate"}
		}
	}
	if len(set.deployments) == 0 {
		return nil, ErrInstall
	}
	sort.Slice(set.deployments, func(i, j int) bool { return set.deployments[i].ID() < set.deployments[j].ID() })
	// Refuse key/cert/token drift across constructor reads. The originals stay
	// pinned for every later boundary; clients are not exposed to callers.
	if set.recheckPreflight(ctx) != nil {
		return nil, ErrInstall
	}
	states := map[string]any{}
	for _, g := range set.gateways {
		states[g.ID()] = g.state
	}
	for _, w := range set.deployments {
		states[w.ID()] = w.original
	}
	for _, w := range set.proPods {
		states[w.ID()] = w.original
	}
	for _, s := range set.stoppedObservations {
		states[s.baseline.SourceKey] = s.baseline
	}
	if j.append(ctx, "", "prepared_original_complete_set", nil, struct {
		Selection BootstrapSourceFilePin
		Instances []domain.SourceInstance
		Census    originalMaintenanceKubernetesCensus
		States    map[string]any
	}{selectionPin, p.instances, census, states}) != nil {
		return nil, ErrInstall
	}
	success = true
	return set, nil
}

func (s *PreparedOriginalWriterSet) recheckPreflight(ctx context.Context) error {
	if s == nil || s.origin != s || s.used || s.owner.check(ctx) != nil || s.owner.checkInstances(ctx) != nil {
		return ErrInstall
	}
	raw, err := readBootstrapSourcePin(s.selectionPin, 262144)
	clear(raw)
	if err != nil {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{s.selection.ObserverCA, s.selection.ObserverCertificate, s.selection.ObserverKey} {
		raw, e := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
	}
	if s.historyMounted == nil || s.historyMounted.installer != s.owner.operator.installer || s.historyMounted.recheckReferences(ctx) != nil {
		return ErrInstall
	}
	current, _, _, _, err := s.owner.readKubernetesCensus(ctx)
	if err != nil || !reflect.DeepEqual(current, s.initial) {
		return ErrInstall
	}
	return nil
}

func (s *PreparedOriginalWriterSet) closePrivate() {
	if s == nil {
		return
	}
	if s.historyMounted != nil {
		s.historyMounted.close()
	}
	for _, g := range s.gateways {
		clear(g.restart.Env)
		clear(g.restart.Environment)
		g.restart = services.RuntimeAgentCreateGatewayRequest{}
	}
	if s.journal != nil {
		_ = s.journal.close()
	}
}
