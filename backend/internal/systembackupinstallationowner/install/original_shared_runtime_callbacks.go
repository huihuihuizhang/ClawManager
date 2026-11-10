package install

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"sync"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This source uses the SAME original maintenance owner, context, operation,
// journal and SQL gate. It is not a second gate or a native physical hold.
type originalSharedRuntimePodRow struct {
	ID                                               int
	UID, Pod, Namespace, Endpoint, Deployment, State string
	Draining                                         bool
}
type originalSharedRuntimeBinding struct {
	InstanceID, RuntimePodID, Port, Generation, PID int
	Workspace, State, Gateway                       string
}
type originalSharedRuntimeSQL struct {
	Pods     []originalSharedRuntimePodRow
	Bindings []originalSharedRuntimeBinding
}

// An opaque original source. Public JSON cannot construct a source owner.
// Empty-manager Agents are retained; unbound error/stopped sources are retained
// separately and require independent whole-node/volume absence proof.
type OriginalSharedRuntimeReservation struct {
	mu           sync.Mutex
	set          *PreparedOriginalWriterSet
	row          originalSharedRuntimePodRow
	pod          corev1.Pod
	capabilities services.RuntimeSharedBackupCapabilities
	callbacks    *services.RuntimeSharedBackupCallbacks
	identity     services.RuntimeSharedBackupIdentity
	bindings     []originalSharedRuntimeBinding
	state        *services.RuntimeSharedNativeState
	originalRaw  []byte
	dispatched   bool
}

func (*OriginalSharedRuntimeReservation) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (p *OriginalWriterMaintenance) readSharedRuntimeSQL(ctx context.Context) (originalSharedRuntimeSQL, error) {
	var out originalSharedRuntimeSQL
	if p == nil || p.check(ctx) != nil {
		return out, ErrInstall
	}
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, ErrInstall
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,p.deployment_name,p.state,p.draining FROM runtime_pods p WHERE p.namespace=? ORDER BY p.id FOR SHARE`, p.operator.installer.plan.Target.Namespace)
	if err != nil {
		return out, ErrInstall
	}
	for rows.Next() {
		var r originalSharedRuntimePodRow
		if rows.Scan(&r.ID, &r.UID, &r.Pod, &r.Namespace, &r.Endpoint, &r.Deployment, &r.State, &r.Draining) != nil || len(out.Pods) >= 100000 {
			rows.Close()
			return out, ErrInstall
		}
		out.Pods = append(out.Pods, r)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return out, ErrInstall
	}
	rows, err = tx.QueryContext(ctx, `SELECT b.instance_id,b.runtime_pod_id,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE p.namespace=? ORDER BY b.instance_id,b.runtime_pod_id FOR SHARE`, p.operator.installer.plan.Target.Namespace)
	if err != nil {
		return out, ErrInstall
	}
	for rows.Next() {
		var b originalSharedRuntimeBinding
		if rows.Scan(&b.InstanceID, &b.RuntimePodID, &b.Port, &b.Workspace, &b.Generation, &b.State, &b.Gateway, &b.PID) != nil || len(out.Bindings) >= 100000 {
			rows.Close()
			return out, ErrInstall
		}
		out.Bindings = append(out.Bindings, b)
	}
	if rows.Err() != nil || rows.Close() != nil || tx.Rollback() != nil {
		return out, ErrInstall
	}
	return out, nil
}

// Called from the real PreparedOriginalWriterSet factory after its complete
// original SQL/Kubernetes census, mounted-history and journal construction.
func (s *PreparedOriginalWriterSet) prepareSharedRuntimeCallbacks(ctx context.Context, pods []corev1.Pod, selected map[string]OriginalDeploymentSelection) error {
	if s == nil || s.origin != s || s.owner.check(ctx) != nil || s.selection.SharedRuntimeProtocol != services.RuntimeSharedBackupProtocol || len(s.selection.Gateways) != 0 || s.agent == nil || s.journal == nil {
		return ErrInstall
	}
	callbacks, err := services.NewRuntimeSharedBackupCallbacks(s.agent)
	if err != nil {
		return ErrInstall
	}
	projection, err := s.owner.readSharedRuntimeSQL(ctx)
	if err != nil {
		return ErrInstall
	}
	s.sharedSQL = projection
	sources := map[int]domain.SourceInstance{}
	for _, source := range s.owner.instances {
		sources[source.ID] = source
	}
	bound := map[int]bool{}
	seenPods := map[int]bool{}
	for _, pod := range pods {
		if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" {
			continue
		}
		ref := pod.OwnerReferences[0]
		rs, err := s.owner.operator.installer.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil || rs.UID != ref.UID || len(rs.OwnerReferences) != 1 {
			return ErrInstall
		}
		dp := rs.OwnerReferences[0]
		if dp.Kind != "Deployment" || selected[dp.Name].Role != "agent" {
			continue
		}
		if ref.Controller == nil || !*ref.Controller || dp.Controller == nil || !*dp.Controller || selected[dp.Name].UID != string(dp.UID) || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.HostNetwork || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "runtime" || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || !pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].State.Running == nil || pod.Status.ContainerStatuses[0].ContainerID == "" || pod.Spec.NodeName == "" {
			return OriginalWriterSourceFailure{Dependency: "complete_actual_shared_runtime_pod_required"}
		}
		var row originalSharedRuntimePodRow
		for _, actual := range projection.Pods {
			if actual.UID == string(pod.UID) || actual.Pod == pod.Name {
				if row.ID != 0 || actual.UID != string(pod.UID) || actual.Namespace != pod.Namespace || actual.Deployment != dp.Name || actual.ID <= 0 {
					return ErrInstall
				}
				row = actual
			}
		}
		if row.ID == 0 || seenPods[row.ID] {
			return OriginalWriterSourceFailure{Dependency: "actual_shared_runtime_sql_pod_registration_required"}
		}
		seenPods[row.ID] = true
		u, err := url.Parse(row.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Port() != "19090" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
			return ErrInstall
		}
		caps, raw, err := callbacks.Capabilities(ctx, row.Endpoint)
		if err != nil || caps.Namespace != pod.Namespace || caps.PodUID != string(pod.UID) || caps.Deployment != dp.Name {
			return OriginalWriterSourceFailure{Dependency: "actual_shared_runtime_protocol_capabilities_required"}
		}
		reservation := &OriginalSharedRuntimeReservation{set: s, row: row, pod: *pod.DeepCopy(), capabilities: caps, callbacks: callbacks, identity: services.RuntimeSharedBackupIdentity{Protocol: services.RuntimeSharedBackupProtocol, Namespace: pod.Namespace, PodUID: string(pod.UID), Deployment: dp.Name, AgentEpoch: caps.AgentEpoch, OperationID: s.owner.operation, InventorySHA256: s.inventorySHA}}
		for _, b := range projection.Bindings {
			if b.RuntimePodID != row.ID {
				continue
			}
			source, ok := sources[b.InstanceID]
			if !ok || source.Mode != "lite" || bound[source.ID] || source.Generation != b.Generation || source.Workspace != b.Workspace || source.Status != b.State || source.Pod != "" && source.Pod != row.Pod || source.Namespace != "" && source.Namespace != row.Namespace || b.Gateway != fmt.Sprintf("gw-%d-%d", source.ID, source.Generation) || b.Port <= 0 || b.Port > 65535 || b.PID < 0 {
				return ErrInstall
			}
			reservation.bindings = append(reservation.bindings, b)
			bound[source.ID] = true
		}
		s.sharedRuntimes = append(s.sharedRuntimes, reservation)
		if s.journal.append(ctx, reservation.ID(), "shared_original_capabilities_observed", nil, struct {
			Identity            services.RuntimeSharedBackupIdentity
			Raw                 []byte
			PodUID, ContainerID string
		}{reservation.identity, raw, string(pod.UID), pod.Status.ContainerStatuses[0].ContainerID}) != nil {
			return ErrInstall
		}
	}
	// No live Agent may be omitted merely because it owns no current instance.
	for _, selection := range selected {
		if selection.Role != "agent" {
			continue
		}
		found := false
		for _, r := range s.sharedRuntimes {
			if r.row.Deployment == selection.Name {
				found = true
			}
		}
		if !found {
			return OriginalWriterSourceFailure{Dependency: "every_original_shared_agent_requires_real_reservation_source"}
		}
	}
	for _, source := range s.owner.instances {
		if source.Mode != "lite" || bound[source.ID] {
			continue
		}
		if source.Status != "error" && source.Status != "stopped" {
			return OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "running_original_lite_requires_actual_shared_binding"}
		}
		s.sharedUnbound = append(s.sharedUnbound, source)
	}
	if len(s.sharedRuntimes) == 0 {
		return ErrInstall
	}
	sort.Slice(s.sharedRuntimes, func(i, j int) bool { return s.sharedRuntimes[i].ID() < s.sharedRuntimes[j].ID() })
	if s.validateOriginalSharedAgentSelection(ctx) != nil {
		return ErrInstall
	}
	return s.recheckSharedRuntimeCallbacks(ctx)
}

func (s *PreparedOriginalWriterSet) recheckSharedRuntimeCallbacks(ctx context.Context) error {
	if s == nil || s.origin != s || s.owner.check(ctx) != nil || s.owner.checkInstances(ctx) != nil {
		return ErrInstall
	}
	current, err := s.owner.readSharedRuntimeSQL(ctx)
	if err != nil || !reflect.DeepEqual(current, s.sharedSQL) {
		return ErrInstall
	}
	for _, r := range s.sharedRuntimes {
		pod, err := s.owner.operator.installer.kube.CoreV1().Pods(r.pod.Namespace).Get(ctx, r.pod.Name, metav1.GetOptions{})
		if err != nil || pod.UID != r.pod.UID || originalObjectSHA(pod.Spec) != originalObjectSHA(r.pod.Spec) || !reflect.DeepEqual(pod.OwnerReferences, r.pod.OwnerReferences) || !reflect.DeepEqual(pod.Status.ContainerStatuses, r.pod.Status.ContainerStatuses) || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			return ErrInstall
		}
		if s.checkOriginalSharedRuntimeVolumes(ctx, pod) != nil {
			return ErrInstall
		}
	}
	return nil
}

func (r *OriginalSharedRuntimeReservation) ID() string { return "shared-runtime/" + r.row.UID }

// Reserve uses the original gate and a send-unknown checkpoint BEFORE one
// actual callback. A subsequent call queries that SAME original operation.
// This returns reservation data only; it never makes OriginalWriterHold.
func (r *OriginalSharedRuntimeReservation) Reserve(ctx context.Context) (services.RuntimeSharedNativeState, error) {
	var zero services.RuntimeSharedNativeState
	if r == nil || r.set == nil {
		return zero, ErrInstall
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.set
	if s.origin != s || s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || s.checkApplicationGate(ctx, "acquiring") != nil || s.recheckSharedRuntimeCallbacks(ctx) != nil {
		return zero, ErrInstall
	}
	action := "state"
	if !r.dispatched {
		if s.journal.append(ctx, r.ID(), "shared_reservation_send_unknown", nil, r.identity) != nil {
			return zero, ErrInstall
		}
		r.dispatched = true
		action = "prepare"
	}
	state, raw, err := r.callbacks.Transition(ctx, r.row.Endpoint, action, r.identity)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	if state.Phase != "reserved" || state.AgentPID != r.capabilities.AgentPID || state.AgentStartTicks != r.capabilities.AgentStartTicks || state.GuardPath != r.capabilities.GuardPath || state.JournalPath != r.capabilities.JournalDirectory+"/current.json" || len(state.Entries) != len(r.bindings) {
		return zero, ErrInstall
	}
	seen := map[int]bool{}
	for _, entry := range state.Entries {
		matched := false
		for _, b := range r.bindings {
			if entry.InstanceID != b.InstanceID {
				continue
			}
			for _, source := range s.owner.instances {
				if source.ID != b.InstanceID {
					continue
				}
				matched = entry.UserID == source.UserID && entry.RuntimeType == source.Type && entry.Generation == b.Generation && entry.Port == b.Port && entry.PID == b.PID && entry.OriginalState == b.State && entry.GatewayID == b.Gateway
			}
		}
		if !matched || seen[entry.InstanceID] {
			return zero, ErrInstall
		}
		seen[entry.InstanceID] = true
	}
	if r.state != nil && r.state.OriginalSHA256 != state.OriginalSHA256 {
		return zero, ErrInstall
	}
	if s.journal.append(ctx, r.ID(), "shared_original_reservation_observed", nil, struct {
		State services.RuntimeSharedNativeState
		Raw   []byte
	}{state, raw}) != nil {
		return zero, ErrCommitUnknown
	}
	r.originalRaw = append([]byte(nil), raw...)
	r.state = &state
	return state, nil
}
