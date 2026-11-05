package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Deployment-owned inputs. No request DTO can construct the concrete Agent or
// authenticated native client. Node validates actual mounts/ELF/process owners.
type RuntimeSharedTaskConfig struct {
	Protocol, NamespaceUID, WorkspaceRoot string
	Agent                                 services.RuntimeAgentClient
	Native                                *q.SharedRuntimeNodeClient
	WholeNode                             *q.NodeObservationClient
	Agents                                []RuntimeSharedAgentDeployment
	Nodes                                 []RuntimeSharedNodeSources
}
type RuntimeSharedAgentDeployment struct{ Name, UID string }
type RuntimeSharedNodeSources struct {
	Name, UID string
	Paths     []string
}

type runtimeSharedMember struct {
	Source  b.InstanceIdentity
	Binding gatewayBindingRow
}
type runtimeSharedDefinition struct {
	Version, Task, InventorySHA256 string
	Attempt                        uint64
	Sources                        []b.InstanceIdentity
	Groups                         []runtimeSharedGroup
	Unbound                        []b.InstanceIdentity
}
type runtimeSharedGroup struct {
	Key, Namespace, Deployment, DeploymentUID, Endpoint              string
	Generation                                                       int64
	Pod                                                              q.PodIdentity
	NodeUID, PodSpecSHA256, WorkspaceRoot, AgentDataDir, OperationID string
	Capabilities                                                     services.RuntimeSharedBackupCapabilities
	Members                                                          []runtimeSharedMember
	Paths                                                            []string
}
type runtimeSharedActor struct {
	Group    runtimeSharedGroup
	Agent    *services.RuntimeSharedNativeState
	AgentRaw []byte
	Request  q.SharedRuntimeNodeRequest
	Last     *q.SharedRuntimeNodeResponse
	Sent     map[string]bool
}

// Versioned namespace within the EXISTING original task native-proof journal.
// Keys start shared-task.v1/<attempt>/; legacy exact-Pod proof reads cannot
// interpret these as isolated stop proof. No task/gate/schema is introduced.
type runtimeSharedBook struct {
	Nodes      []runtimeSharedWholeNode
	Version    string
	Definition runtimeSharedDefinition
	Sequence   uint64
	Actors     []runtimeSharedActor
	Stage      string
}

func runtimeSharedOperation(a d.Authority, pod, inventory string) string {
	raw, _ := json.Marshal([]string{services.RuntimeSharedBackupProtocol, a.InstallationID, a.TaskPublicID, strconv.FormatUint(a.AttemptNo, 10), pod, inventory})
	return recordHash(raw)[:32]
}
func sharedTaskKey(a d.Authority) string {
	return "shared-task.v1/" + strconv.FormatUint(a.AttemptNo, 10) + "/event/%"
}

func (o *SQLRuntimeControl) readSharedTaskBook(ctx context.Context, a d.Authority, recovery bool) (runtimeSharedBook, string, error) {
	var book runtimeSharedBook
	var digest string
	err := o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid LIKE ? ORDER BY pod_uid DESC LIMIT 1 FOR UPDATE`, a.TaskPublicID, sharedTaskKey(a)).Scan(&raw, &digest); err != nil {
			return err
		}
		if len(raw) > 65536 || recordHash(raw) != digest || json.Unmarshal(raw, &book) != nil || book.Version != "runtime-shared-task-book.v1" || book.Definition.Task != a.TaskPublicID || book.Definition.Attempt != a.AttemptNo || book.Sequence == 0 {
			return ErrExecutionRecord
		}
		return nil
	})
	return book, digest, err
}

func (o *SQLRuntimeControl) writeSharedTaskBook(ctx context.Context, a d.Authority, recovery bool, book runtimeSharedBook, previous string) error {
	book.Sequence++
	raw, err := json.Marshal(book)
	if err != nil || len(raw) > 65535 || book.Definition.Task != a.TaskPublicID || book.Definition.Attempt != a.AttemptNo {
		return ErrExecutionRecord
	}
	digest := recordHash(raw)
	return o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
		var originalRaw []byte
		var originalDigest string
		var original runtimeSharedBook
		err := tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid LIKE ? ORDER BY pod_uid DESC LIMIT 1 FOR UPDATE`, a.TaskPublicID, sharedTaskKey(a)).Scan(&originalRaw, &originalDigest)
		if previous == "" {
			if !errors.Is(err, sql.ErrNoRows) || book.Sequence != 1 {
				return ErrExecutionRecord
			}
		} else if err != nil || originalDigest != previous || recordHash(originalRaw) != previous || json.Unmarshal(originalRaw, &original) != nil || !bytes.Equal(mustSharedJSON(original.Definition), mustSharedJSON(book.Definition)) || original.Sequence+1 != book.Sequence {
			return ErrExecutionRecord
		}
		// Fixed-width numeric keys preserve exact append order in the existing
		// binary PK. No witness row is updated/deleted and no grant is widened.
		key := "shared-task.v1/" + strconv.FormatUint(a.AttemptNo, 10) + "/event/" + fmt.Sprintf("%020d", book.Sequence)
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_stop_proofs(task_public_id,pod_uid,proof_json,proof_sha256) VALUES(?,?,?,?)`, a.TaskPublicID, key, raw, digest)
		return err
	})
}

func (o *SQLRuntimeControl) discoverSharedTask(ctx context.Context, a d.Authority, sources []b.InstanceIdentity) (runtimeSharedDefinition, error) {
	var out runtimeSharedDefinition
	cfg := o.cfg.Shared
	if cfg == nil || cfg.Protocol != services.RuntimeSharedBackupProtocol || cfg.NamespaceUID == "" || cfg.Native == nil || cfg.Agent == nil || !path.IsAbs(cfg.WorkspaceRoot) || cfg.WorkspaceRoot == "/" || o.cfg.Gate.Authority.Check(ctx, a) != nil {
		return out, ErrExecutionAuthority
	}
	callbacks, err := services.NewRuntimeSharedBackupCallbacks(cfg.Agent)
	if err != nil {
		return out, err
	}
	ns, err := o.cfg.Client.CoreV1().Namespaces().Get(ctx, o.cfg.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil {
		return out, ErrExecutionRecord
	}
	out = runtimeSharedDefinition{Version: "runtime-shared-task-definition.v1", Task: a.TaskPublicID, Attempt: a.AttemptNo, Sources: append([]b.InstanceIdentity(nil), sources...), Groups: []runtimeSharedGroup{}, Unbound: []b.InstanceIdentity{}}
	out.InventorySHA256 = recordHash(mustSharedJSON(struct {
		Task    string
		Attempt uint64
		Sources []b.InstanceIdentity
	}{a.TaskPublicID, a.AttemptNo, sources}))
	selected := map[string]string{}
	for _, ref := range cfg.Agents {
		if ref.Name == "" || ref.UID == "" || selected[ref.Name] != "" {
			return out, ErrExecutionRecord
		}
		selected[ref.Name] = ref.UID
	}
	if len(selected) == 0 {
		return out, ErrExecutionRecord
	}
	pods, err := o.cfg.Client.CoreV1().Pods(o.cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, err
	}
	sort.Slice(pods.Items, func(i, j int) bool { return string(pods.Items[i].UID) < string(pods.Items[j].UID) })
	bindings := map[int]gatewayBindingRow{}
	tx, err := o.cfg.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	actual, err := domain.ReadSourceInstances(ctx, tx)
	if err == nil {
		actual, err = o.cfg.RuntimeTestScope.RuntimeInstances(actual)
	}
	if err != nil || !bytes.Equal(mustSharedJSON(actual), mustSharedJSON(sources)) {
		tx.Rollback()
		return out, ErrExecutionRecord
	}
	// No ready/status filter: error and stopped bindings remain explicit data.
	rows, err := tx.QueryContext(ctx, `SELECT b.instance_id,p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,p.deployment_name,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE p.namespace=? ORDER BY b.instance_id`, o.cfg.Namespace)
	if err != nil {
		tx.Rollback()
		return out, err
	}
	for rows.Next() {
		var id int
		var r gatewayBindingRow
		if rows.Scan(&id, &r.ID, &r.UID, &r.Pod, &r.Namespace, &r.Endpoint, &r.Port, &r.Workspace, &r.Generation, &r.State, &r.Gateway, &r.Deployment, &r.PID) != nil || bindings[id].ID != 0 {
			rows.Close()
			tx.Rollback()
			return out, ErrExecutionRecord
		}
		bindings[id] = r
	}
	if rows.Err() != nil || rows.Close() != nil || tx.Rollback() != nil {
		return out, ErrExecutionRecord
	}
	bound := map[int]bool{}
	used := map[string]bool{}
	for _, pod := range pods.Items {
		if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" {
			continue
		}
		dep, err := o.deploymentForPod(ctx, &pod)
		if err != nil {
			return out, err
		}
		if selected[dep.Name] == "" {
			continue
		}
		if string(dep.UID) != selected[dep.Name] || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "runtime" || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].State.Running == nil || !pod.Status.ContainerStatuses[0].Ready || pod.Spec.HostNetwork || pod.Spec.NodeName == "" {
			return out, ErrExecutionRecord
		}
		var endpoint string
		if err := o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT agent_endpoint FROM runtime_pods WHERE namespace=? AND pod_name=? AND pod_uid=? AND deployment_name=?`, o.cfg.Namespace, pod.Name, string(pod.UID), dep.Name).Scan(&endpoint); err != nil {
			return out, err
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Port() != "19090" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
			return out, ErrExecutionRecord
		}
		caps, _, err := callbacks.Capabilities(ctx, endpoint)
		if err != nil || caps.Namespace != pod.Namespace || caps.PodUID != string(pod.UID) || caps.Deployment != dep.Name {
			return out, ErrExecutionRecord
		}
		group := runtimeSharedGroup{Key: string(pod.UID), Namespace: pod.Namespace, Deployment: dep.Name, DeploymentUID: string(dep.UID), Generation: dep.Generation, Endpoint: endpoint, Pod: q.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{pod.Status.ContainerStatuses[0].ContainerID}}, PodSpecSHA256: recordHash(mustSharedJSON(pod.Spec)), WorkspaceRoot: cfg.WorkspaceRoot, AgentDataDir: path.Dir(caps.GuardPath), Capabilities: caps, Members: []runtimeSharedMember{}}
		for _, node := range cfg.Nodes {
			if node.Name == pod.Spec.NodeName {
				if group.NodeUID != "" || node.UID == "" || len(node.Paths) == 0 {
					return out, ErrExecutionRecord
				}
				actual, err := o.cfg.Client.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
				if err != nil || string(actual.UID) != node.UID || actual.DeletionTimestamp != nil {
					return out, ErrExecutionRecord
				}
				group.NodeUID = node.UID
				group.Paths = append([]string(nil), node.Paths...)
			}
		}
		if group.NodeUID == "" || group.Generation <= 0 {
			return out, ErrExecutionRecord
		}
		group.OperationID = runtimeSharedOperation(a, group.Key, out.InventorySHA256)
		for _, source := range sources {
			r := bindings[source.ID]
			if r.UID != group.Key {
				continue
			}
			if source.Mode != "lite" || r.Namespace != group.Namespace || r.Pod != group.Pod.Name || r.Deployment != group.Deployment || r.Endpoint != group.Endpoint || r.Generation != source.Generation || r.State != source.Status || r.Workspace != source.Workspace || bound[source.ID] {
				return out, ErrExecutionRecord
			}
			group.Members = append(group.Members, runtimeSharedMember{source, r})
			bound[source.ID] = true
		}
		out.Groups = append(out.Groups, group)
		used[dep.Name] = true
	}
	for dep := range selected {
		if !used[dep] {
			return out, ErrExecutionRecord
		}
	}
	for _, source := range sources {
		if source.Mode == "lite" && !bound[source.ID] {
			if source.Status != "error" && source.Status != "stopped" {
				return out, ErrExecutionRecord
			}
			out.Unbound = append(out.Unbound, source)
		}
	}
	// Inventory includes the complete actual source and Agent/mount universe.
	// Wire operations are derived afterwards, avoiding a self-referential hash.
	for i := range out.Groups {
		out.Groups[i].OperationID = ""
	}
	out.InventorySHA256 = ""
	out.InventorySHA256 = recordHash(mustSharedJSON(out))
	for i := range out.Groups {
		out.Groups[i].OperationID = runtimeSharedOperation(a, out.Groups[i].Key, out.InventorySHA256)
	}
	return out, nil
}

func mustSharedJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func (o *SQLRuntimeControl) prepareSharedTask(ctx context.Context, a d.Authority, sources []b.InstanceIdentity) ([]b.RuntimeWriterSpec, error) {
	book, _, err := o.readSharedTaskBook(ctx, a, false)
	if errors.Is(err, sql.ErrNoRows) {
		definition, err := o.discoverSharedTask(ctx, a, sources)
		if err != nil {
			return nil, err
		}
		book = runtimeSharedBook{Version: "runtime-shared-task-book.v1", Definition: definition, Stage: "defined", Actors: []runtimeSharedActor{}}
		for _, g := range definition.Groups {
			book.Actors = append(book.Actors, runtimeSharedActor{Group: g, Sent: map[string]bool{}})
		}
		if err := o.writeSharedTaskBook(ctx, a, false, book, ""); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if !bytes.Equal(mustSharedJSON(book.Definition.Sources), mustSharedJSON(sources)) {
		return nil, ErrExecutionRecord
	}
	var legacy []b.InstanceIdentity
	var specs []b.RuntimeWriterSpec
	for _, source := range sources {
		if source.Mode != "lite" {
			legacy = append(legacy, source)
			continue
		}
		uid := "unbound"
		generation := int64(a.ConfigVersion)
		for _, g := range book.Definition.Groups {
			for _, m := range g.Members {
				if m.Source.ID == source.ID {
					uid = g.Key
					generation = g.Generation
				}
			}
		}
		spec := b.RuntimeWriterSpec{Source: source, Kind: "shared", UID: uid, Name: uid, SharedCohort: uid, RestartRef: "shared-task.v1/" + a.TaskPublicID + "/" + strconv.FormatUint(a.AttemptNo, 10), Stopped: flow.State{UID: uid + "/member/" + strconv.Itoa(source.ID), Generation: generation, Running: source.Status == "running", Checkpoint: recordHash(mustSharedJSON(struct {
			Definition runtimeSharedDefinition
			Source     b.InstanceIdentity
		}{book.Definition, source}))}}
		for _, group := range book.Definition.Groups {
			if group.Key != uid {
				continue
			}
			for _, member := range group.Members {
				if member.Source.ID == source.ID {
					r := member.Binding
					spec.Endpoint = r.Endpoint
					spec.Port = r.Port
					spec.Runtime = b.RuntimeLocator{Version: "runtime-locator.shared.v1", Namespace: r.Namespace, Pod: r.Pod, RegisteredPodUID: r.UID, Deployment: r.Deployment, AgentEpoch: group.Capabilities.AgentEpoch, RuntimePodID: r.ID, GatewayPID: r.PID}
				}
			}
		}
		if err := o.save(ctx, a, spec, mustSharedJSON(book.Definition)); err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	old, err := o.prepareSources(ctx, a, legacy)
	if err != nil {
		return nil, err
	}
	return append(specs, old...), nil
}

// Shared IDs keep every source in the existing original custody, including an
// unbound error row. They do not masquerade as an isolated gateway/slot ID.
func sharedRuntimeWriterID(s b.RuntimeWriterSpec) string {
	if s.Source.Status == "stopped" {
		return "stopped/" + strconv.Itoa(s.Source.ID)
	}
	if s.UID != "unbound" {
		return fmt.Sprintf("gateway/%s/%d", s.UID, s.Source.ID)
	}
	return "shared-source/" + strconv.Itoa(s.Source.ID)
}

// Actual read-only service preflight for the new profile, without probing an
// isolated slot or reconstructing original requests.
func (o *SQLRuntimeControl) ResolveSharedTaskPod(ctx context.Context, source b.InstanceIdentity) (*corev1.Pod, error) {
	if o == nil || o.cfg.Shared == nil || source.Mode != "lite" {
		return nil, ErrExecutionRecord
	}
	var podName, namespace, uid, deployment, workspace, state string
	var generation int
	if err := o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT p.pod_name,p.namespace,COALESCE(p.pod_uid,''),p.deployment_name,b.workspace_path,b.state,b.generation FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE b.instance_id=? AND p.namespace=?`, source.ID, o.cfg.Namespace).Scan(&podName, &namespace, &uid, &deployment, &workspace, &state, &generation); err != nil {
		return nil, err
	}
	if uid == "" || namespace != o.cfg.Namespace || workspace != source.Workspace || state != source.Status || generation != source.Generation {
		return nil, ErrExecutionRecord
	}
	pod, err := o.cfg.Client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != uid || pod.DeletionTimestamp != nil {
		return nil, ErrExecutionRecord
	}
	dep, err := o.deploymentForPod(ctx, pod)
	if err != nil || dep.Name != deployment {
		return nil, ErrExecutionRecord
	}
	selected := false
	for _, ref := range o.cfg.Shared.Agents {
		if ref.Name == dep.Name && ref.UID == string(dep.UID) {
			selected = true
		}
	}
	if !selected {
		return nil, ErrExecutionRecord
	}
	return pod, nil
}

func (o *SQLRuntimeControl) resolveSharedSource(ctx context.Context, source b.InstanceIdentity) (b.RuntimeWriterSpec, error) {
	var zero b.RuntimeWriterSpec
	pod, err := o.ResolveSharedTaskPod(ctx, source)
	if err != nil {
		return zero, err
	}
	var r gatewayBindingRow
	if o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,p.deployment_name,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE b.instance_id=? AND p.namespace=? AND p.pod_uid=?`, source.ID, o.cfg.Namespace, string(pod.UID)).Scan(&r.ID, &r.UID, &r.Pod, &r.Namespace, &r.Endpoint, &r.Port, &r.Workspace, &r.Generation, &r.State, &r.Gateway, &r.Deployment, &r.PID) != nil {
		return zero, ErrExecutionRecord
	}
	u, err := url.Parse(r.Endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Port() != "19090" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
		return zero, ErrExecutionRecord
	}
	callbacks, err := services.NewRuntimeSharedBackupCallbacks(o.cfg.Shared.Agent)
	if err != nil {
		return zero, err
	}
	caps, _, err := callbacks.Capabilities(ctx, r.Endpoint)
	if err != nil || caps.PodUID != r.UID || caps.Namespace != r.Namespace || caps.Deployment != r.Deployment {
		return zero, ErrExecutionRecord
	}
	return b.RuntimeWriterSpec{Source: source, Kind: "shared", UID: r.UID, SharedCohort: r.UID, Name: r.Pod, Endpoint: r.Endpoint, Port: r.Port, Runtime: b.RuntimeLocator{Version: "runtime-locator.shared.v1", Namespace: r.Namespace, Pod: r.Pod, RegisteredPodUID: r.UID, Deployment: r.Deployment, AgentEpoch: caps.AgentEpoch, RuntimePodID: r.ID, GatewayPID: r.PID}}, nil
}
