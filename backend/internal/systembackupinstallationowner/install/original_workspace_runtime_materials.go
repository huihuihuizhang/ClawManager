package install

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalWorkspaceRuntimeDefinition struct {
	Version, Operation string
	Baseline, AgentCA  BootstrapSourceFilePin
	RequireShared      bool
}

type OriginalWorkspaceRuntimeAgent struct {
	Deployment, DeploymentUID, Pod, PodUID, Namespace, Node, ContainerID, Endpoint string
	ControlToken                                                                   BootstrapSourceFilePin
	Gateways                                                                       []services.RuntimeAgentGatewayState
	Capabilities                                                                   *services.RuntimeSharedBackupCapabilities `json:",omitempty"`
}

// Authenticated operational DATA for this deployment, never native pause,
// source authority, immutable original reservation or backup readiness proof.
type OriginalWorkspaceRuntimeReceipt struct {
	Version, Status, PlanSHA256, DefinitionSHA256, Operation, Namespace, NamespaceUID string
	AuthorityHead                                                                     HeadCAS
	Instances                                                                         []domain.SourceInstance
	RuntimeSQL                                                                        originalSharedRuntimeSQL
	Agents                                                                            []OriginalWorkspaceRuntimeAgent
	ObservedAt                                                                        time.Time
}

func (s *authenticatedOperator) readWorkspaceRuntimeSQL(ctx context.Context) ([]domain.SourceInstance, originalSharedRuntimeSQL, error) {
	var projection originalSharedRuntimeSQL
	tx, err := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, projection, ErrInstall
	}
	defer tx.Rollback()
	if _, err := s.lockAdmin(ctx, tx); err != nil {
		return nil, projection, ErrInstall
	}
	sources, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return nil, projection, ErrInstall
	}
	rows, err := tx.QueryContext(ctx, `SELECT p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,p.deployment_name,p.state,p.draining FROM runtime_pods p WHERE p.namespace=? ORDER BY p.id FOR SHARE`, s.installer.plan.Target.Namespace)
	if err != nil {
		return nil, projection, ErrInstall
	}
	for rows.Next() {
		var row originalSharedRuntimePodRow
		if rows.Scan(&row.ID, &row.UID, &row.Pod, &row.Namespace, &row.Endpoint, &row.Deployment, &row.State, &row.Draining) != nil || len(projection.Pods) >= 100000 {
			rows.Close()
			return nil, projection, ErrInstall
		}
		projection.Pods = append(projection.Pods, row)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, projection, ErrInstall
	}
	rows, err = tx.QueryContext(ctx, `SELECT b.instance_id,b.runtime_pod_id,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE p.namespace=? ORDER BY b.instance_id,b.runtime_pod_id FOR SHARE`, s.installer.plan.Target.Namespace)
	if err != nil {
		return nil, projection, ErrInstall
	}
	for rows.Next() {
		var row originalSharedRuntimeBinding
		if rows.Scan(&row.InstanceID, &row.RuntimePodID, &row.Port, &row.Workspace, &row.Generation, &row.State, &row.Gateway, &row.PID) != nil || len(projection.Bindings) >= 100000 {
			rows.Close()
			return nil, projection, ErrInstall
		}
		projection.Bindings = append(projection.Bindings, row)
	}
	if rows.Err() != nil || rows.Close() != nil || tx.Rollback() != nil {
		return nil, projection, ErrInstall
	}
	return sources, projection, nil
}

func (s *authenticatedOperator) workspaceRuntimeToken(ctx context.Context, pod *corev1.Pod) ([]byte, error) {
	var token []byte
	for _, entry := range pod.Spec.Containers[0].Env {
		if entry.Name != "RUNTIME_AGENT_CONTROL_TOKEN" && entry.Name != "CLAWMANAGER_AGENT_CONTROL_TOKEN" {
			continue
		}
		value := []byte(entry.Value)
		if entry.ValueFrom != nil {
			ref := entry.ValueFrom.SecretKeyRef
			if ref == nil || ref.Name == "" || ref.Key == "" || ref.Optional != nil && *ref.Optional {
				return nil, ErrInstall
			}
			secret, err := s.installer.kube.CoreV1().Secrets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
			if err != nil || secret.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			value = bytes.Clone(secret.Data[ref.Key])
		}
		if len(value) < 32 || len(value) > 8192 || strings.ContainsAny(string(value), " \t\r\n\x00") || token != nil && !bytes.Equal(token, value) {
			return nil, ErrInstall
		}
		token = bytes.Clone(value)
	}
	if len(token) == 0 {
		return nil, ErrInstall
	}
	return token, nil
}

func originalWorkspaceStatesPreserved(before, after []domain.SourceInstance, namespace string) bool {
	if len(before) == 0 || len(before) != len(after) {
		return false
	}
	for index, old := range before {
		current := after[index]
		if old.Mode != "lite" || old.Status != "running" {
			if old != current {
				return false
			}
			continue
		}
		if current.Generation < old.Generation || current.Status != "running" || current.Namespace != "" && current.Namespace != namespace {
			return false
		}
		old.Generation, old.Pod = current.Generation, current.Pod
		if old.Namespace == "" {
			old.Namespace = current.Namespace
		}
		if old != current {
			return false
		}
	}
	return true
}

// Calls only actual complete SQL/Kube/authentication and actual authenticated
// GatewayState/Caps reads. It never starts/stops a Gateway or writes SQL.
// Before captures the old three-running/etc DATA; after waits for the REAL
// ordinary scheduler to reconstruct those sources, retaining every stopped/
// error/Pro source and rejecting unauthorized source-universe changes.
func (i *Installer) ProduceOriginalWorkspaceRuntimeMaterials(ctx context.Context, password []byte, enrollment EnrollmentPin, file, digest, directory string, after bool) (OriginalWorkspaceRuntimeReceipt, error) {
	var zero OriginalWorkspaceRuntimeReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	var definition OriginalWorkspaceRuntimeDefinition
	if err != nil || decodeExact(raw, &definition) != nil || definition.Version != "original-workspace-runtime-observation.v1" || !stopTokenValidOriginalOperation(definition.Operation) {
		return zero, ErrInstall
	}
	operator, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	authority, _, err := operator.observerPKIOwner(ctx, enrollment)
	if err != nil {
		return zero, ErrInstall
	}
	var baseline OriginalWorkspaceRuntimeReceipt
	if after {
		body, e := readBootstrapSourcePin(definition.Baseline, 4<<20)
		if e != nil || decodeExact(body, &baseline) != nil || baseline.Version != "original-workspace-runtime-materials.v1" || baseline.Operation != definition.Operation || baseline.PlanSHA256 != i.planHash || baseline.NamespaceUID != i.plan.Target.NamespaceUID || baseline.Status != "original_before_deployment_data_no_native_proof" {
			return zero, ErrInstall
		}
	}
	var ca []byte
	if definition.AgentCA != (BootstrapSourceFilePin{}) {
		ca, err = readBootstrapSourcePin(definition.AgentCA, 262144)
		if err != nil {
			return zero, ErrInstall
		}
	}
	for {
		// A new actual local-admin authentication refreshes only this bounded
		// read-only deployment observation; no capture/recovery grant is renewed.
		if after && time.Until(operator.until) < 20*time.Second {
			fresh, e := i.authenticate(ctx, password)
			if e != nil {
				return zero, ErrInstall
			}
			current, _, e := fresh.observerPKIOwner(ctx, enrollment)
			if e != nil || current.cas != authority.cas {
				return zero, ErrInstall
			}
			operator = fresh
		}
		result, err := operator.observeWorkspaceRuntime(ctx, definition, directory, after, baseline, ca)
		if err == nil {
			current, now, e := operator.observerPKIOwner(ctx, enrollment)
			if e != nil || current.cas != authority.cas {
				return zero, ErrInstall
			}
			fresh, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
			if e != nil || !bytes.Equal(fresh, raw) {
				return zero, ErrInstall
			}
			result.Version, result.PlanSHA256, result.DefinitionSHA256 = "original-workspace-runtime-materials.v1", i.planHash, digest
			result.Operation, result.Namespace, result.NamespaceUID = definition.Operation, i.plan.Target.Namespace, i.plan.Target.NamespaceUID
			result.AuthorityHead, result.ObservedAt = authority.cas, now
			result.Status = "original_before_deployment_data_no_native_proof"
			if after {
				result.Status = "actual_original_business_states_and_running_gateways_observed_no_backup_proof"
			}
			return result, nil
		}
		if !after || errors.Is(err, ErrOriginalObserverPKIUnconfirmed) {
			return zero, err
		}
		select {
		case <-ctx.Done():
			return zero, ErrInstall
		case <-time.After(2 * time.Second):
		}
	}
}

func stopTokenValidOriginalOperation(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, letter := range value {
		if letter < '0' || letter > '9' {
			if letter < 'a' || letter > 'f' {
				return false
			}
		}
	}
	return true
}

func (s *authenticatedOperator) observeWorkspaceRuntime(ctx context.Context, definition OriginalWorkspaceRuntimeDefinition, directory string, after bool, baseline OriginalWorkspaceRuntimeReceipt, ca []byte) (OriginalWorkspaceRuntimeReceipt, error) {
	var result OriginalWorkspaceRuntimeReceipt
	sources, projection, err := s.readWorkspaceRuntimeSQL(ctx)
	if err != nil || len(sources) == 0 || after && !originalWorkspaceStatesPreserved(baseline.Instances, sources, s.installer.plan.Target.Namespace) {
		return result, ErrInstall
	}
	result.Instances, result.RuntimeSQL = sources, projection
	pods, err := s.installer.kube.CoreV1().Pods(s.installer.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, ErrInstall
	}
	used := map[int]bool{}
	podPins := map[string]string{}
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	for _, pod := range pods.Items {
		if pod.Labels["clawmanager.io/runtime-type"] == "" {
			continue
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 || !pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].State.Running == nil || pod.UID == "" || len(pod.OwnerReferences) != 1 {
			return result, ErrInstall
		}
		podPins[string(pod.UID)] = originalWorkspacePodStamps(&corev1.PodList{Items: []corev1.Pod{pod}})
		owner := pod.OwnerReferences[0]
		if owner.Kind != "ReplicaSet" || owner.Controller == nil || !*owner.Controller {
			return result, ErrInstall
		}
		rs, e := s.installer.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if e != nil || rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
			return result, ErrInstall
		}
		parent := rs.OwnerReferences[0]
		dep, e := s.installer.kube.AppsV1().Deployments(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
		if e != nil || parent.Kind != "Deployment" || parent.Controller == nil || !*parent.Controller || dep.UID != parent.UID || dep.DeletionTimestamp != nil {
			return result, ErrInstall
		}
		var row originalSharedRuntimePodRow
		for _, candidate := range projection.Pods {
			if candidate.Pod == pod.Name && candidate.Namespace == pod.Namespace {
				if row.ID != 0 || candidate.UID != "" && candidate.UID != string(pod.UID) || candidate.Deployment != dep.Name || after && candidate.UID != string(pod.UID) {
					return result, ErrInstall
				}
				row = candidate
			}
		}
		endpoint, e := url.Parse(row.Endpoint)
		if row.ID == 0 || e != nil || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() != "19090" || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) || after && definition.RequireShared && endpoint.Scheme != "https" {
			return result, ErrInstall
		}
		token, e := s.workspaceRuntimeToken(ctx, &pod)
		if e != nil {
			return result, ErrInstall
		}
		var client services.RuntimeAgentClient
		if len(ca) > 0 {
			client, e = services.NewRuntimeAgentClientWithPinnedCA(string(token), ca)
		} else {
			client = services.NewRuntimeAgentClientWithHTTPClient(string(token), &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
		}
		if e != nil {
			clear(token)
			return result, ErrInstall
		}
		name := "agent-" + hash([]byte(string(pod.UID)))[:24] + ".control-token"
		files[name] = token
		agent := OriginalWorkspaceRuntimeAgent{Deployment: dep.Name, DeploymentUID: string(dep.UID), Pod: pod.Name, PodUID: string(pod.UID), Namespace: pod.Namespace, Node: pod.Spec.NodeName, ContainerID: pod.Status.ContainerStatuses[0].ContainerID, Endpoint: row.Endpoint, ControlToken: BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(token)}, Gateways: []services.RuntimeAgentGatewayState{}}
		if after && definition.RequireShared {
			callbacks, e := services.NewRuntimeSharedBackupCallbacks(client)
			if e != nil {
				return result, ErrInstall
			}
			caps, _, e := callbacks.Capabilities(ctx, row.Endpoint)
			if e != nil || caps.PodUID != string(pod.UID) || caps.Deployment != dep.Name || caps.Namespace != pod.Namespace {
				return result, ErrInstall
			}
			agent.Capabilities = &caps
		}
		for _, source := range sources {
			if source.Mode != "lite" || source.Status != "running" {
				continue
			}
			for _, binding := range projection.Bindings {
				if binding.InstanceID != source.ID || binding.RuntimePodID != row.ID {
					continue
				}
				if used[source.ID] || binding.State != "running" || binding.Generation != source.Generation || binding.Workspace != source.Workspace || binding.Gateway != fmt.Sprintf("gw-%d-%d", source.ID, source.Generation) {
					return result, ErrInstall
				}
				state, e := originalWorkspaceGatewayState(ctx, client, row.Endpoint, binding.Gateway)
				if e != nil || state == nil || state.State != "running" || state.InstanceID != source.ID || state.UserID != source.UserID || state.Generation != source.Generation || state.GatewayID != binding.Gateway || state.Port != binding.Port || state.PID <= 0 || binding.PID > 0 && binding.PID != state.PID || after && binding.PID != state.PID {
					return result, ErrInstall
				}
				agent.Gateways = append(agent.Gateways, *state)
				used[source.ID] = true
			}
		}
		result.Agents = append(result.Agents, agent)
	}
	for _, source := range sources {
		if source.Mode == "lite" && source.Status == "running" && !used[source.ID] {
			return result, ErrInstall
		}
	}
	if len(result.Agents) == 0 {
		return result, ErrInstall
	}
	again, sqlAgain, err := s.readWorkspaceRuntimeSQL(ctx)
	if err != nil || !reflect.DeepEqual(again, sources) || !reflect.DeepEqual(sqlAgain, projection) {
		return result, ErrInstall
	}
	podsAgain, err := s.installer.kube.CoreV1().Pods(s.installer.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || originalWorkspacePodStamps(pods) != originalWorkspacePodStamps(podsAgain) {
		return result, ErrInstall
	}
	for _, agent := range result.Agents {
		pod, e := s.installer.kube.CoreV1().Pods(agent.Namespace).Get(ctx, agent.Pod, metav1.GetOptions{})
		if e != nil || string(pod.UID) != agent.PodUID || len(pod.OwnerReferences) != 1 || podPins[agent.PodUID] != originalWorkspacePodStamps(&corev1.PodList{Items: []corev1.Pod{*pod}}) {
			return result, ErrInstall
		}
		owner := pod.OwnerReferences[0]
		rs, e := s.installer.kube.AppsV1().ReplicaSets(agent.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if e != nil || rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
			return result, ErrInstall
		}
		dep, e := s.installer.kube.AppsV1().Deployments(agent.Namespace).Get(ctx, agent.Deployment, metav1.GetOptions{})
		if e != nil || string(dep.UID) != agent.DeploymentUID || dep.UID != rs.OwnerReferences[0].UID || dep.DeletionTimestamp != nil {
			return result, ErrInstall
		}
	}
	sort.Slice(result.Agents, func(i, j int) bool { return result.Agents[i].PodUID < result.Agents[j].PodUID })
	// Create only after every read succeeds. Retry loops above leave no partial
	// credential output and never replay a source mutation or create request.
	if err := writeNewFiles(directory, files); err != nil {
		return result, ErrOriginalObserverPKIUnconfirmed
	}
	return result, nil
}

func originalWorkspacePodStamps(pods *corev1.PodList) string {
	if pods == nil {
		return ""
	}
	type stamp struct {
		UID        string
		Labels     map[string]string
		PodIP      string
		PodIPs     []corev1.PodIP
		Spec       corev1.PodSpec
		Owners     []metav1.OwnerReference
		Deleting   *metav1.Time
		Phase      corev1.PodPhase
		Containers []corev1.ContainerStatus
	}
	items := make([]stamp, 0, len(pods.Items))
	for _, pod := range pods.Items {
		items = append(items, stamp{string(pod.UID), pod.Labels, pod.Status.PodIP, pod.Status.PodIPs, pod.Spec, pod.OwnerReferences, pod.DeletionTimestamp, pod.Status.Phase, pod.Status.ContainerStatuses})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UID < items[j].UID })
	raw, err := canonical(items)
	if err != nil {
		return ""
	}
	return hash(raw)
}

type OriginalWorkspaceGatewayStopDefinition struct {
	Version, Operation, PodUID, GatewayID string
	Baseline, AgentCA                     BootstrapSourceFilePin
}

// Stop exactly one genuinely observed original Gateway through the existing
// SDK. The backend must already be natively absent, so its SQL desired state
// remains running. This is an operational acknowledgement, never exit proof.
// A durable create-only intent prevents replay after any uncertain response.
func (i *Installer) StopOriginalWorkspaceGateway(ctx context.Context, password []byte, enrollment EnrollmentPin, file, digest, directory string) (any, error) {
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(directory) != nil {
		return nil, ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	var definition OriginalWorkspaceGatewayStopDefinition
	if err != nil || decodeExact(raw, &definition) != nil || definition.Version != "original-workspace-gateway-stop.v1" || !stopTokenValidOriginalOperation(definition.Operation) {
		return nil, ErrInstall
	}
	body, err := readBootstrapSourcePin(definition.Baseline, 4<<20)
	var baseline OriginalWorkspaceRuntimeReceipt
	if err != nil || decodeExact(body, &baseline) != nil || baseline.Version != "original-workspace-runtime-materials.v1" || baseline.Operation != definition.Operation || baseline.PlanSHA256 != i.planHash || baseline.NamespaceUID != i.plan.Target.NamespaceUID || baseline.Namespace != i.plan.Target.Namespace || baseline.Status != "original_before_deployment_data_no_native_proof" && baseline.Status != "actual_original_business_states_and_running_gateways_observed_no_backup_proof" {
		return nil, ErrInstall
	}
	operator, err := i.authenticate(ctx, password)
	if err != nil {
		return nil, ErrInstall
	}
	authority, _, err := operator.observerPKIOwner(ctx, enrollment)
	if err != nil || authority.cas != baseline.AuthorityHead {
		return nil, ErrInstall
	}
	sources, projection, err := operator.readWorkspaceRuntimeSQL(ctx)
	if err != nil || !reflect.DeepEqual(sources, baseline.Instances) || !reflect.DeepEqual(projection, baseline.RuntimeSQL) {
		return nil, ErrInstall
	}
	var selected *OriginalWorkspaceRuntimeAgent
	var gateway *services.RuntimeAgentGatewayState
	for index := range baseline.Agents {
		agent := &baseline.Agents[index]
		if agent.PodUID != definition.PodUID {
			continue
		}
		if selected != nil {
			return nil, ErrInstall
		}
		selected = agent
		for index := range agent.Gateways {
			if agent.Gateways[index].GatewayID == definition.GatewayID {
				if gateway != nil {
					return nil, ErrInstall
				}
				gateway = &agent.Gateways[index]
			}
		}
	}
	if selected == nil || gateway == nil || selected.Namespace != i.plan.Target.Namespace {
		return nil, ErrInstall
	}
	// Baseline.Agents is operational input, not authority. Re-derive the one
	// target from THIS transaction's complete real SQL before any SDK mutation.
	if !originalWorkspaceGatewaySQLTarget(sources, projection, *selected, *gateway) {
		return nil, ErrInstall
	}
	pod, err := i.kube.CoreV1().Pods(selected.Namespace).Get(ctx, selected.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != selected.PodUID || pod.DeletionTimestamp != nil || pod.Spec.NodeName != selected.Node || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != selected.ContainerID || pod.Status.ContainerStatuses[0].State.Running == nil || len(pod.OwnerReferences) != 1 {
		return nil, ErrInstall
	}
	owner := pod.OwnerReferences[0]
	rs, err := i.kube.AppsV1().ReplicaSets(selected.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || owner.Kind != "ReplicaSet" || owner.Controller == nil || !*owner.Controller || rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
		return nil, ErrInstall
	}
	parent := rs.OwnerReferences[0]
	dep, err := i.kube.AppsV1().Deployments(selected.Namespace).Get(ctx, selected.Deployment, metav1.GetOptions{})
	if err != nil || parent.Kind != "Deployment" || parent.Controller == nil || !*parent.Controller || parent.UID != dep.UID || parent.Name != dep.Name || string(dep.UID) != selected.DeploymentUID || dep.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	token, err := operator.workspaceRuntimeToken(ctx, pod)
	if err != nil {
		return nil, ErrInstall
	}
	defer clear(token)
	pinnedToken, err := readBootstrapSourcePin(selected.ControlToken, 8192)
	if err != nil || !bytes.Equal(token, pinnedToken) {
		clear(pinnedToken)
		return nil, ErrInstall
	}
	clear(pinnedToken)
	endpoint, err := url.Parse(selected.Endpoint)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() != "19090" || net.ParseIP(endpoint.Hostname()) == nil || !net.ParseIP(endpoint.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
		return nil, ErrInstall
	}
	var client services.RuntimeAgentClient
	if endpoint.Scheme == "https" {
		ca, e := readBootstrapSourcePin(definition.AgentCA, 262144)
		if e != nil {
			return nil, ErrInstall
		}
		client, err = services.NewRuntimeAgentClientWithPinnedCA(string(token), ca)
		if err != nil {
			return nil, ErrInstall
		}
	} else if endpoint.Scheme == "http" && definition.AgentCA == (BootstrapSourceFilePin{}) {
		client = services.NewRuntimeAgentClientWithHTTPClient(string(token), &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	} else {
		return nil, ErrInstall
	}
	actual, err := originalWorkspaceGatewayState(ctx, client, selected.Endpoint, gateway.GatewayID)
	if err != nil || actual == nil || !reflect.DeepEqual(*actual, *gateway) {
		return nil, ErrInstall
	}
	current, _, err := operator.observerPKIOwner(ctx, enrollment)
	if err != nil || current.cas != authority.cas {
		return nil, ErrInstall
	}
	name := "gateway-" + hash([]byte(selected.PodUID + ":" + gateway.GatewayID))[:32]
	expectedDirectory := originalWorkspaceGatewayCustody(i.plan.Target.InstallationID, definition.Operation, selected.PodUID, gateway.GatewayID)
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || directory != expectedDirectory || privateDirectory(directory) != nil {
		return nil, ErrInstall
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, ErrInstall
	}
	intent, err := canonical(struct{ Version, Operation, DefinitionSHA256, PodUID, GatewayID string }{"original-workspace-gateway-stop-intent.v1", definition.Operation, digest, selected.PodUID, gateway.GatewayID})
	// Existing durable source-material writer uses O_EXCL, file fsync AND
	// directory fsync. The target directory is fixed by installation/op/Pod/GW,
	// so another --output-directory cannot bypass an uncertain original send.
	if err != nil || writeOriginalRuntimeIssuerFiles(directory, map[string][]byte{name + ".send-unknown.json": intent}) != nil {
		return nil, ErrOriginalObserverPKIUnconfirmed
	}
	retained, err := ReadPrivateFile(filepath.Join(directory, name+".send-unknown.json"), 262144)
	if err != nil || !bytes.Equal(retained, intent) {
		return nil, ErrOriginalObserverPKIUnconfirmed
	}
	if client.DeleteGateway(ctx, selected.Endpoint, gateway.GatewayID) != nil {
		return nil, ErrOriginalObserverPKIUnconfirmed
	}
	ack := struct {
		Version, Operation, PodUID, GatewayID string
		NativeExitProved                      bool
	}{"original-workspace-gateway-stop-ack.v1", definition.Operation, selected.PodUID, gateway.GatewayID, false}
	ackBytes, err := canonical(ack)
	if err != nil || writeOriginalRuntimeIssuerFiles(directory, map[string][]byte{name + ".ack.json": ackBytes}) != nil {
		return nil, ErrOriginalObserverPKIUnconfirmed
	}
	return ack, nil
}

func originalWorkspaceGatewayCustody(installation, operation, pod, gateway string) string {
	return filepath.Join("/var/lib/clawmanager-system-backup/workspace-gateway-stops", hash([]byte(installation))[:24], operation, hash([]byte(pod + ":" + gateway))[:32])
}

func originalWorkspaceGatewaySQLTarget(sources []domain.SourceInstance, projection originalSharedRuntimeSQL, agent OriginalWorkspaceRuntimeAgent, gateway services.RuntimeAgentGatewayState) bool {
	if gateway.State != "running" || gateway.PID <= 0 || gateway.Port <= 0 || agent.PodUID == "" || agent.Endpoint == "" {
		return false
	}
	var source domain.SourceInstance
	sourceCount := 0
	for _, candidate := range sources {
		if candidate.ID == gateway.InstanceID {
			source = candidate
			sourceCount++
		}
	}
	if sourceCount != 1 || source.Mode != "lite" || source.Status != "running" || source.Generation != gateway.Generation || source.UserID != gateway.UserID || gateway.GatewayID != fmt.Sprintf("gw-%d-%d", source.ID, source.Generation) || source.Workspace == "" {
		return false
	}
	var pod originalSharedRuntimePodRow
	podCount := 0
	for _, candidate := range projection.Pods {
		if candidate.Pod == agent.Pod && candidate.Namespace == agent.Namespace {
			pod = candidate
			podCount++
		}
	}
	if podCount != 1 || pod.ID <= 0 || pod.UID != "" && pod.UID != agent.PodUID || pod.Deployment != agent.Deployment || pod.Endpoint != agent.Endpoint {
		return false
	}
	count := 0
	for _, binding := range projection.Bindings {
		if binding.InstanceID != source.ID {
			continue
		}
		count++
		if binding.RuntimePodID != pod.ID || binding.State != "running" || binding.Generation != source.Generation || binding.Workspace != source.Workspace || binding.Gateway != gateway.GatewayID || binding.Port != gateway.Port || binding.PID > 0 && binding.PID != gateway.PID {
			return false
		}
	}
	return count == 1
}

// The constructors return the base interface. State read is the existing
// upgrade SDK interface on that SAME actual HTTP client; never extend the base
// interface or replace the authenticated transport with a state DTO.
func originalWorkspaceGatewayState(ctx context.Context, client services.RuntimeAgentClient, endpoint, gateway string) (*services.RuntimeAgentGatewayState, error) {
	reader, ok := client.(services.RuntimeUpgradeAgentClient)
	if !ok {
		return nil, ErrInstall
	}
	return reader.GatewayState(ctx, endpoint, gateway)
}
