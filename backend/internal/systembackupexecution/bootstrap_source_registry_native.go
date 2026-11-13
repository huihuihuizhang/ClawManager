package systembackupexecution

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"clawreef/internal/services"
	"clawreef/internal/systembackupinstallationowner/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Native read endpoints are derived exclusively from complete actual SQL rows
// and the current Pod graph. No task/runtime-control/gate/stop key is built.
func (x *bootstrapSourceRegistryReader) readNativeWriters(sqlFacts *bootstrapSourceSQLFacts, api *observedWriterAPI, clients *productionMetadataClients) (_ []bootstrapSourceNativeWriter, resultErr error) {
	step, kind, instanceID := "native_inputs", "", 0
	var observed error
	var ctx context.Context
	if x != nil {
		ctx = x.physical
	}
	defer func() { resultErr = writerNativeReadFailure(resultErr, ctx, step, kind, instanceID, observed) }()
	if x == nil || sqlFacts == nil || api == nil || clients == nil || clients.API == nil {
		return nil, install.ErrInstall
	}
	step, kind = "native_writer_graph", "Graph"
	if err := x.checkWriterGraph(sqlFacts.inventory, api, sqlFacts.metadata); err != nil {
		return nil, errors.Join(install.ErrInstall, err)
	}
	controller := x.association.Source.Controller
	step, kind, observed = "native_controller_pod", "Pod", nil
	cp, err := clients.API.CoreV1().Pods(controller.Namespace).Get(x.physical, controller.Pod, metav1.GetOptions{})
	observed = err
	if err != nil || string(cp.UID) != controller.PodUID || cp.DeletionTimestamp != nil || cp.Status.Phase != "Running" || cp.Spec.ServiceAccountName != controller.ServiceAccount || !matchesBootstrapWriterObject(api, "Pod", cp) {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_controller_pod_owner", "Pod", nil
	parent := metav1.GetControllerOf(cp)
	if parent == nil || parent.Kind != "ReplicaSet" || parent.Name != controller.ReplicaSet || string(parent.UID) != controller.ReplicaSetUID {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_controller_replicaset", "ReplicaSet", nil
	cr, err := clients.API.AppsV1().ReplicaSets(controller.Namespace).Get(x.physical, controller.ReplicaSet, metav1.GetOptions{})
	observed = err
	if err != nil || string(cr.UID) != controller.ReplicaSetUID || cr.DeletionTimestamp != nil || !matchesBootstrapWriterObject(api, "ReplicaSet", cr) {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_controller_replicaset_owner", "ReplicaSet", nil
	parent = metav1.GetControllerOf(cr)
	if parent == nil || parent.Kind != "Deployment" || parent.Name != controller.Deployment || string(parent.UID) != controller.DeploymentUID {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_controller_deployment", "Deployment", nil
	cd, err := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	observed = err
	if err != nil || string(cd.UID) != controller.DeploymentUID || cd.DeletionTimestamp != nil || cd.Spec.Template.Spec.ServiceAccountName != controller.ServiceAccount || !matchesBootstrapWriterObject(api, "Deployment", cd) {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_controller_account", "ServiceAccount", nil
	cs, err := clients.API.CoreV1().ServiceAccounts(controller.Namespace).Get(x.physical, controller.ServiceAccount, metav1.GetOptions{})
	observed = err
	if err != nil || string(cs.UID) != controller.ServiceAccountUID || cs.DeletionTimestamp != nil || x.checkPhysical(x.physical) != nil {
		return nil, install.ErrInstall
	}
	step, kind, observed = "native_census_node", "Node", nil
	for _, object := range api.objects {
		if object.Kind != "Pod" {
			continue
		}
		if object.Node == "" || x.config.Security.NodeUIDs[object.Node] == "" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		node, err := clients.API.CoreV1().Nodes().Get(x.physical, object.Node, metav1.GetOptions{})
		observed = err
		if err != nil || string(node.UID) != x.config.Security.NodeUIDs[object.Node] || node.DeletionTimestamp != nil || node.Labels["kubernetes.io/os"] != "linux" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
	}
	step, kind, observed = "native_cluster_identity", "Namespace", nil
	for _, pin := range [][2]string{{"kube-system", x.association.Target.ClusterID}, {x.config.Namespace, x.config.NamespaceUID}} {
		ns, err := clients.API.CoreV1().Namespaces().Get(x.physical, pin[0], metav1.GetOptions{})
		observed = err
		if err != nil || string(ns.UID) != pin[1] || ns.DeletionTimestamp != nil || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
	}
	bindings, pods := map[int]observedSourceRuntimeBinding{}, map[int]observedSourceRuntimePod{}
	step, kind, observed = "native_binding_state", "RuntimeBinding", nil
	for _, row := range sqlFacts.bindings {
		instanceID = row.Instance
		deferred := false
		for _, source := range sqlFacts.inventory.Instances {
			if source.ID == row.Instance && deferredRuntimeTestInstance(x.config, source) {
				deferred = true
			}
		}
		if deferred {
			bindings[row.Instance] = row
			continue
		}
		if row.State != "running" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		bindings[row.Instance] = row
	}
	// Keep the complete SQL census, including historical pool rows. As in the
	// enrolled reader, readiness is required for each current instance binding
	// below; every ready pool row must also match the live API census at the end.
	// An unused unhealthy/draining history row is not a live runtime writer.
	for _, row := range sqlFacts.pods {
		pods[row.ID] = row
	}
	var agent services.BackupGatewayAgent
	var capabilities services.RuntimeAgentBackupClient
	lite := false
	for _, instance := range sqlFacts.inventory.Instances {
		lite = lite || instance.Mode == "lite" && !deferredRuntimeTestInstance(x.config, instance)
	}
	step, kind, observed = "native_agent_credential", "RuntimeAgent", nil
	if lite {
		instanceID = 0
		a := x.association.Source.RuntimeAgent
		if a == nil || len(a.Operations) != 2 || a.Operations[0] != "backup_capabilities_read" || a.Operations[1] != "gateway_state_read" {
			return nil, install.ErrInstall
		}
		token, err := x.access.Read(x.ctx, a.Credential)
		observed = err
		if err != nil {
			return nil, install.ErrInstall
		}
		ca, err := x.access.Read(x.ctx, a.CA)
		observed = err
		if err != nil {
			clear(token)
			return nil, install.ErrInstall
		}
		client, err := services.NewRuntimeAgentClientWithPinnedCA(strings.TrimSpace(string(token)), ca)
		observed = err
		clear(token)
		if err != nil {
			return nil, install.ErrInstall
		}
		var ok bool
		agent, ok = client.(services.BackupGatewayAgent)
		if !ok {
			return nil, install.ErrInstall
		}
		capabilities, ok = client.(services.RuntimeAgentBackupClient)
		if !ok {
			return nil, install.ErrInstall
		}
	}
	out := []bootstrapSourceNativeWriter{}
	seen := map[int]bool{}
	step, kind, observed = "native_instance", "Instance", nil
	for _, instance := range sqlFacts.inventory.Instances {
		instanceID = instance.ID
		if deferredRuntimeTestInstance(x.config, instance) {
			copy := instance
			out = append(out, bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, State: "runtime_capture_deferred_by_original_test_scope", RuntimeCaptureDeferred: &copy})
			seen[instance.ID] = true
			continue
		}
		step, kind, observed = "native_stopped_pro", "Instance", nil
		if isCurrentStoppedPro(instance) {
			m, err := observeCurrentStoppedPro(x.physical, clients.API, x.config, instance, sqlFacts.metadata.CurrentStoppedProStorage[instance.ID])
			observed = err
			if err != nil {
				return nil, err
			}
			out = append(out, bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, State: "stopped", CurrentStoppedPro: &m})
			continue
		}
		step, kind, observed = "native_tenant_pro", "Instance", nil
		if instance.Mode != "lite" {
			if isRunningTenantPro(instance) && instance.Namespace != x.config.Namespace {
				mount, err := observeTenantProMountFromCensus(x.physical, clients.API, x.config, instance, api)
				observed = err
				if err != nil {
					return nil, err
				}
				out = append(out, bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, State: "running", Namespace: instance.Namespace, Pod: instance.Pod, PodUID: mount.PodUID, Deployment: mount.Deployment, DeploymentUID: mount.DeploymentUID, ReplicaSetUID: mount.ReplicaSetUID, RunningTenantPro: &mount})
			}
			continue
		}
		step, kind, observed = "native_instance_binding", "RuntimeBinding", nil
		binding := bindings[instance.ID]
		row, ok := pods[binding.RuntimePod]
		if !ok || binding.Generation != instance.Generation || binding.State != "running" || binding.PID <= 0 || binding.Port <= 0 || binding.Port > 65535 || binding.Gateway != fmt.Sprintf("gw-%d-%d", instance.ID, instance.Generation) || binding.Workspace != instance.Workspace || row.Namespace != x.config.Namespace || row.State != "ready" || row.Draining || row.Endpoint == "" {
			return nil, install.ErrInstall
		}
		if instance.Namespace != "" && instance.Namespace != row.Namespace || instance.Pod != "" && instance.Pod != row.Name {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_pod", "Pod", nil
		pod, err := clients.API.CoreV1().Pods(row.Namespace).Get(x.physical, row.Name, metav1.GetOptions{})
		observed = err
		if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) == "" || row.UID != "" && row.UID != string(pod.UID) || pod.Spec.ServiceAccountName == "" || !matchesBootstrapWriterObject(api, "Pod", pod) {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_endpoint", "RuntimeAgent", nil
		u, err := url.Parse(row.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || net.ParseIP(u.Hostname()) == nil || net.ParseIP(pod.Status.PodIP) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_pod_owner", "Pod", nil
		parent := metav1.GetControllerOf(pod)
		if parent == nil || parent.Kind != "ReplicaSet" {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_replicaset", "ReplicaSet", nil
		rs, err := clients.API.AppsV1().ReplicaSets(row.Namespace).Get(x.physical, parent.Name, metav1.GetOptions{})
		observed = err
		if err != nil || rs.UID != parent.UID || rs.DeletionTimestamp != nil || !matchesBootstrapWriterObject(api, "ReplicaSet", rs) {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_replicaset_owner", "ReplicaSet", nil
		parent = metav1.GetControllerOf(rs)
		if parent == nil || parent.Kind != "Deployment" || parent.Name != row.Deployment {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_deployment", "Deployment", nil
		dep, err := clients.API.AppsV1().Deployments(row.Namespace).Get(x.physical, parent.Name, metav1.GetOptions{})
		observed = err
		if err != nil || dep.UID != parent.UID || dep.DeletionTimestamp != nil || !matchesBootstrapWriterObject(api, "Deployment", dep) {
			return nil, install.ErrInstall
		}
		// Pod admission selects the namespace's default account when the
		// Deployment template omits it. Keep the original census unchanged.
		templateAccount := dep.Spec.Template.Spec.ServiceAccountName
		if templateAccount == "" {
			templateAccount = "default"
		}
		if templateAccount != pod.Spec.ServiceAccountName {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_account", "ServiceAccount", nil
		sa, err := clients.API.CoreV1().ServiceAccounts(row.Namespace).Get(x.physical, pod.Spec.ServiceAccountName, metav1.GetOptions{})
		observed = err
		if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_instance_approved_node", "Node", nil
		approved := false
		for _, ref := range x.config.RuntimeSources.Deployments {
			approved = approved || ref.Namespace == row.Namespace && ref.Name == dep.Name && ref.UID == string(dep.UID)
		}
		if !approved || x.config.Security.NodeUIDs[pod.Spec.NodeName] == "" {
			return nil, install.ErrInstall
		}
		node, err := clients.API.CoreV1().Nodes().Get(x.physical, pod.Spec.NodeName, metav1.GetOptions{})
		observed = err
		if err != nil || string(node.UID) != x.config.Security.NodeUIDs[pod.Spec.NodeName] || node.DeletionTimestamp != nil || node.Labels["kubernetes.io/os"] != "linux" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_agent_capabilities", "RuntimeAgent", nil
		caps, err := capabilities.BackupCapabilities(x.physical, row.Endpoint, binding.Port)
		observed = err
		if err != nil || caps == nil || caps.Protocol != services.RuntimeBackupProtocol || caps.Scope != services.RuntimeBackupStopScope || caps.Namespace != row.Namespace || caps.PodUID != string(pod.UID) || caps.GatewayPort != binding.Port || caps.AgentEpoch == "" || caps.Slot == "" || !caps.Supported || !caps.DurableReservation || !services.RuntimeBackupSupportsOriginalOperationRecovery(caps) || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		step, kind, observed = "native_gateway_state", "RuntimeAgent", nil
		state, err := agent.GatewayState(x.physical, row.Endpoint, binding.Gateway)
		observed = err
		if err != nil || state == nil || state.State != "running" || state.InstanceID != instance.ID || state.UserID != instance.UserID || state.Generation != instance.Generation || state.GatewayID != binding.Gateway || state.PID != binding.PID || state.Port != binding.Port || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		seen[instance.ID] = true
		out = append(out, bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, RuntimePodID: row.ID, PID: binding.PID, Port: binding.Port, Namespace: row.Namespace, Pod: row.Name, PodUID: string(pod.UID), Deployment: row.Deployment, Gateway: binding.Gateway, Endpoint: row.Endpoint, AgentEpoch: caps.AgentEpoch, State: state.State, DeploymentUID: string(dep.UID), ReplicaSetUID: string(rs.UID), ServiceAccount: sa.Name, ServiceAccountUID: string(sa.UID), NodeUID: string(node.UID), RecoveryScope: caps.RecoveryScope, AgentRestartPolicy: caps.AgentRestartPolicy, DurableReservation: caps.DurableReservation, AgentRestartReconciliation: caps.AgentRestartReconciliation})
	}
	step, kind, observed = "native_binding_coverage", "RuntimeBinding", nil
	for _, binding := range sqlFacts.bindings {
		instanceID = binding.Instance
		if binding.State == "running" && !seen[binding.Instance] {
			return nil, install.ErrInstall
		}
	}
	step, kind, observed = "native_runtime_pool_coverage", "RuntimePod", nil
	instanceID = 0
	for _, row := range sqlFacts.pods {
		if row.State != "ready" || row.Draining {
			continue
		}
		found := false
		for _, object := range api.objects {
			found = found || object.Kind == "Pod" && object.Namespace == row.Namespace && object.Name == row.Name && (row.UID == "" || object.UID == row.UID) && object.Running
		}
		if !found {
			return nil, install.ErrInstall
		}
	}
	step, kind, observed = "native_final_authority", "Authority", nil
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	if x.checkPhysical(x.physical) != nil {
		return nil, install.ErrInstall
	}
	return out, nil
}

// A successful GET must still be the exact object in this round's complete
// census. A replacement with the same name cannot be joined to an earlier UID,
// resource version, process list or owner graph merely because its RPC works.
func matchesBootstrapWriterObject(api *observedWriterAPI, kind string, object runtime.Object) bool {
	if api == nil || object == nil {
		return false
	}
	actual, err := projectWriterAPIObject(kind, object)
	if err != nil {
		return false
	}
	for _, selected := range api.objects {
		if selected.Kind == kind && selected.Namespace == actual.Namespace && selected.Name == actual.Name {
			return reflect.DeepEqual(selected, actual)
		}
	}
	return false
}
