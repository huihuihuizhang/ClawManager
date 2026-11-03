package systembackupexecution

import (
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
func (x *bootstrapSourceRegistryReader) readNativeWriters(sqlFacts *bootstrapSourceSQLFacts, api *observedWriterAPI, clients *productionMetadataClients) ([]bootstrapSourceNativeWriter, error) {
	if sqlFacts == nil || api == nil || clients == nil || clients.API == nil || x.checkWriterGraph(sqlFacts.inventory, api) != nil {
		return nil, install.ErrInstall
	}
	controller := x.association.Source.Controller
	cp, err := clients.API.CoreV1().Pods(controller.Namespace).Get(x.physical, controller.Pod, metav1.GetOptions{})
	if err != nil || string(cp.UID) != controller.PodUID || cp.DeletionTimestamp != nil || cp.Status.Phase != "Running" || cp.Spec.ServiceAccountName != controller.ServiceAccount || !matchesBootstrapWriterObject(api, "Pod", cp) {
		return nil, install.ErrInstall
	}
	parent := metav1.GetControllerOf(cp)
	if parent == nil || parent.Kind != "ReplicaSet" || parent.Name != controller.ReplicaSet || string(parent.UID) != controller.ReplicaSetUID {
		return nil, install.ErrInstall
	}
	cr, err := clients.API.AppsV1().ReplicaSets(controller.Namespace).Get(x.physical, controller.ReplicaSet, metav1.GetOptions{})
	if err != nil || string(cr.UID) != controller.ReplicaSetUID || cr.DeletionTimestamp != nil || !matchesBootstrapWriterObject(api, "ReplicaSet", cr) {
		return nil, install.ErrInstall
	}
	parent = metav1.GetControllerOf(cr)
	if parent == nil || parent.Kind != "Deployment" || parent.Name != controller.Deployment || string(parent.UID) != controller.DeploymentUID {
		return nil, install.ErrInstall
	}
	cd, err := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	if err != nil || string(cd.UID) != controller.DeploymentUID || cd.DeletionTimestamp != nil || cd.Spec.Template.Spec.ServiceAccountName != controller.ServiceAccount || !matchesBootstrapWriterObject(api, "Deployment", cd) {
		return nil, install.ErrInstall
	}
	cs, err := clients.API.CoreV1().ServiceAccounts(controller.Namespace).Get(x.physical, controller.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(cs.UID) != controller.ServiceAccountUID || cs.DeletionTimestamp != nil || x.checkPhysical(x.physical) != nil {
		return nil, install.ErrInstall
	}
	for _, object := range api.objects {
		if object.Kind != "Pod" {
			continue
		}
		if object.Node == "" || x.config.Security.NodeUIDs[object.Node] == "" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		node, err := clients.API.CoreV1().Nodes().Get(x.physical, object.Node, metav1.GetOptions{})
		if err != nil || string(node.UID) != x.config.Security.NodeUIDs[object.Node] || node.DeletionTimestamp != nil || node.Labels["kubernetes.io/os"] != "linux" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
	}
	for _, pin := range [][2]string{{"kube-system", x.association.Target.ClusterID}, {x.config.Namespace, x.config.NamespaceUID}} {
		ns, err := clients.API.CoreV1().Namespaces().Get(x.physical, pin[0], metav1.GetOptions{})
		if err != nil || string(ns.UID) != pin[1] || ns.DeletionTimestamp != nil || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
	}
	bindings, pods := map[int]observedSourceRuntimeBinding{}, map[int]observedSourceRuntimePod{}
	for _, row := range sqlFacts.bindings {
		if row.State != "running" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		bindings[row.Instance] = row
	}
	for _, row := range sqlFacts.pods {
		if row.State != "ready" || row.Draining {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pods[row.ID] = row
	}
	var agent services.BackupGatewayAgent
	var capabilities services.RuntimeAgentBackupClient
	lite := false
	for _, instance := range sqlFacts.inventory.Instances {
		lite = lite || instance.Mode == "lite"
	}
	if lite {
		a := x.association.Source.RuntimeAgent
		if a == nil || len(a.Operations) != 2 || a.Operations[0] != "backup_capabilities_read" || a.Operations[1] != "gateway_state_read" {
			return nil, install.ErrInstall
		}
		token, err := x.access.Read(x.ctx, a.Credential)
		if err != nil {
			return nil, install.ErrInstall
		}
		ca, err := x.access.Read(x.ctx, a.CA)
		if err != nil {
			clear(token)
			return nil, install.ErrInstall
		}
		client, err := services.NewRuntimeAgentClientWithPinnedCA(strings.TrimSpace(string(token)), ca)
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
	for _, instance := range sqlFacts.inventory.Instances {
		if instance.Mode != "lite" {
			continue
		}
		binding := bindings[instance.ID]
		row, ok := pods[binding.RuntimePod]
		if !ok || binding.Generation != instance.Generation || binding.State != "running" || binding.PID <= 0 || binding.Port <= 0 || binding.Port > 65535 || binding.Gateway != fmt.Sprintf("gw-%d-%d", instance.ID, instance.Generation) || binding.Workspace != instance.Workspace || row.Namespace != x.config.Namespace || row.State != "ready" || row.Draining || row.Endpoint == "" {
			return nil, install.ErrInstall
		}
		if instance.Namespace != "" && instance.Namespace != row.Namespace || instance.Pod != "" && instance.Pod != row.Name {
			return nil, install.ErrInstall
		}
		pod, err := clients.API.CoreV1().Pods(row.Namespace).Get(x.physical, row.Name, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) == "" || row.UID != "" && row.UID != string(pod.UID) || pod.Spec.ServiceAccountName == "" || !matchesBootstrapWriterObject(api, "Pod", pod) {
			return nil, install.ErrInstall
		}
		u, err := url.Parse(row.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || net.ParseIP(u.Hostname()) == nil || net.ParseIP(pod.Status.PodIP) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) {
			return nil, install.ErrInstall
		}
		parent := metav1.GetControllerOf(pod)
		if parent == nil || parent.Kind != "ReplicaSet" {
			return nil, install.ErrInstall
		}
		rs, err := clients.API.AppsV1().ReplicaSets(row.Namespace).Get(x.physical, parent.Name, metav1.GetOptions{})
		if err != nil || rs.UID != parent.UID || rs.DeletionTimestamp != nil || !matchesBootstrapWriterObject(api, "ReplicaSet", rs) {
			return nil, install.ErrInstall
		}
		parent = metav1.GetControllerOf(rs)
		if parent == nil || parent.Kind != "Deployment" || parent.Name != row.Deployment {
			return nil, install.ErrInstall
		}
		dep, err := clients.API.AppsV1().Deployments(row.Namespace).Get(x.physical, parent.Name, metav1.GetOptions{})
		if err != nil || dep.UID != parent.UID || dep.DeletionTimestamp != nil || dep.Spec.Template.Spec.ServiceAccountName != pod.Spec.ServiceAccountName || !matchesBootstrapWriterObject(api, "Deployment", dep) {
			return nil, install.ErrInstall
		}
		sa, err := clients.API.CoreV1().ServiceAccounts(row.Namespace).Get(x.physical, pod.Spec.ServiceAccountName, metav1.GetOptions{})
		if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
			return nil, install.ErrInstall
		}
		approved := false
		for _, ref := range x.config.RuntimeSources.Deployments {
			approved = approved || ref.Namespace == row.Namespace && ref.Name == dep.Name && ref.UID == string(dep.UID)
		}
		if !approved || x.config.Security.NodeUIDs[pod.Spec.NodeName] == "" {
			return nil, install.ErrInstall
		}
		node, err := clients.API.CoreV1().Nodes().Get(x.physical, pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil || string(node.UID) != x.config.Security.NodeUIDs[pod.Spec.NodeName] || node.DeletionTimestamp != nil || node.Labels["kubernetes.io/os"] != "linux" || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		caps, err := capabilities.BackupCapabilities(x.physical, row.Endpoint, binding.Port)
		if err != nil || caps == nil || caps.Protocol != services.RuntimeBackupProtocol || caps.Scope != services.RuntimeBackupStopScope || caps.Namespace != row.Namespace || caps.PodUID != string(pod.UID) || caps.GatewayPort != binding.Port || caps.AgentEpoch == "" || caps.Slot == "" || !caps.Supported || !caps.DurableReservation || !caps.AgentRestartReconciliation || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		state, err := agent.GatewayState(x.physical, row.Endpoint, binding.Gateway)
		if err != nil || state == nil || state.State != "running" || state.InstanceID != instance.ID || state.UserID != instance.UserID || state.Generation != instance.Generation || state.GatewayID != binding.Gateway || state.PID != binding.PID || state.Port != binding.Port || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		seen[instance.ID] = true
		out = append(out, bootstrapSourceNativeWriter{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, RuntimePodID: row.ID, PID: binding.PID, Port: binding.Port, Namespace: row.Namespace, Pod: row.Name, PodUID: string(pod.UID), Deployment: row.Deployment, Gateway: binding.Gateway, Endpoint: row.Endpoint, AgentEpoch: caps.AgentEpoch, State: state.State, DeploymentUID: string(dep.UID), ReplicaSetUID: string(rs.UID), ServiceAccount: sa.Name, ServiceAccountUID: string(sa.UID), NodeUID: string(node.UID)})
	}
	for _, binding := range sqlFacts.bindings {
		if binding.State == "running" && !seen[binding.Instance] {
			return nil, install.ErrInstall
		}
	}
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
