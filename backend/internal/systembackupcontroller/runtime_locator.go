package systembackupcontroller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"

	"clawreef/internal/services"
	b "clawreef/internal/systembackup/publicadapter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type runtimeBindingQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type gatewayBindingRow struct {
	ID, Port, Generation, PID                                            int
	UID, Pod, Namespace, Endpoint, Workspace, State, Gateway, Deployment string
}

func readGatewayBinding(ctx context.Context, db runtimeBindingQuery, id int, lock bool) (gatewayBindingRow, error) {
	var r gatewayBindingRow
	q := `SELECT p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,p.deployment_name,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE b.instance_id=? AND p.state='ready' AND p.draining=FALSE`
	if lock {
		q += " FOR UPDATE"
	}
	e := db.QueryRowContext(ctx, q, id).Scan(&r.ID, &r.UID, &r.Pod, &r.Namespace, &r.Endpoint, &r.Port, &r.Workspace, &r.Generation, &r.State, &r.Gateway, &r.Deployment, &r.PID)
	return r, e
}

func bindingMatchesSource(r gatewayBindingRow, source b.InstanceIdentity, namespace string) bool {
	return namespace != "" && r.Namespace == namespace && r.ID > 0 && r.Pod != "" && r.Deployment != "" && r.PID > 0 && r.Port > 0 && r.Port <= 65535 &&
		(source.Namespace == "" || source.Namespace == r.Namespace) && (source.Pod == "" || source.Pod == r.Pod) && r.Workspace == source.Workspace && source.Workspace != "" &&
		r.Generation == source.Generation && r.State == "running" && r.Gateway == fmt.Sprintf("gw-%d-%d", source.ID, source.Generation)
}

func gatewayEndpointMatchesPod(endpoint string, pod *corev1.Pod) bool {
	if pod == nil || pod.UID == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || pod.Spec.HostNetwork {
		return false
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.Equal(net.ParseIP(pod.Status.PodIP)) {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func validGatewayCapabilities(caps *services.RuntimeBackupCapabilities, uid, namespace string, port int) bool {
	if caps == nil {
		return false
	}
	epoch, e := hex.DecodeString(caps.AgentEpoch)
	return e == nil && len(epoch) == 16 && hex.EncodeToString(epoch) == caps.AgentEpoch && caps.Protocol == services.RuntimeBackupProtocol && caps.PodUID == uid && caps.Namespace == namespace && caps.GatewayPort == port && caps.Slot != "" && caps.Supported && caps.DurableReservation && caps.Scope == services.RuntimeBackupStopScope
}

// ResolveGatewaySource is read-only discovery, not an execution grant. The
// exact row and raw Source are rechecked under the original authority when
// custody is saved, and again by every control callback. It never backfills SQL.
func (o *SQLRuntimeControl) ResolveGatewaySource(ctx context.Context, source b.InstanceIdentity) (b.RuntimeWriterSpec, error) {
	if o != nil && o.cfg.Shared != nil {
		return o.resolveSharedSource(ctx, source)
	}
	var zero b.RuntimeWriterSpec
	if o == nil || o.cfg.Gate.Authority.DB == nil || source.Status != "running" || source.Mode != "lite" || source.ID <= 0 || source.UserID <= 0 || source.Generation <= 0 {
		return zero, ErrExecutionRecord
	}
	r, e := readGatewayBinding(ctx, o.cfg.Gate.Authority.DB, source.ID, false)
	if e != nil || !bindingMatchesSource(r, source, o.cfg.Namespace) {
		return zero, ErrExecutionRecord
	}
	spec := b.RuntimeWriterSpec{Source: source, Kind: "gateway", Name: r.Pod, Endpoint: r.Endpoint, Port: r.Port,
		Runtime: b.RuntimeLocator{Version: "runtime-locator.v2", Namespace: r.Namespace, Pod: r.Pod, RegisteredPodUID: r.UID, RuntimePodID: r.ID, Deployment: r.Deployment, GatewayPID: r.PID}}
	pod, e := o.cfg.Client.CoreV1().Pods(r.Namespace).Get(ctx, r.Pod, metav1.GetOptions{})
	if e != nil || !gatewayEndpointMatchesPod(r.Endpoint, pod) || (r.UID != "" && r.UID != string(pod.UID)) {
		return zero, ErrExecutionRecord
	}
	spec.UID = string(pod.UID)
	caps, e := o.gatewayCapabilities(ctx, spec)
	if e != nil {
		return zero, e
	}
	spec.Runtime.AgentEpoch = caps.AgentEpoch
	return spec, nil
}

func (o *SQLRuntimeControl) gatewayCapabilities(ctx context.Context, spec b.RuntimeWriterSpec) (*services.RuntimeBackupCapabilities, error) {
	if spec.RuntimeNamespace() != o.cfg.Namespace {
		return nil, ErrExecutionRecord
	}
	probe := o.cfg.DeploymentChecks[spec.RuntimeNamespace()+"/"+spec.Runtime.Deployment]
	if absentExecutionDependency(probe) || probe.Check(ctx) != nil {
		return nil, ErrExecutionRecord
	}
	pod, e := o.cfg.Client.CoreV1().Pods(spec.RuntimeNamespace()).Get(ctx, spec.RuntimePod(), metav1.GetOptions{})
	if e != nil || !gatewayEndpointMatchesPod(spec.Endpoint, pod) || string(pod.UID) != spec.UID {
		return nil, ErrExecutionRecord
	}
	dep, e := o.deploymentForPod(ctx, pod)
	if e != nil || dep.Name != spec.Runtime.Deployment {
		return nil, ErrExecutionRecord
	}
	agent, ok := o.cfg.Agent.(services.RuntimeAgentBackupClient)
	if !ok {
		return nil, ErrExecutionRecord
	}
	caps, e := agent.BackupCapabilities(ctx, spec.Endpoint, spec.Port)
	if e != nil || !validGatewayCapabilities(caps, spec.UID, spec.RuntimeNamespace(), spec.Port) || (spec.Runtime.AgentEpoch != "" && caps.AgentEpoch != spec.Runtime.AgentEpoch) {
		return nil, ErrExecutionRecord
	}
	return caps, nil
}

func (o *SQLRuntimeControl) checkGatewayPod(ctx context.Context, spec b.RuntimeWriterSpec) error {
	if spec.Runtime.Version != "" {
		if spec.Runtime.Version != "runtime-locator.v2" {
			return ErrExecutionRecord
		}
		_, e := o.gatewayCapabilities(ctx, spec)
		return e
	}
	// Existing custody retains its original non-null source location.
	if spec.Source.Namespace != o.cfg.Namespace {
		return ErrExecutionRecord
	}
	pod, e := o.cfg.Client.CoreV1().Pods(spec.Source.Namespace).Get(ctx, spec.Source.Pod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != spec.UID || pod.DeletionTimestamp != nil {
		return ErrExecutionRecord
	}
	return nil
}
