package k8s

import (
	"context"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
)

// NativeRuntimeConfig is an explicit new pool, never an in-place migration of
// a legacy runtime. The caller supplies reviewed node profiles and original
// resource UIDs. No credentials, grants or recovery receipts are synthesized.
// One pool/one slot is intentional: their independent ledgers must be exclusive
// across Pod replacement, not shared by replicas or backed by emptyDir.
type NativeRuntimeConfig struct {
	InstallationID                  string
	NodeName, NodeUID               string
	Ledger                          NativeRuntimePVC
	Workspace                       NativeRuntimePVC
	TokenSecret, TokenSecretUID     string
	TLSSecret, TLSSecretUID         string
	AppArmorProfile, SeccompProfile string
}

type NativeRuntimePVC struct {
	Name, UID, VolumeName, VolumeUID string
}

const nativeLayout = "pool-slot-v1"

var nativeImage = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)

func validNativeName(s string) bool { return len(validation.IsDNS1123Subdomain(s)) == 0 }

func (n NativeRuntimeConfig) validate(spec RuntimeDeploymentSpec) error {
	if !validNativeName(spec.Name) || !validNativeName(spec.Namespace) || !validNativeName(n.NodeName) || n.NodeUID == "" || n.InstallationID == "" || len(n.InstallationID) > 128 || !nativeImage.MatchString(spec.Image) || spec.Replicas != 1 || (spec.RuntimeType != "openclaw" && spec.RuntimeType != "hermes") {
		return fmt.Errorf("native runtime requires immutable image, one replica and pinned identity")
	}
	if spec.AgentControlToken != "" || spec.AgentReportToken != "" || spec.WorkspaceNFSServer != "" || spec.WorkspaceNFSPath != "" || spec.WorkspacePVCClaimName != n.Workspace.Name || runtimeWorkspaceMountPath(spec.WorkspaceMountPath) != defaultWorkspaceMount || spec.HermesDesktopWeb {
		return fmt.Errorf("native runtime requires explicit PVC and Secret references")
	}
	if spec.GatewayPortStart <= 0 || spec.GatewayPortEnd > 65535 || spec.GatewayPortEnd-spec.GatewayPortStart != 2 {
		return fmt.Errorf("native single slot requires exactly one three-port block")
	}
	for _, p := range []NativeRuntimePVC{n.Ledger, n.Workspace} {
		if !validNativeName(p.Name) || p.UID == "" || !validNativeName(p.VolumeName) || p.VolumeUID == "" {
			return fmt.Errorf("native PVC identity is incomplete")
		}
	}
	if n.Ledger.Name == n.Workspace.Name || n.Ledger.VolumeName == n.Workspace.VolumeName || n.Ledger.VolumeUID == n.Workspace.VolumeUID {
		return fmt.Errorf("runtime ledger must be separate from workspace")
	}
	if !validNativeName(n.TokenSecret) || !validNativeName(n.TLSSecret) || n.TokenSecretUID == "" || n.TLSSecretUID == "" || n.TokenSecret == n.TLSSecret {
		return fmt.Errorf("native token/TLS references are incomplete")
	}
	if n.AppArmorProfile == "" || strings.ContainsAny(n.AppArmorProfile, "/ \t\r\n") || n.SeccompProfile == "" || path.IsAbs(n.SeccompProfile) || path.Clean(n.SeccompProfile) != n.SeccompProfile || n.SeccompProfile == ".." || strings.HasPrefix(n.SeccompProfile, "../") {
		return fmt.Errorf("native runtime requires reviewed localhost node profiles")
	}
	return nil
}

// BuildNativeRuntimeDeployment creates a scheduling-disabled candidate. TCP
// readiness only observes the TLS listener; Agent capability/pinned TLS and
// physical stop/resume evidence remain required by SQLRuntimeControl. Native
// templates cannot be scaled/rolled by any legacy deployment method.
func BuildNativeRuntimeDeployment(spec RuntimeDeploymentSpec, n NativeRuntimeConfig) (*appsv1.Deployment, error) {
	if err := n.validate(spec); err != nil {
		return nil, err
	}
	d := BuildRuntimeDeployment(spec)
	d.Labels[runtimeSchedulingLabel] = "false"
	d.Labels["clawmanager.io/runtime-layout"] = nativeLayout
	d.Spec.Template.Labels[runtimeSchedulingLabel] = "false"
	d.Spec.Template.Labels["clawmanager.io/runtime-layout"] = nativeLayout
	d.Spec.Template.Annotations = map[string]string{"clawmanager.io/installation-id": n.InstallationID, "clawmanager.io/ledger-uid": n.Ledger.UID, "clawmanager.io/workspace-uid": n.Workspace.UID}
	d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	f := false
	d.Spec.Template.Spec.AutomountServiceAccountToken = &f
	d.Spec.Template.Spec.EnableServiceLinks = &f
	d.Spec.Template.Spec.NodeSelector = map[string]string{corev1.LabelHostname: n.NodeName, corev1.LabelOSStable: "linux"}
	d.Spec.Template.Spec.Volumes = []corev1.Volume{
		{Name: "workspaces", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n.Workspace.Name}}},
		{Name: "ledger", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n.Ledger.Name}}},
		{Name: "sockets", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: n.TLSSecret, DefaultMode: ptrInt32(0400), Items: []corev1.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}}}},
	}
	base := d.Spec.Template.Spec.Containers[0]
	// Replace the legacy plain token variables with immutable Secret refs.
	for _, name := range []string{"CLAWMANAGER_AGENT_CONTROL_TOKEN", "CLAWMANAGER_AGENT_REPORT_TOKEN", "RUNTIME_AGENT_CONTROL_TOKEN", "RUNTIME_AGENT_REPORT_TOKEN"} {
		removeEnvVar(&base, name)
	}
	base.Command = []string{"/usr/local/bin/clawmanager-agent"}
	base.Env = append(base.Env, fieldRefEnv("POD_UID", "metadata.uid"), corev1.EnvVar{Name: "RUNTIME_AGENT_DATA_DIR", Value: "/var/lib/clawmanager-agent"}, corev1.EnvVar{Name: "RUNTIME_GATEWAY_PORT_BLOCK_SIZE", Value: "3"}, corev1.EnvVar{Name: "RUNTIME_GATEWAY_CAPACITY", Value: "1"}, nativeSecretEnv("RUNTIME_AGENT_CONTROL_TOKEN", n.TokenSecret, "control"))
	base.VolumeMounts = []corev1.VolumeMount{{Name: "workspaces", MountPath: "/workspaces"}, {Name: "sockets", MountPath: "/run/clawmanager-slots"}}
	base.SecurityContext = &corev1.SecurityContext{Privileged: &f, AllowPrivilegeEscalation: &f, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: &n.AppArmorProfile}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: &n.SeccompProfile}}
	pool := *base.DeepCopy()
	pool.Name = "pool"
	pool.Env = append(pool.Env, corev1.EnvVar{Name: "RUNTIME_AGENT_ROLE", Value: "pool"}, corev1.EnvVar{Name: "RUNTIME_SLOT_COUNT", Value: "1"}, corev1.EnvVar{Name: "RUNTIME_AGENT_TLS_CERT_FILE", Value: "/tls/tls.crt"}, corev1.EnvVar{Name: "RUNTIME_AGENT_TLS_KEY_FILE", Value: "/tls/tls.key"}, nativeSecretEnv("RUNTIME_AGENT_REPORT_TOKEN", n.TokenSecret, "report"))
	pool.VolumeMounts = append(pool.VolumeMounts, corev1.VolumeMount{Name: "ledger", MountPath: "/var/lib/clawmanager-agent", SubPath: "pool"}, corev1.VolumeMount{Name: "tls", MountPath: "/tls", ReadOnly: true})
	pool.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(runtimeAgentPort)}}, PeriodSeconds: 5, TimeoutSeconds: 1, FailureThreshold: 3}
	slot := *base.DeepCopy()
	slot.Name = "slot"
	slot.Ports = nil
	// A slot serves a Unix socket only. Never inherit the legacy HTTP probe
	// or pool TCP probe; positive protocol/capability admission is separate.
	slot.ReadinessProbe, slot.LivenessProbe, slot.StartupProbe = nil, nil, nil
	slot.Env = append(slot.Env, corev1.EnvVar{Name: "RUNTIME_AGENT_ROLE", Value: "slot"}, corev1.EnvVar{Name: "RUNTIME_SLOT_INDEX", Value: strconv.Itoa(0)}, corev1.EnvVar{Name: "RUNTIME_SLOT_SOCKET", Value: "/run/clawmanager-slots/slot-0.sock"})
	slot.VolumeMounts = append(slot.VolumeMounts, corev1.VolumeMount{Name: "ledger", MountPath: "/var/lib/clawmanager-agent", SubPath: "slot-0"})
	d.Spec.Template.Spec.Containers = []corev1.Container{pool, slot}
	nativeTemplateDefaults(&d.Spec.Template)
	return d, nil
}

// Apply only API defaults, to defensive copies, before strict equality. Do not
// remove unknown fields/admission changes: they are drift and must be reviewed.
func nativeTemplateDefaults(t *corev1.PodTemplateSpec) {
	p := &t.Spec
	if p.RestartPolicy == "" {
		p.RestartPolicy = corev1.RestartPolicyAlways
	}
	if p.DNSPolicy == "" {
		p.DNSPolicy = corev1.DNSClusterFirst
	}
	if p.SchedulerName == "" {
		p.SchedulerName = corev1.DefaultSchedulerName
	}
	if p.TerminationGracePeriodSeconds == nil {
		seconds := int64(30)
		p.TerminationGracePeriodSeconds = &seconds
	}
	if p.SecurityContext == nil {
		p.SecurityContext = &corev1.PodSecurityContext{}
	}
	for j := range p.Containers {
		c := &p.Containers[j]
		if c.ImagePullPolicy == "" {
			c.ImagePullPolicy = corev1.PullIfNotPresent
		}
		if c.TerminationMessagePath == "" {
			c.TerminationMessagePath = corev1.TerminationMessagePathDefault
		}
		if c.TerminationMessagePolicy == "" {
			c.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		}
		for k := range c.Ports {
			if c.Ports[k].Protocol == "" {
				c.Ports[k].Protocol = corev1.ProtocolTCP
			}
		}
		for k := range c.Env {
			if from := c.Env[k].ValueFrom; from != nil && from.FieldRef != nil && from.FieldRef.APIVersion == "" {
				from.FieldRef.APIVersion = "v1"
			}
		}
		for _, probe := range []*corev1.Probe{c.ReadinessProbe, c.LivenessProbe, c.StartupProbe} {
			if probe == nil {
				continue
			}
			if probe.TimeoutSeconds == 0 {
				probe.TimeoutSeconds = 1
			}
			if probe.PeriodSeconds == 0 {
				probe.PeriodSeconds = 10
			}
			if probe.SuccessThreshold == 0 {
				probe.SuccessThreshold = 1
			}
			if probe.FailureThreshold == 0 {
				probe.FailureThreshold = 3
			}
		}
	}
}

func ptrInt32(v int32) *int32 { return &v }
func nativeSecretEnv(name, secret, key string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: key}}}
}

// ensureNativeRuntime only creates a new candidate or confirms the exact
// original template. Configuration drift requires an explicit migration; it
// never restarts a writer or reuses a missing resource under the same name.
func (s *runtimeDeploymentService) ensureNativeRuntime(ctx context.Context, spec RuntimeDeploymentSpec, n NativeRuntimeConfig) error {
	desired, err := BuildNativeRuntimeDeployment(spec, n)
	if err != nil {
		return err
	}
	if err = s.checkNativeResources(ctx, spec, n); err != nil {
		return err
	}
	deps := s.client.AppsV1().Deployments(spec.Namespace)
	existing, err := deps.Get(ctx, spec.Name, metav1.GetOptions{})
	if err == nil {
		actualTemplate := existing.Spec.Template.DeepCopy()
		nativeTemplateDefaults(actualTemplate)
		if existing.DeletionTimestamp != nil || !reflect.DeepEqual(*actualTemplate, desired.Spec.Template) || existing.Spec.Replicas == nil || *existing.Spec.Replicas != 1 || !reflect.DeepEqual(existing.Spec.Selector, desired.Spec.Selector) || existing.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || existing.Labels[runtimeSchedulingLabel] != "false" {
			return fmt.Errorf("native runtime candidate differs from original immutable plan")
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	_, err = deps.Create(ctx, desired, metav1.CreateOptions{})
	return err // lost create response is reconciled by GET, never DELETE/recreate
}

func (s *runtimeDeploymentService) checkNativeResources(ctx context.Context, spec RuntimeDeploymentSpec, n NativeRuntimeConfig) error {
	node, err := s.client.CoreV1().Nodes().Get(ctx, n.NodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(node.UID) != n.NodeUID || node.DeletionTimestamp != nil || node.Labels[corev1.LabelHostname] != n.NodeName || node.Labels[corev1.LabelOSStable] != "linux" {
		return fmt.Errorf("native node identity changed")
	}
	var backing []corev1.PersistentVolumeSpec
	for i, p := range []NativeRuntimePVC{n.Ledger, n.Workspace} {
		claim, err := s.client.CoreV1().PersistentVolumeClaims(spec.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if string(claim.UID) != p.UID || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName != p.VolumeName || (claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem) {
			return fmt.Errorf("native PVC identity changed")
		}
		if i == 0 && (len(claim.Spec.AccessModes) != 1 || claim.Spec.AccessModes[0] != corev1.ReadWriteOncePod) {
			return fmt.Errorf("native ledger requires ReadWriteOncePod exclusivity")
		}
		pv, err := s.client.CoreV1().PersistentVolumes().Get(ctx, p.VolumeName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if string(pv.UID) != p.VolumeUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != p.UID || pv.Spec.ClaimRef.Namespace != spec.Namespace || pv.Spec.ClaimRef.Name != p.Name || pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain || (pv.Spec.CSI == nil && pv.Spec.NFS == nil) {
			return fmt.Errorf("native durable volume binding is not retained")
		}
		if i == 0 && pv.Spec.CSI == nil {
			return fmt.Errorf("native ledger requires CSI ReadWriteOncePod fencing")
		}
		backing = append(backing, pv.Spec)
	}
	if backing[0].CSI != nil && backing[1].CSI != nil && backing[0].CSI.Driver == backing[1].CSI.Driver && backing[0].CSI.VolumeHandle == backing[1].CSI.VolumeHandle {
		return fmt.Errorf("runtime ledger aliases workspace backing")
	}
	for _, ref := range []struct {
		name, uid string
		keys      []string
	}{{n.TokenSecret, n.TokenSecretUID, []string{"control", "report"}}, {n.TLSSecret, n.TLSSecretUID, []string{"tls.crt", "tls.key"}}} {
		secret, err := s.client.CoreV1().Secrets(spec.Namespace).Get(ctx, ref.name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if string(secret.UID) != ref.uid || secret.DeletionTimestamp != nil || secret.Immutable == nil || !*secret.Immutable {
			return fmt.Errorf("native credential Secret identity changed")
		}
		for _, key := range ref.keys {
			if len(secret.Data[key]) == 0 {
				return fmt.Errorf("native credential Secret is incomplete")
			}
		}
	}
	return nil
}
