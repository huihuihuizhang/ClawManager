package systembackupexecution

import (
	"context"
	"reflect"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Operator-selected names are not authority; the native reader binds live identities.
type OriginalTeamAttachmentSelection struct {
	TeamID                int
	Namespace, Pod, Image string
}
type originalTeamAttachment struct {
	OriginalTeamAttachmentSelection
	NamespaceUID, PodUID, PodSpecSHA256, Node, NodeUID string
	PVC, PVCUID, PV, PVUID, PVSpecSHA256               string
}

// This installation-scoped read-only consumer is deliberately not a task writer.
// It must remain present until the installation is retired; deleting it invalidates
// the signed discovery instead of silently recreating or adopting another Pod.
func observeOriginalTeamAttachments(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, inventory b.SourceInventory, selected []OriginalTeamAttachmentSelection) ([]originalTeamAttachment, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	if len(selected) > 8 || inventory.TeamFacts == nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out := []originalTeamAttachment{}
	seen := map[int]bool{}
	for _, choice := range selected {
		if choice.TeamID <= 0 || seen[choice.TeamID] {
			return nil, ErrSourceWriterObservationIncomplete
		}
		seen[choice.TeamID] = true
		claim := ""
		nsUID := ""
		for _, t := range inventory.TeamFacts.Teams {
			if t.ID == choice.TeamID && t.Namespace == choice.Namespace {
				var err error
				nsUID, err = observeTeamSourceNamespace(ctx, api, cfg, t)
				if err != nil {
					return nil, err
				}
				claim = t.PVC
			}
		}
		if claim == "" || nsUID == "" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		// Require the existing tenant census; this does not expand namespace access.
		covered := false
		for _, i := range inventory.Instances {
			covered = covered || !deferredRuntimeTestInstance(cfg, i) && isRunningTenantPro(i) && i.Namespace == choice.Namespace
		}
		if !covered {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pod, err := api.CoreV1().Pods(choice.Namespace).Get(ctx, choice.Pod, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if !validTeamAttachmentPod(pod, claim, choice.Image) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pvc, err := api.CoreV1().PersistentVolumeClaims(choice.Namespace).Get(ctx, claim, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound || !reflect.DeepEqual(pvc.Spec.AccessModes, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pv, err := api.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != pvc.UID || pv.Spec.ClaimRef.Namespace != choice.Namespace || pv.Spec.ClaimRef.Name != claim {
			return nil, ErrSourceWriterObservationIncomplete
		}
		node, err := api.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if node.UID == "" || string(node.UID) != cfg.Security.NodeUIDs[node.Name] || node.DeletionTimestamp != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out = append(out, originalTeamAttachment{choice, nsUID, string(pod.UID), kube.ContentHash(pod.Spec), node.Name, string(node.UID), claim, string(pvc.UID), pv.Name, string(pv.UID), kube.ContentHash(pv.Spec)})
	}
	return out, nil
}

func validTeamAttachmentPod(p *corev1.Pod, claim, image string) bool {
	if p == nil || p.UID == "" || p.DeletionTimestamp != nil || len(p.OwnerReferences) != 0 || len(p.Finalizers) != 0 || !strings.Contains(image, "@sha256:") {
		return false
	}
	s := p.Spec
	if s.NodeName == "" || s.HostNetwork || s.HostPID || s.HostIPC || s.ShareProcessNamespace != nil && *s.ShareProcessNamespace || s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken || s.ServiceAccountName != "default" || len(s.InitContainers) != 0 || len(s.EphemeralContainers) != 0 || len(s.Containers) != 1 || len(s.Volumes) != 1 || s.RestartPolicy != corev1.RestartPolicyNever {
		return false
	}
	v := s.Volumes[0]
	expected := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim, ReadOnly: true}}}
	if !reflect.DeepEqual(v, expected) {
		return false
	}
	c := s.Containers[0]
	if c.Name != "attachment" || c.Image != image || !reflect.DeepEqual(c.Command, []string{"/bin/sh", "-ec"}) || !reflect.DeepEqual(c.Args, []string{"exec sleep 2147483647"}) || len(c.Env) != 0 || len(c.EnvFrom) != 0 || c.Lifecycle != nil || c.LivenessProbe != nil || c.ReadinessProbe != nil || c.StartupProbe != nil || len(c.VolumeDevices) != 0 || len(c.Ports) != 0 {
		return false
	}
	if !reflect.DeepEqual(c.VolumeMounts, []corev1.VolumeMount{{Name: "source", MountPath: "/source", ReadOnly: true}}) {
		return false
	}
	sc := c.SecurityContext
	if sc == nil || sc.Privileged != nil && *sc.Privileged || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || sc.RunAsUser == nil || *sc.RunAsUser != 65532 || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || sc.Capabilities == nil || len(sc.Capabilities.Add) != 0 || !reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		return false
	}
	if s.SecurityContext != nil && (s.SecurityContext.FSGroup != nil || len(s.SecurityContext.Sysctls) != 0) {
		return false
	}
	o, err := projectWriterAPIObject("Pod", p)
	return err == nil && o.Running && len(p.Status.ContainerStatuses) == 1
}

func admitTeamAttachments(cfg DeploymentConfig, source b.SourceInventory, api *observedWriterAPI, pins []originalTeamAttachment, rawPods map[string]bool) error {
	if len(pins) == 0 {
		return nil
	}
	if len(pins) > 8 || source.TeamFacts == nil {
		return ErrSourceWriterObservationIncomplete
	}
	objects := map[string]observedWriterAPIObject{}
	for _, o := range api.objects {
		objects[o.Kind+"/"+o.Namespace+"/"+o.Name] = o
	}
	seen := map[int]bool{}
	for _, p := range pins {
		if seen[p.TeamID] || p.TeamID <= 0 {
			return ErrSourceWriterObservationIncomplete
		}
		seen[p.TeamID] = true
		matched := false
		for _, t := range source.TeamFacts.Teams {
			matched = matched || t.ID == p.TeamID && t.Namespace == p.Namespace && t.PVC == p.PVC && validTenantProNamespace(cfg.Namespace, b.InstanceIdentity{UserID: t.UserID, Namespace: t.Namespace})
		}
		key := "Pod/" + p.Namespace + "/" + p.Pod
		o := objects[key]
		claim := objects["PersistentVolumeClaim/"+p.Namespace+"/"+p.PVC]
		pv := objects["PersistentVolume//"+p.PV]
		if !matched || p.PVCUID == "" || p.PVUID == "" || p.PV == "" || !formalCandidateDigest(p.PVSpecSHA256) || !formalCandidateDigest(p.PodSpecSHA256) || p.NamespaceUID == "" || objects["Namespace//"+p.Namespace].UID != p.NamespaceUID || p.PodUID == "" || o.UID != p.PodUID || o.SpecSHA256 != p.PodSpecSHA256 || o.Node != p.Node || p.NodeUID == "" || cfg.Security.NodeUIDs[p.Node] != p.NodeUID || claim.UID != p.PVCUID || claim.Volume != p.PV || pv.UID != p.PVUID || pv.SpecSHA256 != p.PVSpecSHA256 || !validTeamAttachmentPod(o.pod, p.PVC, p.Image) {
			return ErrSourceWriterObservationIncomplete
		}
		if _, exists := rawPods[key]; exists {
			return ErrSourceWriterObservationIncomplete
		}
		// Requiring a team identity prevents arbitrary read-only Pods from becoming exceptions.
		if !strings.HasPrefix(p.Pod, "sbk-team-"+strconv.Itoa(p.TeamID)+"-") {
			return ErrSourceWriterObservationIncomplete
		}
		rawPods[key] = false
	}
	return nil
}
