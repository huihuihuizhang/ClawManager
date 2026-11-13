package systembackupexecution

import (
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"testing"
)

func teamAttachmentFixture() *corev1.Pod {
	off, on, uid := false, true, int64(65532)
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "sbk-team-1-read", Namespace: "site-user-1", UID: "pod-uid"}, Spec: corev1.PodSpec{
		NodeName: "node1", ServiceAccountName: "default", AutomountServiceAccountToken: &off, RestartPolicy: corev1.RestartPolicyNever,
		Volumes:    []corev1.Volume{{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "team-pvc", ReadOnly: true}}}},
		Containers: []corev1.Container{{Name: "attachment", Image: "registry/app@sha256:" + strings.Repeat("a", 64), Command: []string{"/bin/sh", "-ec"}, Args: []string{"exec sleep 2147483647"}, VolumeMounts: []corev1.VolumeMount{{Name: "source", MountPath: "/source", ReadOnly: true}}, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &off, ReadOnlyRootFilesystem: &on, RunAsUser: &uid, RunAsNonRoot: &on, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "attachment", Ready: true, ContainerID: "containerd://original", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
}
func TestTeamAttachmentRejectsUnsafeOrReplacedMount(t *testing.T) {
	original := teamAttachmentFixture()
	image := original.Spec.Containers[0].Image
	if !validTeamAttachmentPod(original, "team-pvc", image) {
		t.Fatal("valid read-only attachment refused")
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"writable-claim":  func(p *corev1.Pod) { p.Spec.Volumes[0].PersistentVolumeClaim.ReadOnly = false },
		"writable-mount":  func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].ReadOnly = false },
		"different-claim": func(p *corev1.Pod) { p.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "other" },
		"token":           func(p *corev1.Pod) { *p.Spec.AutomountServiceAccountToken = true },
		"host":            func(p *corev1.Pod) { p.Spec.HostPID = true },
		"exec":            func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"touch /source/file"} },
		"image":           func(p *corev1.Pod) { p.Spec.Containers[0].Image = "other" },
		"sidecar":         func(p *corev1.Pod) { p.Spec.Containers = append(p.Spec.Containers, p.Spec.Containers[0]) },
		"init":            func(p *corev1.Pod) { p.Spec.InitContainers = p.Spec.Containers },
		"fs-group": func(p *corev1.Pod) {
			g := int64(1000)
			p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &g}
		},
		"not-ready": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false },
		"deleting":  func(p *corev1.Pod) { now := metav1.Now(); p.DeletionTimestamp = &now },
	} {
		t.Run(name, func(t *testing.T) {
			p := original.DeepCopy()
			mutate(p)
			if validTeamAttachmentPod(p, "team-pvc", image) {
				t.Fatal("unsafe attachment accepted")
			}
		})
	}
}

func TestTeamAttachmentPinsRejectIdentityDrift(t *testing.T) {
	pod := teamAttachmentFixture()
	o, err := projectWriterAPIObject("Pod", pod)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DeploymentConfig{Namespace: "site-system", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"node1": "node-uid"}}}
	source := b.SourceInventory{TeamFacts: &team.SourceFacts{Teams: []team.TeamSQLFacts{{ID: 1, UserID: 1, Namespace: pod.Namespace, PVC: "team-pvc"}}}}
	pin := originalTeamAttachment{OriginalTeamAttachmentSelection: OriginalTeamAttachmentSelection{TeamID: 1, Namespace: pod.Namespace, Pod: pod.Name, Image: pod.Spec.Containers[0].Image}, NamespaceUID: "ns-uid", PodUID: string(pod.UID), PodSpecSHA256: o.SpecSHA256, Node: "node1", NodeUID: "node-uid", PVC: "team-pvc", PVCUID: "pvc-uid", PV: "pv", PVUID: "pv-uid", PVSpecSHA256: strings.Repeat("b", 64)}
	api := &observedWriterAPI{objects: []observedWriterAPIObject{o, {Kind: "Namespace", Name: pod.Namespace, UID: "ns-uid"}, {Kind: "PersistentVolumeClaim", Namespace: pod.Namespace, Name: "team-pvc", UID: "pvc-uid", Volume: "pv"}, {Kind: "PersistentVolume", Name: "pv", UID: "pv-uid", SpecSHA256: pin.PVSpecSHA256}}}
	admitted := map[string]bool{}
	if err := admitTeamAttachments(cfg, source, api, []originalTeamAttachment{pin}, admitted); err != nil || len(admitted) != 1 {
		t.Fatalf("valid pin: %v", err)
	}
	for name, mutate := range map[string]func(*originalTeamAttachment){
		"pod": func(p *originalTeamAttachment) { p.PodUID = "other" }, "namespace": func(p *originalTeamAttachment) { p.NamespaceUID = "other" }, "pvc": func(p *originalTeamAttachment) { p.PVCUID = "other" }, "pv": func(p *originalTeamAttachment) { p.PVUID = "other" }, "node": func(p *originalTeamAttachment) { p.NodeUID = "other" }, "spec": func(p *originalTeamAttachment) { p.PodSpecSHA256 = strings.Repeat("c", 64) }, "team": func(p *originalTeamAttachment) { p.TeamID = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pin
			mutate(&changed)
			if admitTeamAttachments(cfg, source, api, []originalTeamAttachment{changed}, map[string]bool{}) == nil {
				t.Fatal("identity drift admitted")
			}
		})
	}
	if admitTeamAttachments(cfg, source, api, []originalTeamAttachment{pin, pin}, map[string]bool{}) == nil {
		t.Fatal("duplicate admitted")
	}
}
