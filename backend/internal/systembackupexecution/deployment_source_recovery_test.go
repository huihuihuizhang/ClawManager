package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func sourceRecoveredPodFixture() (*productionSourceBinding, *corev1.Pod, productionCaptureMetadata) {
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "original-ns", Name: "workspace", UID: "original-claim", ResourceVersion: "11"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-pv"}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "original-pv", UID: "original-pv-uid", ResourceVersion: "12"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "original-node", UID: "original-node-uid"}}
	client := fake.NewSimpleClientset(claim, pv, node)
	owner := &PublicJobOwner{Client: client, Namespace: claim.Namespace, Security: kube.WorkerSecurity{NodeUIDs: map[string]string{node.Name: string(node.UID)}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: claim.Namespace, Name: "recovered", UID: "recovered-pod", ResourceVersion: "19"}, Spec: corev1.PodSpec{NodeName: node.Name, Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name}}}}, Containers: []corev1.Container{{Name: "runtime", VolumeMounts: []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspaces"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "runtime", Ready: true, ContainerID: "containerd://original-new-container", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	metadata := productionCaptureMetadata{MountIdentities: map[string]kube.MountIdentity{"instance_7_workspace": {Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}}}
	return &productionSourceBinding{owner: owner}, pod, metadata
}

func TestSourceRecoveredDeploymentReceiptCannotBeJoinedToReplacementPod(t *testing.T) {
	runtime := &c.SourceRecoveryRuntime{Spec: b.RuntimeWriterSpec{Kind: "deployment", Source: b.InstanceIdentity{Namespace: "original-ns"}}, Resumed: json.RawMessage(`{"PodName":"restored","PodUID":"restored-uid"}`)}
	for _, change := range []string{"original", "name", "uid", "namespace", "two-pods"} {
		t.Run(change, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "original-ns", Name: "restored", UID: "restored-uid"}}
			pods := []*corev1.Pod{pod}
			if change == "name" {
				pod.Name = "new-ready"
			}
			if change == "uid" {
				pod.UID = "new-ready-uid"
			}
			if change == "namespace" {
				pod.Namespace = "other"
			}
			if change == "two-pods" {
				pods = append(pods, pod.DeepCopy())
			}
			if sourceRecoveredDeploymentReceiptMatches(runtime, pods, "original-ns") != (change == "original") {
				t.Fatal("mixed old receipt and current Pod accepted")
			}
		})
	}
}

func sourceRecoveryDeploymentFixture(t *testing.T) (*productionSourceBinding, *corev1.Pod, *appsv1.Deployment, *appsv1.ReplicaSet, b.FrozenWriter, sourceRecoveryCheckpoint) {
	t.Helper()
	x, pod, _ := sourceRecoveredPodFixture()
	x.service = &DeploymentService{}
	one, controller := int32(1), true
	template := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "platform"}}, Spec: *pod.Spec.DeepCopy()}
	template.Spec.NodeName = ""
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "platform", UID: "platform-uid", Generation: 4, Annotations: map[string]string{"backup.clawmanager.io/source-resume-fence": "original/attempt/1"}}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "platform"}}, Template: template}, Status: appsv1.DeploymentStatus{ObservedGeneration: 4, ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "platform-rs", UID: "platform-rs-uid", Labels: map[string]string{"app": "platform"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Replicas: &one, Template: *dep.Spec.Template.DeepCopy()}}
	rs.Spec.Template.Labels["pod-template-hash"] = "reviewed-revision"
	pod.Labels = map[string]string{"app": "platform"}
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}
	spec := dep.Spec.DeepCopy()
	spec.Replicas = nil
	cp := sourceRecoveryCheckpoint{Version: "deployment-quiesce.v1", Namespace: dep.Namespace, Name: dep.Name, FenceID: "original/attempt/1", SpecSHA256: kube.ContentHash(spec), Replicas: 1}
	raw, _ := json.Marshal(cp)
	writer := b.FrozenWriter{ID: "deployment/" + dep.Namespace + "/" + dep.Name, Original: flow.State{UID: string(dep.UID), Generation: 1, Running: true, Checkpoint: string(raw)}}
	x.service.Config.Writers = []PlatformDeployment{{Namespace: dep.Namespace, Name: dep.Name, UID: string(dep.UID)}}
	for _, create := range []func() error{
		func() error {
			_, err := x.owner.Client.AppsV1().Deployments(dep.Namespace).Create(context.Background(), dep, metav1.CreateOptions{})
			return err
		},
		func() error {
			_, err := x.owner.Client.AppsV1().ReplicaSets(rs.Namespace).Create(context.Background(), rs, metav1.CreateOptions{})
			return err
		},
		func() error {
			_, err := x.owner.Client.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
			return err
		},
	} {
		if err := create(); err != nil {
			t.Fatal(err)
		}
	}
	return x, pod, dep, rs, writer, cp
}

func TestSourceRecoveredDeploymentRejectsOldRevisionAndChangedPodSpec(t *testing.T) {
	for _, change := range []string{"original", "old-rs-revision", "changed-pod-image", "changed-pod-env", "changed-rs-annotation"} {
		t.Run(change, func(t *testing.T) {
			x, pod, _, rs, writer, cp := sourceRecoveryDeploymentFixture(t)
			if change == "old-rs-revision" {
				rs.Spec.Template.Spec.Containers[0].Image = "unapproved-old-image"
			}
			if change == "changed-rs-annotation" {
				rs.Spec.Template.Annotations = map[string]string{"different": "policy"}
			}
			if change == "old-rs-revision" || change == "changed-rs-annotation" {
				if _, err := x.owner.Client.AppsV1().ReplicaSets(rs.Namespace).Update(context.Background(), rs, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			if change == "changed-pod-image" {
				pod.Spec.Containers[0].Image = "unapproved-image"
			}
			if change == "changed-pod-env" {
				pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "INJECTED", Value: "unexpected"}}
			}
			if change == "changed-pod-image" || change == "changed-pod-env" {
				if _, err := x.owner.Client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := x.recoveredDeploymentPods(context.Background(), writer, cp)
			if (err == nil) != (change == "original") {
				t.Fatal("original template/spec binding result", err)
			}
		})
	}
}

func TestPlatformVolumeIsFrozenBeforeCaptureWithoutInstanceOrTeam(t *testing.T) {
	x, pod, _, _, writer, _ := sourceRecoveryDeploymentFixture(t)
	pins, err := x.service.freezePlatformSourceRecoveryMounts(context.Background(), x.owner, []b.FrozenWriter{writer})
	if err != nil || len(pins) != 1 || pins[0].Claim == nil || pins[0].Claim.UID != "original-claim" {
		t.Fatal("original platform PVC/PV not frozen", err)
	}
	metadata := productionCaptureMetadata{PlatformMounts: pins}
	if _, err := x.observeRecoveredPod(context.Background(), pod, metadata, writer); err != nil {
		t.Fatal("platform-only original pin was not consumed", err)
	}
	if _, err := x.observeRecoveredPod(context.Background(), pod, productionCaptureMetadata{}, writer); err == nil {
		t.Fatal("missing original pin adopted current PVC/PV")
	}
	pins[0].Claim.UID = "other-claim"
	if _, err := x.observeRecoveredPod(context.Background(), pod, metadata, writer); err == nil {
		t.Fatal("replaced original claim accepted")
	}
}

func TestPlatformMountRecheckAfterPauseUsesFrozenTemplateAndStorage(t *testing.T) {
	x, pod, dep, _, writer, cp := sourceRecoveryDeploymentFixture(t)
	cp.Pods = []quiesce.PodIdentity{{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{pod.Status.ContainerStatuses[0].ContainerID}}}
	raw, _ := json.Marshal(cp)
	writer.Original.Checkpoint = string(raw)
	ctx := context.Background()
	original, err := x.service.freezePlatformSourceRecoveryMounts(ctx, x.owner, []b.FrozenWriter{writer})
	if err != nil {
		t.Fatal("pre-stop original Pod validation", err)
	}
	if err := x.owner.Client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.service.freezePlatformSourceRecoveryMounts(ctx, x.owner, []b.FrozenWriter{writer}); err == nil {
		t.Fatal("initial freeze accepted a missing original Pod")
	}
	current, err := x.service.currentPlatformSourceRecoveryMounts(ctx, x.owner, []b.FrozenWriter{writer})
	if err != nil || !reflect.DeepEqual(original, current) {
		t.Fatal("normal pause changed original template/storage pins", err)
	}
	dep.Spec.Template.Spec.Containers[0].Image = "replacement-image"
	if _, err := x.owner.Client.AppsV1().Deployments(dep.Namespace).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.service.currentPlatformSourceRecoveryMounts(ctx, x.owner, []b.FrozenWriter{writer}); err == nil {
		t.Fatal("post-stop recheck accepted a changed original template")
	}
}

func TestSourceRecoveredPodObservesActualAPIContainerAndVolumeIdentity(t *testing.T) {
	x, pod, metadata := sourceRecoveredPodFixture()
	ob, err := x.observeRecoveredPod(context.Background(), pod, metadata)
	if err != nil || ob.UID != string(pod.UID) || ob.NodeUID != "original-node-uid" || len(ob.Containers) != 1 || len(ob.Volumes) != 1 || ob.Volumes[0].ClaimUID != "original-claim" || ob.Volumes[0].PVUID != "original-pv-uid" {
		t.Fatal("actual API binding not retained", err)
	}
}

func TestSourceRecoveredPodReadyAloneDoesNotSatisfyBindings(t *testing.T) {
	for _, name := range []string{"container", "wrong-status-container", "node-replaced", "claim-replaced", "pv-spec-changed", "missing-original-pin", "ephemeral", "unknown-nfs"} {
		t.Run(name, func(t *testing.T) {
			x, pod, metadata := sourceRecoveredPodFixture()
			switch name {
			case "container":
				pod.Status.ContainerStatuses[0].ContainerID = ""
			case "wrong-status-container":
				pod.Status.ContainerStatuses[0].Name = "unrelated"
			case "node-replaced":
				x.owner.Security.NodeUIDs[pod.Spec.NodeName] = "different-node-uid"
			case "claim-replaced":
				claim, _ := x.owner.Client.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(context.Background(), "workspace", metav1.GetOptions{})
				claim.UID = types.UID("new-claim-uid")
				if _, err := x.owner.Client.CoreV1().PersistentVolumeClaims(pod.Namespace).Update(context.Background(), claim, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "pv-spec-changed":
				pv, _ := x.owner.Client.CoreV1().PersistentVolumes().Get(context.Background(), "original-pv", metav1.GetOptions{})
				pv.Spec.StorageClassName = "different-policy"
				if _, err := x.owner.Client.CoreV1().PersistentVolumes().Update(context.Background(), pv, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			case "missing-original-pin":
				metadata.MountIdentities = nil
			case "ephemeral":
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "extra-writer"}}}
			case "unknown-nfs":
				pod.Spec.Volumes[0].VolumeSource = corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: "unregistered", Path: "/other"}}
			}
			if _, err := x.observeRecoveredPod(context.Background(), pod, metadata); err == nil {
				t.Fatal("Ready Pod substituted for complete original positive facts")
			}
		})
	}
}

func TestRecoveredInstanceMountRejectsSubpathAndShadowMountChanges(t *testing.T) {
	for _, name := range []string{"original", "different-subpath", "subpath-expression", "shadow-mount", "different-original-spec"} {
		t.Run(name, func(t *testing.T) {
			x, pod, metadata := sourceRecoveredPodFixture()
			instance := b.InstanceIdentity{ID: 7, Workspace: "/workspaces/users/2/instances/7"}
			metadata.Mounts = []productionInstanceMount{{InstanceID: 7, MountID: "workspace", SubPath: "users/2/instances/7", Source: pod.Spec.Volumes[0], SourceSpecSHA256: "original-spec"}}
			if name == "different-subpath" {
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "other"
			}
			if name == "subpath-expression" {
				pod.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(POD_NAME)"
			}
			if name == "shadow-mount" {
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: instance.Workspace + "/nested"})
			}
			if name == "different-original-spec" {
				metadata.Mounts[0].SourceSpecSHA256 = "other-spec"
			}
			err := x.checkRecoveredInstanceMount(pod, instance, "original-spec", metadata)
			if (name == "original") != (err == nil) {
				t.Fatal("incorrect original mount binding result", err)
			}
		})
	}
}
