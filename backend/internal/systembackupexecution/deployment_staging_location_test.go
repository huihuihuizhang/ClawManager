package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func stagingLocationFixture() (*DeploymentService, *fake.Clientset, *corev1.Pod, *corev1.Node, *corev1.PersistentVolumeClaim, *corev1.PersistentVolume) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "original-node", UID: "original-node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux", "original-storage": "true"}}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "original-staging", Namespace: "original", UID: "original-claim-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-pv", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: claim.Spec.VolumeName, UID: "original-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}, PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/original-staging"}}, NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "original-storage", Operator: corev1.NodeSelectorOpIn, Values: []string{"true"}}}}}}}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-controller", Namespace: claim.Namespace, UID: "original-controller-uid"}, Spec: corev1.PodSpec{NodeName: node.Name, ServiceAccountName: "controller", Volumes: []corev1.Volume{{Name: "staging", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name}}}}, Containers: []corev1.Container{{Name: "controller", VolumeMounts: []corev1.VolumeMount{{Name: "staging", MountPath: "/staging"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "controller", ContainerID: "containerd://original-controller", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	ref := &StagingLocationReference{Version: stagingLocationVersion, Node: node.Name, NodeUID: string(node.UID), Container: "controller", Volume: "staging", ContainerPath: "/staging", Claim: claim.Name, ClaimUID: string(claim.UID), PV: pv.Name, PVUID: string(pv.UID), PVSpecSHA256: kube.ContentHash(pv.Spec)}
	cfg := DeploymentConfig{Namespace: claim.Namespace, NamespaceUID: "original-namespace-uid", StagingDirectory: "/staging", StagingClaim: claim.Name, StagingLocation: ref, Workspace: WorkspaceCapture{Node: node.Name}, Security: kube.WorkerSecurity{NodeUIDs: map[string]string{node.Name: string(node.UID)}, Volumes: []kube.MountIdentity{{Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: ref.PVSpecSHA256}}}}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: "original-namespace-uid"}}, pod, node, claim, pv)
	s := &DeploymentService{Config: cfg, controllerActor: controllerObservedActor{PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: "controller"}}
	s.Runtime = &PublicCapture{Owner: &PublicJobOwner{Client: client}}
	return s, client, pod, node, claim, pv
}

func TestStagingLocationRequiresOriginalControllerNodeContainerAndVolume(t *testing.T) {
	for _, change := range []string{"original", "starting-controller", "missing-reference", "wrong-config-node", "wrong-actor", "other-node", "node-replaced", "node-pressure", "node-not-ready", "node-cordoned", "wrong-container", "terminated-container", "subpath", "subpath-expression", "readonly-mount", "shadow-mount", "claim-replaced", "claim-unbound", "claim-readonly", "pv-replaced", "pv-spec-changed", "affinity-no-longer-matches"} {
		t.Run(change, func(t *testing.T) {
			s, client, pod, node, claim, pv := stagingLocationFixture()
			switch change {
			case "starting-controller":
				pod.Status.Conditions[0].Status = corev1.ConditionFalse
				pod.Status.ContainerStatuses[0].Ready = false
			case "missing-reference":
				s.Config.StagingLocation = nil
			case "wrong-config-node":
				s.Config.Workspace.Node = "spare-node"
			case "wrong-actor":
				s.controllerActor.PodUID = "replacement-controller-uid"
			case "other-node":
				pod.Spec.NodeName = "spare-node"
			case "node-replaced":
				node.UID = "replacement-node-uid"
			case "node-pressure":
				node.Status.Conditions = append(node.Status.Conditions, corev1.NodeCondition{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue})
			case "node-not-ready":
				node.Status.Conditions[0].Status = corev1.ConditionFalse
			case "node-cordoned":
				node.Spec.Unschedulable = true
			case "wrong-container":
				s.Config.StagingLocation.Container = "another-container"
			case "terminated-container":
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "different-root"
			case "subpath-expression":
				pod.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(POD_NAME)"
			case "readonly-mount":
				pod.Spec.Containers[0].VolumeMounts[0].ReadOnly = true
			case "shadow-mount":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "different", MountPath: "/staging/objects"})
			case "claim-replaced":
				claim.UID = "replacement-claim-uid"
			case "claim-unbound":
				claim.Status.Phase = corev1.ClaimPending
			case "claim-readonly":
				claim.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadOnlyMany}
			case "pv-replaced":
				pv.UID = "replacement-pv-uid"
			case "pv-spec-changed":
				pv.Spec.HostPath.Path = "/other-data"
			case "affinity-no-longer-matches":
				node.Labels["original-storage"] = "false"
			}
			ctx := context.Background()
			for _, update := range []func() error{
				func() error {
					_, err := client.CoreV1().Pods(pod.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
					return err
				},
				func() error { _, err := client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); return err },
				func() error {
					_, err := client.CoreV1().PersistentVolumeClaims(claim.Namespace).Update(ctx, claim, metav1.UpdateOptions{})
					return err
				},
				func() error {
					_, err := client.CoreV1().PersistentVolumes().Update(ctx, pv, metav1.UpdateOptions{})
					return err
				},
			} {
				if err := update(); err != nil {
					t.Fatal(err)
				}
			}
			actualNode, err := s.publicationStagingNode(ctx)
			if change == "original" || change == "starting-controller" {
				if err != nil || actualNode != "original-node" {
					t.Fatal("original API staging binding refused", actualNode, err)
				}
			} else if err == nil || actualNode != "" {
				t.Fatal("replacement/absent staging identity accepted", actualNode)
			}
		})
	}
}

func TestCaptureOperationsUseOneOriginalStagingNode(t *testing.T) {
	s, _, _, _, _, _ := stagingLocationFixture()
	s.captureMaterials = &productionCaptureMaterials{Operations: map[string]productionCaptureOperation{"capture-database": {}, "capture-workspace": {}}}
	operations, err := s.captureOperationsAtStagingNode()
	if err != nil || len(operations) != 2 {
		t.Fatal(err)
	}
	for name, operation := range operations {
		if operation.Workload.NodeName != "original-node" || s.captureMaterials.Operations[name].Workload.NodeName != "" {
			t.Fatal("operation placement was empty or modified immutable input")
		}
	}
	wrong := s.captureMaterials.Operations["capture-workspace"]
	wrong.Workload.NodeName = "spare-node"
	s.captureMaterials.Operations["capture-workspace"] = wrong
	if _, err := s.captureOperationsAtStagingNode(); err == nil {
		t.Fatal("conflicting original source/staging node accepted")
	}
}
