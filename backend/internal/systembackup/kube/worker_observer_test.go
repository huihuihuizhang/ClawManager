package kube

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestWorkerObserverRejectsResourceAndNestedSpecDrift(t *testing.T) {
	for _, scenario := range []string{"valid", "defaults", "job-uid", "pod-owner", "privileged", "extra-env", "pvc-replaced", "pv-remapped", "node-replaced", "restart", "multiple-pods", "missing-binding"} {
		t.Run(scenario, func(t *testing.T) {
			job, e := Job(JobRequest{Identity: Identity{"backup", "capture", "task-one"}, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "backup", Command: []string{"/backup-worker"}, Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/workspace"}}}, NodeName: "node-a", StagingClaim: "staging", DeadlineSeconds: 120})
			if e != nil {
				t.Fatal(e)
			}
			intent, e := Intent("Job", job)
			if e != nil {
				t.Fatal(e)
			}
			liveJob := &batchv1.Job{}
			if e = json.Unmarshal(intent.RequestJSON, liveJob); e != nil {
				t.Fatal(e)
			}
			liveJob.UID = "job-uid"
			liveJob.ResourceVersion = "1"
			record := ResourceRecord{Intent: intent, UID: string(liveJob.UID), CreateDispatched: true}
			yes := true
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "capture-abc", Namespace: "backup", UID: "pod-uid", ResourceVersion: "2", Labels: map[string]string{OwnerLabel: "task-one", "backup.clawmanager.io/job": "capture", "batch.kubernetes.io/controller-uid": "job-uid"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: liveJob.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "worker", Ready: true, ContainerID: "containerd://" + strings.Repeat("a", 64), State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
			for k, v := range job.Spec.Template.Labels {
				pod.Labels[k] = v
			}
			pod.Spec.NodeName = "node-a"
			claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "staging", Namespace: "backup", UID: "claim-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-staging"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
			pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-staging", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: claim.Name, Namespace: claim.Namespace, UID: claim.UID}, PersistentVolumeSource: corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nfs.internal", Path: "/staging"}}}}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}}
			security := WorkerSecurity{NodeUIDs: map[string]string{"node-a": "node-uid"}, Volumes: []MountIdentity{{Volume: "staging", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: ContentHash(pv.Spec)}}}
			switch scenario {
			case "defaults":
				grace := int64(30)
				pod.Spec.TerminationGracePeriodSeconds = &grace
				pod.Spec.DNSPolicy = corev1.DNSClusterFirst
				pod.Spec.SchedulerName = "default-scheduler"
				pod.Spec.Containers[0].ImagePullPolicy = corev1.PullIfNotPresent
			case "job-uid":
				liveJob.UID = "replacement"
			case "pod-owner":
				pod.OwnerReferences[0].UID = types.UID("foreign")
			case "privileged":
				pod.Spec.Containers[0].SecurityContext.Privileged = &yes
			case "extra-env":
				pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "INJECTED", Value: "value"}}
			case "pvc-replaced":
				claim.UID = "replacement"
			case "pv-remapped":
				pv.Spec.NFS.Path = "/foreign"
			case "node-replaced":
				node.UID = "replacement"
			case "restart":
				pod.Status.ContainerStatuses[0].RestartCount = 1
			case "missing-binding":
				security.Volumes = nil
			}
			client := fake.NewSimpleClientset(liveJob, pod, claim, pv, node)
			if scenario == "multiple-pods" {
				second := pod.DeepCopy()
				second.Name = "capture-def"
				second.UID = "second"
				if _, e = client.CoreV1().Pods("backup").Create(context.Background(), second, metav1.CreateOptions{}); e != nil {
					t.Fatal(e)
				}
			}
			observation, e := (WorkerObserver{Client: client}).Observe(context.Background(), record, security)
			if (scenario == "valid" || scenario == "defaults") != (e == nil) {
				t.Fatal("worker identity acceptance mismatch", e)
			}
			if e == nil && observation.UID != "pod-uid" {
				t.Fatal("wrong process captured")
			}
		})
	}
}

func TestJobOwnershipRejectsNestedPrivilegeInjection(t *testing.T) {
	runner, client, journal, job := runnerFixture(t)
	record, e := runner.Ensure(context.Background(), "Job", job)
	if e != nil {
		t.Fatal(e)
	}
	gvr, _, _ := resourceType("Job")
	live, e := client.Resource(gvr).Namespace(record.Intent.Identity.Namespace).Get(context.Background(), record.Intent.Identity.Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	spec := live.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	c["securityContext"].(map[string]any)["privileged"] = true
	if owned(record, live) {
		t.Fatal("nested privilege addition accepted despite frozen request")
	}
	_ = journal
}
