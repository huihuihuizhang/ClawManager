package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
)

// WorkerSecurity is frozen during discovery, before dispatch. Volume identities
// bind PVC->PV and immutable ConfigMap/Secret content; node UIDs prevent a
// recreated node with the same name from inheriting the old authorization.
type WorkerSecurity struct {
	NodeUIDs map[string]string `json:"node_uids"`
	Volumes  []MountIdentity   `json:"volumes"`
}
type MountIdentity struct {
	Volume, Kind, Name, UID string
	PVName, PVUID, SHA256   string
}
type WorkerProcess struct {
	Name, UID, Node string
	Containers      []string
}
type WorkerObserver struct{ Client kubernetes.Interface }

func ContentHash(v any) string {
	raw, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func jsonMap(v any) (map[string]any, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	e = json.Unmarshal(b, &m)
	return m, e
}

// podSpecMatches permits only explicit Kubernetes defaults. Recursive equality
// is intentional: a matching command/hash annotation cannot authorize injected
// privileged securityContext, extra capabilities, env, volumes or sidecars.
func podSpecMatches(expected, actual map[string]any, scheduled bool) bool {
	if expected == nil || actual == nil {
		return false
	}
	raw, _ := json.Marshal(actual)
	var copy map[string]any
	if json.Unmarshal(raw, &copy) != nil {
		return false
	}
	defaults := map[string]any{"dnsPolicy": "ClusterFirst", "schedulerName": "default-scheduler", "terminationGracePeriodSeconds": float64(30), "enableServiceLinks": true, "preemptionPolicy": "PreemptLowerPriority", "serviceAccount": expected["serviceAccountName"]}
	for key, value := range defaults {
		if _, set := expected[key]; !set && reflect.DeepEqual(copy[key], value) {
			delete(copy, key)
		}
	}
	if scheduled {
		if _, set := expected["nodeName"]; !set {
			delete(copy, "nodeName")
		}
		if _, set := expected["priority"]; !set && copy["priority"] == float64(0) {
			delete(copy, "priority")
		}
		if _, set := expected["tolerations"]; !set {
			if ts, ok := copy["tolerations"].([]any); ok {
				seen := map[string]bool{}
				for _, value := range ts {
					m, ok := value.(map[string]any)
					if !ok || len(m) != 4 {
						return false
					}
					key, _ := m["key"].(string)
					if (key != "node.kubernetes.io/not-ready" && key != "node.kubernetes.io/unreachable") || seen[key] || m["operator"] != "Exists" || m["effect"] != "NoExecute" || m["tolerationSeconds"] != float64(300) {
						return false
					}
					seen[key] = true
				}
				delete(copy, "tolerations")
			}
		}
	}
	ec, _ := expected["containers"].([]any)
	ac, _ := copy["containers"].([]any)
	if len(ec) == 0 || len(ec) != len(ac) {
		return false
	}
	for i := range ec {
		em, eok := ec[i].(map[string]any)
		am, aok := ac[i].(map[string]any)
		if !eok || !aok {
			return false
		}
		for key, value := range map[string]any{"imagePullPolicy": "IfNotPresent", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File"} {
			if _, set := em[key]; !set && am[key] == value {
				delete(am, key)
			}
		}
	}
	return reflect.DeepEqual(expected, copy)
}

func (o WorkerObserver) Observe(ctx context.Context, record ResourceRecord, security WorkerSecurity) (WorkerProcess, error) {
	if o.Client == nil || record.Intent.Kind != "Job" || record.UID == "" || record.Deleted || record.Deleting || !record.CreateDispatched || len(security.NodeUIDs) == 0 {
		return WorkerProcess{}, ErrResource
	}
	i := record.Intent.Identity
	job, e := o.Client.BatchV1().Jobs(i.Namespace).Get(ctx, i.Name, metav1.GetOptions{})
	if e != nil {
		return WorkerProcess{}, ErrPending
	}
	jm, e := jsonMap(job)
	if e != nil || !owned(record, &unstructured.Unstructured{Object: jm}) || job.DeletionTimestamp != nil {
		return WorkerProcess{}, ErrOwnership
	}
	pods, e := o.Client.CoreV1().Pods(i.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "batch.kubernetes.io/controller-uid=" + record.UID})
	if e != nil || len(pods.Items) != 1 {
		return WorkerProcess{}, ErrPending
	}
	pod := &pods.Items[0]
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != i.Name || string(owner.UID) != record.UID || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 {
		return WorkerProcess{}, ErrOwnership
	}
	for key, value := range job.Spec.Template.Labels {
		if pod.Labels[key] != value {
			return WorkerProcess{}, ErrOwnership
		}
	}
	var desired map[string]any
	if json.Unmarshal(record.Intent.RequestJSON, &desired) != nil {
		return WorkerProcess{}, ErrResource
	}
	spec, _, _ := unstructured.NestedMap(desired, "spec", "template", "spec")
	pm, e := jsonMap(pod.Spec)
	if e != nil || !podSpecMatches(spec, pm, true) {
		return WorkerProcess{}, ErrOwnership
	}
	// The Job builder uses a single metadata.name node-affinity term for local
	// storage. A manually bound Pod must still satisfy that frozen placement.
	if affinity := job.Spec.Template.Spec.Affinity; affinity != nil && affinity.NodeAffinity != nil && affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		terms := affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) != 1 || len(terms[0].MatchExpressions) != 0 || len(terms[0].MatchFields) != 1 {
			return WorkerProcess{}, ErrOwnership
		}
		field := terms[0].MatchFields[0]
		if field.Key != "metadata.name" || field.Operator != corev1.NodeSelectorOpIn || len(field.Values) != 1 || field.Values[0] != pod.Spec.NodeName {
			return WorkerProcess{}, ErrOwnership
		}
	}
	uid := security.NodeUIDs[pod.Spec.NodeName]
	if uid == "" {
		return WorkerProcess{}, ErrOwnership
	}
	node, e := o.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if e != nil || string(node.UID) != uid || node.DeletionTimestamp != nil || node.Labels[corev1.LabelOSStable] != "linux" {
		return WorkerProcess{}, ErrOwnership
	}
	if e = o.mounts(ctx, i.Namespace, pod.Spec.Volumes, security.Volumes); e != nil {
		return WorkerProcess{}, e
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != pod.Spec.Containers[0].Name || status.ContainerID == "" || status.State.Running == nil || !status.Ready || status.RestartCount != 0 || status.LastTerminationState.Terminated != nil {
		return WorkerProcess{}, ErrPending
	}
	return WorkerProcess{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{status.ContainerID}}, nil
}
func (o WorkerObserver) mounts(ctx context.Context, namespace string, volumes []corev1.Volume, bindings []MountIdentity) error {
	byName := map[string]MountIdentity{}
	for _, b := range bindings {
		if b.Volume == "" || b.UID == "" || b.Name == "" || len(b.SHA256) != 64 {
			return ErrResource
		}
		if _, exists := byName[b.Volume]; exists {
			return ErrResource
		}
		byName[b.Volume] = b
	}
	for _, v := range volumes {
		b, bound := byName[v.Name]
		switch {
		case v.PersistentVolumeClaim != nil:
			if !bound || b.Kind != "PersistentVolumeClaim" || b.Name != v.PersistentVolumeClaim.ClaimName || b.PVName == "" || b.PVUID == "" {
				return ErrOwnership
			}
			claim, e := o.Client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, b.Name, metav1.GetOptions{})
			if e != nil || string(claim.UID) != b.UID || claim.DeletionTimestamp != nil || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName != b.PVName {
				return ErrOwnership
			}
			pv, e := o.Client.CoreV1().PersistentVolumes().Get(ctx, b.PVName, metav1.GetOptions{})
			if e != nil || string(pv.UID) != b.PVUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != b.UID || pv.Spec.ClaimRef.Name != b.Name || pv.Spec.ClaimRef.Namespace != namespace || ContentHash(pv.Spec) != b.SHA256 {
				return ErrOwnership
			}
		case v.Secret != nil:
			if !bound || b.Kind != "Secret" || b.Name != v.Secret.SecretName {
				return ErrOwnership
			}
			secret, e := o.Client.CoreV1().Secrets(namespace).Get(ctx, b.Name, metav1.GetOptions{})
			if e != nil || string(secret.UID) != b.UID || secret.DeletionTimestamp != nil || secret.Immutable == nil || !*secret.Immutable || ContentHash(secret.Data) != b.SHA256 {
				return ErrOwnership
			}
		case v.ConfigMap != nil:
			if !bound || b.Kind != "ConfigMap" || b.Name != v.ConfigMap.Name {
				return ErrOwnership
			}
			cm, e := o.Client.CoreV1().ConfigMaps(namespace).Get(ctx, b.Name, metav1.GetOptions{})
			if e != nil || string(cm.UID) != b.UID || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || ContentHash([]any{cm.Data, cm.BinaryData}) != b.SHA256 {
				return ErrOwnership
			}
		case v.HostPath != nil, v.NFS != nil, v.EmptyDir != nil:
			// Exact path/export/subPath/read-only settings are already frozen in spec.
			if bound {
				return ErrOwnership
			}
		default:
			return ErrResource
		}
		delete(byName, v.Name)
	}
	if len(byName) != 0 {
		return ErrOwnership
	}
	return nil
}

func SameWorkerProcess(a, b WorkerProcess) bool {
	aa, bb := append([]string(nil), a.Containers...), append([]string(nil), b.Containers...)
	sort.Strings(aa)
	sort.Strings(bb)
	return a.Name == b.Name && a.UID == b.UID && a.Node == b.Node && reflect.DeepEqual(aa, bb)
}
