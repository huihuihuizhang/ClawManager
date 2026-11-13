package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	"context"
	"encoding/json"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type observedWriterAPIObject struct {
	pod                                                     *corev1.Pod
	Hostname                                                string `json:",omitempty"`
	Kind, Namespace, Name, UID, ResourceVersion, SpecSHA256 string
	Generation, ObservedGeneration                          int64
	Replicas, Ready                                         int32
	Node, Phase, Volume                                     string
	Running                                                 bool
	Owners                                                  []metav1.OwnerReference
	Claims                                                  []string
	Processes                                               []string
}

type observedWriterAPI struct {
	objects []observedWriterAPIObject
	sha256  string
}

// Fixed namespace/resource set from the original source scope. This enumerates
// unknown controllers too; the later graph check cannot silently drop them.
func (x *sourceSQLObservation) observeWriterAPI(ctx context.Context, inventories ...[]b.InstanceIdentity) (*observedWriterAPI, error) {
	if x.recheck(ctx) != nil || len(inventories) > 1 {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out := &observedWriterAPI{objects: []observedWriterAPIObject{}}
	seen := map[string]bool{}
	for _, kind := range []string{"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob", "HorizontalPodAutoscaler", "Pod", "PersistentVolumeClaim"} {
		continuation, version := "", ""
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 || x.recheck(ctx) != nil {
				return nil, ErrSourceWriterObservationIncomplete
			}
			list, err := x.writerAPIPage(ctx, kind, metav1.ListOptions{Limit: 1000, Continue: continuation})
			if err != nil {
				return nil, ErrSourceWriterObservationIncomplete
			}
			m, err := meta.ListAccessor(list)
			if err != nil || m.GetResourceVersion() == "" {
				return nil, ErrSourceWriterObservationIncomplete
			}
			if page == 0 {
				version = m.GetResourceVersion()
			} else if version != m.GetResourceVersion() {
				return nil, ErrSourceWriterObservationIncomplete
			}
			items, err := meta.ExtractList(list)
			if err != nil || len(items) > 1000 {
				return nil, ErrSourceWriterObservationIncomplete
			}
			for _, item := range items {
				value, err := projectWriterAPIObject(kind, item)
				key := value.Kind + "/" + value.Namespace + "/" + value.Name
				if err != nil || value.Namespace != x.delegation.service.Config.Namespace || seen[key] || len(out.objects) >= 10000 {
					return nil, ErrSourceWriterObservationIncomplete
				}
				seen[key] = true
				out.objects = append(out.objects, value)
			}
			continuation = m.GetContinue()
			if continuation == "" {
				break
			}
			if tokens[continuation] {
				return nil, ErrSourceWriterObservationIncomplete
			}
			tokens[continuation] = true
		}
	}
	// PV reads are limited to the complete namespace PVC set, never a caller's
	// selected list. Bind each actual PV to the exact current PVC UID.
	claims := append([]observedWriterAPIObject{}, out.objects...)
	for _, claim := range claims {
		if claim.Kind != "PersistentVolumeClaim" {
			continue
		}
		if claim.Volume == "" || x.recheck(ctx) != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pv, err := x.delegation.owner.Client.CoreV1().PersistentVolumes().Get(ctx, claim.Volume, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name || string(pv.Spec.ClaimRef.UID) != claim.UID {
			return nil, ErrSourceWriterObservationIncomplete
		}
		raw, err := json.Marshal(pv.Spec)
		if err != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out.objects = append(out.objects, observedWriterAPIObject{Kind: "PersistentVolume", Name: pv.Name, UID: string(pv.UID), ResourceVersion: pv.ResourceVersion, SpecSHA256: hash(raw), Owners: []metav1.OwnerReference{}, Claims: []string{claim.Name}})
	}
	if x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	if len(inventories) == 1 {
		var scope *productionPersistentMountScope
		service := x.delegation.service
		if service.captureMaterials != nil && service.captureMaterials.Discovery != nil {
			scope = service.captureMaterials.Discovery.PersistentMounts
		}
		tenant, err := observeTenantProWriterAPI(ctx, x.delegation.owner.Client, service.Config, inventories[0], scope, x.recheck)
		if err != nil || len(out.objects)+len(tenant) > 10000 {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out.objects = append(out.objects, tenant...)
	}
	sort.Slice(out.objects, func(i, j int) bool {
		a, b := out.objects[i], out.objects[j]
		return a.Kind+"/"+a.Namespace+"/"+a.Name < b.Kind+"/"+b.Namespace+"/"+b.Name
	})
	raw, err := json.Marshal(out.objects)
	if err != nil || len(raw) > 8<<20 {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out.sha256 = hash(raw)
	return out, nil
}

func (x *sourceSQLObservation) writerAPIPage(ctx context.Context, kind string, options metav1.ListOptions) (runtime.Object, error) {
	c, ns := x.delegation.owner.Client, x.delegation.service.Config.Namespace
	switch kind {
	case "Deployment":
		return c.AppsV1().Deployments(ns).List(ctx, options)
	case "ReplicaSet":
		return c.AppsV1().ReplicaSets(ns).List(ctx, options)
	case "StatefulSet":
		return c.AppsV1().StatefulSets(ns).List(ctx, options)
	case "DaemonSet":
		return c.AppsV1().DaemonSets(ns).List(ctx, options)
	case "Job":
		return c.BatchV1().Jobs(ns).List(ctx, options)
	case "CronJob":
		return c.BatchV1().CronJobs(ns).List(ctx, options)
	case "HorizontalPodAutoscaler":
		return c.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, options)
	case "Pod":
		return c.CoreV1().Pods(ns).List(ctx, options)
	case "PersistentVolumeClaim":
		return c.CoreV1().PersistentVolumeClaims(ns).List(ctx, options)
	}
	return nil, ErrSourceWriterObservationIncomplete
}

func projectWriterAPIObject(kind string, object runtime.Object) (observedWriterAPIObject, error) {
	var out observedWriterAPIObject
	m, err := meta.Accessor(object)
	if err != nil || m.GetName() == "" || m.GetUID() == "" || m.GetDeletionTimestamp() != nil {
		return out, ErrSourceWriterObservationIncomplete
	}
	out = observedWriterAPIObject{Kind: kind, Namespace: m.GetNamespace(), Name: m.GetName(), UID: string(m.GetUID()), ResourceVersion: m.GetResourceVersion(), Generation: m.GetGeneration(), Owners: append([]metav1.OwnerReference{}, m.GetOwnerReferences()...), Claims: []string{}}
	var spec any
	switch value := object.(type) {
	case *appsv1.Deployment:
		spec = value.Spec
		if value.Spec.Replicas == nil {
			return out, ErrSourceWriterObservationIncomplete
		}
		out.Replicas, out.Ready, out.ObservedGeneration = *value.Spec.Replicas, value.Status.ReadyReplicas, value.Status.ObservedGeneration
	case *appsv1.ReplicaSet:
		spec = value.Spec
	case *appsv1.StatefulSet:
		spec = value.Spec
	case *appsv1.DaemonSet:
		spec = value.Spec
	case *batchv1.Job:
		spec = value.Spec
	case *batchv1.CronJob:
		spec = value.Spec
	case *corev1.Pod:
		out.pod = value.DeepCopy()
		out.Hostname = value.Spec.Hostname
		spec = value.Spec
		out.Node, out.Phase = value.Spec.NodeName, string(value.Status.Phase)
		out.Running = value.Status.Phase == corev1.PodRunning && out.Node != "" && len(value.Status.ContainerStatuses) != 0
		ready := false
		for _, condition := range value.Status.Conditions {
			ready = ready || condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
		}
		out.Running = out.Running && ready
		for _, status := range value.Status.ContainerStatuses {
			out.Running = out.Running && status.Ready && status.ContainerID != "" && status.State.Running != nil
			out.Processes = append(out.Processes, status.Name+"/"+status.ContainerID)
		}
		sort.Strings(out.Processes)
		for _, volume := range value.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil {
				out.Claims = append(out.Claims, volume.PersistentVolumeClaim.ClaimName)
			}
		}
	case *corev1.PersistentVolumeClaim:
		spec = value.Spec
		out.Volume = value.Spec.VolumeName
	default:
		// HPA is deliberately represented and rejected by the graph check;
		// no unsupported controller is treated as an absent writer.
		spec = object
	}
	raw, err := json.Marshal(spec)
	if err != nil || len(raw) > 1<<20 {
		return out, ErrSourceWriterObservationIncomplete
	}
	out.SpecSHA256 = hash(raw)
	clear(raw)
	return out, nil
}
