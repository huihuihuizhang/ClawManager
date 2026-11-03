package systembackupexecution

import (
	"context"
	"encoding/json"
	"sort"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (x *bootstrapSourceRegistryReader) readWriterAPI(ctx context.Context, clients *productionMetadataClients) (*observedWriterAPI, error) {
	if x.checkPhysical(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out := &observedWriterAPI{objects: []observedWriterAPIObject{}}
	seen := map[string]bool{}
	for _, kind := range []string{"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob", "HorizontalPodAutoscaler", "Pod", "PersistentVolumeClaim"} {
		continuation, version := "", ""
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 || x.checkPhysical(ctx) != nil {
				return nil, ErrSourceWriterObservationIncomplete
			}
			list, err := x.candidateWriterAPIPage(ctx, clients, kind, metav1.ListOptions{Limit: 1000, Continue: continuation})
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
				if err != nil || value.Namespace != x.config.Namespace || seen[key] || len(out.objects) >= 10000 {
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
		if claim.Volume == "" || x.checkPhysical(ctx) != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pv, err := clients.API.CoreV1().PersistentVolumes().Get(ctx, claim.Volume, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name || string(pv.Spec.ClaimRef.UID) != claim.UID {
			return nil, ErrSourceWriterObservationIncomplete
		}
		raw, err := json.Marshal(pv.Spec)
		if err != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out.objects = append(out.objects, observedWriterAPIObject{Kind: "PersistentVolume", Name: pv.Name, UID: string(pv.UID), ResourceVersion: pv.ResourceVersion, SpecSHA256: hash(raw), Owners: []metav1.OwnerReference{}, Claims: []string{claim.Name}})
	}
	if x.checkPhysical(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
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

func (x *bootstrapSourceRegistryReader) candidateWriterAPIPage(ctx context.Context, clients *productionMetadataClients, kind string, options metav1.ListOptions) (runtime.Object, error) {
	c, ns := clients.API, x.config.Namespace
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
