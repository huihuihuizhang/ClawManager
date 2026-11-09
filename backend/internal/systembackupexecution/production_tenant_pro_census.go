package systembackupexecution

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

// Tenant names come from original SQL owners, never an HTTP namespace list.
// Every controller in each selected tenant is observed, including unknown ones.
func observeTenantProWriterAPI(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, sources []b.InstanceIdentity, scope *productionPersistentMountScope, check func(context.Context) error) ([]observedWriterAPIObject, error) {
	if client == nil || check == nil || len(sources) > 9998 || check(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	users := map[string]int{}
	for _, source := range sources {
		if deferredRuntimeTestInstance(cfg, source) || !isRunningTenantPro(source) || source.Namespace == cfg.Namespace {
			continue
		}
		if !validTenantProNamespace(cfg.Namespace, source) || source.Pod == "" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		if scope != nil {
			pin := runningTenantProMountFor(scope, source)
			if pin == nil || pin.check(ctx, client, cfg.Namespace) != nil {
				return nil, ErrSourceWriterObservationIncomplete
			}
		}
		users[source.Namespace] = source.UserID
	}
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []observedWriterAPIObject{}
	seen := map[string]bool{}
	for _, namespace := range names {
		if check(ctx) != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		ns, err := client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil || ns.Labels["app"] != "clawreef" || ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != strconv.Itoa(users[namespace]) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		raw, err := json.Marshal([]any{ns.Spec, ns.Labels})
		if err != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out = append(out, observedWriterAPIObject{Kind: "Namespace", Name: namespace, UID: string(ns.UID), ResourceVersion: ns.ResourceVersion, SpecSHA256: hash(raw)})
		for _, kind := range []string{"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob", "HorizontalPodAutoscaler", "Pod", "PersistentVolumeClaim"} {
			continuation, version := "", ""
			tokens := map[string]bool{}
			for page := 0; ; page++ {
				if page >= 100 || check(ctx) != nil {
					return nil, ErrSourceWriterObservationIncomplete
				}
				list, err := tenantWriterAPIPage(ctx, client, namespace, kind, metav1.ListOptions{Limit: 1000, Continue: continuation})
				if err != nil {
					return nil, ErrSourceWriterObservationIncomplete
				}
				accessor, err := meta.ListAccessor(list)
				if err != nil || accessor.GetResourceVersion() == "" || page > 0 && accessor.GetResourceVersion() != version {
					return nil, ErrSourceWriterObservationIncomplete
				}
				version = accessor.GetResourceVersion()
				items, err := meta.ExtractList(list)
				if err != nil || len(items) > 1000 {
					return nil, ErrSourceWriterObservationIncomplete
				}
				for _, item := range items {
					value, err := projectWriterAPIObject(kind, item)
					key := value.Kind + "/" + value.Namespace + "/" + value.Name
					if err != nil || value.Namespace != namespace || seen[key] || len(out) >= 10000 {
						return nil, ErrSourceWriterObservationIncomplete
					}
					seen[key] = true
					out = append(out, value)
				}
				continuation = accessor.GetContinue()
				if continuation == "" {
					break
				}
				if tokens[continuation] {
					return nil, ErrSourceWriterObservationIncomplete
				}
				tokens[continuation] = true
			}
		}
	}
	for _, claim := range append([]observedWriterAPIObject{}, out...) {
		if claim.Kind != "PersistentVolumeClaim" {
			continue
		}
		if claim.Volume == "" || check(ctx) != nil || len(out) >= 10000 {
			return nil, ErrSourceWriterObservationIncomplete
		}
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, claim.Volume, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != claim.Namespace || pv.Spec.ClaimRef.Name != claim.Name || string(pv.Spec.ClaimRef.UID) != claim.UID {
			return nil, ErrSourceWriterObservationIncomplete
		}
		raw, err := json.Marshal(pv.Spec)
		if err != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		out = append(out, observedWriterAPIObject{Kind: "PersistentVolume", Name: pv.Name, UID: string(pv.UID), ResourceVersion: pv.ResourceVersion, SpecSHA256: hash(raw), Owners: []metav1.OwnerReference{}, Claims: []string{claim.Name}})
	}
	return out, check(ctx)
}

func tenantWriterAPIPage(ctx context.Context, client kubernetes.Interface, namespace, kind string, options metav1.ListOptions) (runtime.Object, error) {
	switch kind {
	case "Deployment":
		return client.AppsV1().Deployments(namespace).List(ctx, options)
	case "ReplicaSet":
		return client.AppsV1().ReplicaSets(namespace).List(ctx, options)
	case "StatefulSet":
		return client.AppsV1().StatefulSets(namespace).List(ctx, options)
	case "DaemonSet":
		return client.AppsV1().DaemonSets(namespace).List(ctx, options)
	case "Job":
		return client.BatchV1().Jobs(namespace).List(ctx, options)
	case "CronJob":
		return client.BatchV1().CronJobs(namespace).List(ctx, options)
	case "HorizontalPodAutoscaler":
		return client.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, options)
	case "Pod":
		return client.CoreV1().Pods(namespace).List(ctx, options)
	case "PersistentVolumeClaim":
		return client.CoreV1().PersistentVolumeClaims(namespace).List(ctx, options)
	}
	return nil, ErrSourceWriterObservationIncomplete
}

func appendTenantProGraphRoots(cfg DeploymentConfig, source b.SourceInventory, api *observedWriterAPI, want map[string]string, scope *productionPersistentMountScope) (map[string]string, error) {
	objects := map[string]observedWriterAPIObject{}
	for _, object := range api.objects {
		key := object.Kind + "/" + object.Namespace + "/" + object.Name
		if objects[key].UID != "" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		objects[key] = object
	}
	namespaces := map[string]string{}
	for _, instance := range source.Instances {
		if deferredRuntimeTestInstance(cfg, instance) || !isRunningTenantPro(instance) || instance.Namespace == cfg.Namespace {
			continue
		}
		if !validTenantProNamespace(cfg.Namespace, instance) {
			return nil, ErrSourceWriterObservationIncomplete
		}
		ns := objects["Namespace//"+instance.Namespace]
		pod := objects["Pod/"+instance.Namespace+"/"+instance.Pod]
		root, err := observedWriterRoot(pod, objects)
		deployment := objects[root]
		if err != nil || ns.UID == "" || pod.UID == "" || !pod.Running || deployment.Kind != "Deployment" || deployment.Namespace != instance.Namespace || deployment.UID == "" || deployment.Replicas != 1 {
			return nil, ErrSourceWriterObservationIncomplete
		}
		if scope != nil {
			pin := runningTenantProMountFor(scope, instance)
			if pin == nil || !pin.valid() || pin.NamespaceUID != ns.UID || pin.PodUID != pod.UID || pin.PodSpecSHA256 != pod.SpecSHA256 || pin.Deployment != deployment.Name || pin.DeploymentUID != deployment.UID {
				return nil, ErrSourceWriterObservationIncomplete
			}
		}
		if want[root] != "" {
			return nil, ErrSourceWriterObservationIncomplete
		}
		want[root], namespaces[instance.Namespace] = deployment.UID, ns.UID
	}
	return namespaces, nil
}

func observeTenantProMountFromCensus(ctx context.Context, client kubernetes.Interface, cfg DeploymentConfig, source b.InstanceIdentity, api *observedWriterAPI) (runningTenantProMount, error) {
	var empty runningTenantProMount
	if api == nil || !isRunningTenantPro(source) || !validTenantProNamespace(cfg.Namespace, source) {
		return empty, ErrSourceWriterObservationIncomplete
	}
	objects := map[string]observedWriterAPIObject{}
	for _, object := range api.objects {
		key := object.Kind + "/" + object.Namespace + "/" + object.Name
		if objects[key].UID != "" {
			return empty, ErrSourceWriterObservationIncomplete
		}
		objects[key] = object
	}
	pod := objects["Pod/"+source.Namespace+"/"+source.Pod]
	root, err := observedWriterRoot(pod, objects)
	deployment := objects[root]
	if err != nil || pod.UID == "" || !pod.Running || deployment.Kind != "Deployment" || deployment.Namespace != source.Namespace {
		return empty, ErrSourceWriterObservationIncomplete
	}
	mount, err := observeRunningTenantProMount(ctx, client, cfg, source, b.RuntimeWriterSpec{Source: source, Kind: "deployment", Name: deployment.Name, UID: deployment.UID})
	if err != nil || mount.PodUID != pod.UID || mount.PodSpecSHA256 != pod.SpecSHA256 || mount.NamespaceUID != objects["Namespace//"+source.Namespace].UID {
		return empty, ErrSourceWriterObservationIncomplete
	}
	return mount, nil
}
