package systembackupexecution

import (
	"context"
	"database/sql"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Recovery and physical actor construction recheck the still-running database;
// they never restore/scale it as an ordinary platform writer.
func (s *DeploymentService) checkDatabaseWorkloadLive(ctx context.Context, client kubernetes.Interface) error {
	if s.Config.DatabaseWorkload == nil {
		return nil
	}
	if client == nil || s.Source == nil || validateDatabaseWorkload(s.Config) != nil {
		return ErrSourceWriterObservationIncomplete
	}
	tx, err := s.Source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrSourceWriterObservationIncomplete
	}
	defer tx.Rollback()
	var hostname string
	if s.checkSourceIdentity(ctx, tx) != nil || tx.QueryRowContext(ctx, "SELECT @@hostname").Scan(&hostname) != nil || hostname == "" {
		return ErrSourceWriterObservationIncomplete
	}
	ref := s.Config.DatabaseWorkload
	pods, err := client.CoreV1().Pods(ref.Namespace).List(ctx, metav1.ListOptions{Limit: 1000})
	if err != nil || pods.Continue != "" || len(pods.Items) > 1000 {
		return ErrSourceWriterObservationIncomplete
	}
	api := &observedWriterAPI{}
	for n := range pods.Items {
		pod := &pods.Items[n]
		if pod.Name != hostname && pod.Spec.Hostname != hostname {
			continue
		}
		projected, e := projectWriterAPIObject("Pod", pod)
		if e != nil {
			return e
		}
		api.objects = append(api.objects, projected)
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.Kind != "ReplicaSet" {
			return ErrSourceWriterObservationIncomplete
		}
		rs, e := client.AppsV1().ReplicaSets(ref.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if e != nil || rs.UID != owner.UID {
			return ErrSourceWriterObservationIncomplete
		}
		projected, e = projectWriterAPIObject("ReplicaSet", rs)
		if e != nil {
			return e
		}
		api.objects = append(api.objects, projected)
	}
	dep, err := client.AppsV1().Deployments(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return ErrSourceWriterObservationIncomplete
	}
	projected, err := projectWriterAPIObject("Deployment", dep)
	if err != nil {
		return err
	}
	api.objects = append(api.objects, projected)
	if addDatabaseGraphRoot(s.Config, api, map[string]string{}, []productionSQLSourceMetadata{{DatabaseHostname: hostname}}) != nil || s.checkSourceIdentity(ctx, tx) != nil || tx.Commit() != nil {
		return ErrSourceWriterObservationIncomplete
	}
	return nil
}

// DatabaseWorkload is observed, never a physical platform stop actor. Its
// reference is administrator-pinned; every graph use also binds it to the
// hostname read from the authenticated source SQL snapshot.
func validateDatabaseWorkload(cfg DeploymentConfig) error {
	ref := cfg.DatabaseWorkload
	if ref == nil {
		return nil
	}
	if ref.Namespace != cfg.Namespace || ref.Name == "" || ref.UID == "" || ref.UID == cfg.ControllerOwner {
		return ErrSourceWriterObservationIncomplete
	}
	refs := append([]PlatformDeployment{}, cfg.Writers...)
	if cfg.RuntimeSources != nil {
		refs = append(refs, cfg.RuntimeSources.Deployments...)
	}
	for _, w := range refs {
		if w.Name == ref.Name || w.UID == ref.UID {
			return ErrSourceWriterObservationIncomplete
		}
	}
	for _, p := range cfg.ProviderDependencies {
		if p.Workload.Deployment == ref.Name || p.Workload.DeploymentUID == ref.UID {
			return ErrSourceWriterObservationIncomplete
		}
	}
	return nil
}

func addDatabaseGraphRoot(cfg DeploymentConfig, api *observedWriterAPI, want map[string]string, sql []productionSQLSourceMetadata) error {
	if cfg.DatabaseWorkload == nil {
		return nil
	}
	if validateDatabaseWorkload(cfg) != nil || api == nil || len(sql) != 1 || sql[0].DatabaseHostname == "" {
		return ErrSourceWriterObservationIncomplete
	}
	ref := cfg.DatabaseWorkload
	key := "Deployment/" + ref.Namespace + "/" + ref.Name
	if want[key] != "" {
		return ErrSourceWriterObservationIncomplete
	}
	objects := map[string]observedWriterAPIObject{}
	for _, o := range api.objects {
		id := o.Kind + "/" + o.Namespace + "/" + o.Name
		if objects[id].UID != "" {
			return ErrSourceWriterObservationIncomplete
		}
		objects[id] = o
	}
	dep := objects[key]
	if dep.UID != ref.UID || dep.Replicas != 1 || dep.Ready != 1 || dep.Generation != dep.ObservedGeneration {
		return ErrSourceWriterObservationIncomplete
	}
	matches := 0
	for _, pod := range api.objects {
		if pod.Kind != "Pod" || pod.Namespace != ref.Namespace || pod.Name != sql[0].DatabaseHostname && pod.Hostname != sql[0].DatabaseHostname {
			continue
		}
		root, err := observedWriterRoot(pod, objects)
		if err != nil || root != key || !pod.Running || pod.UID == "" {
			return ErrSourceWriterObservationIncomplete
		}
		matches++
	}
	if matches != 1 {
		return ErrSourceWriterObservationIncomplete
	}
	want[key] = ref.UID
	return nil
}
