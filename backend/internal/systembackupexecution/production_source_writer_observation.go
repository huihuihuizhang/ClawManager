package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrSourceWriterObservationIncomplete = errors.New("original source writer observation incomplete or outside the pinned registry")

// Facts only. The original task's authority, gate, writer freeze/recovery,
// publication dependencies and admission drift checks remain mandatory.
type SourceDependencyObservation struct {
	metadata         SourceMetadataObservation
	metadataSHA256   string
	writerSHA256     string
	checkedAt, until time.Time
}

func (o SourceDependencyObservation) CheckedAt() time.Time   { return o.checkedAt }
func (o SourceDependencyObservation) ValidUntil() time.Time  { return o.until }
func (o SourceDependencyObservation) WriterSHA256() string   { return o.writerSHA256 }
func (o SourceDependencyObservation) MetadataSHA256() string { return o.metadataSHA256 }

func (s *DeploymentService) ObserveSourceDependencies(ctx context.Context) (SourceDependencyObservation, error) {
	var zero SourceDependencyObservation
	x, err := s.newSourceSQLObservation(ctx)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	metadata, err := x.observeMetadata(ctx)
	if err != nil {
		return zero, err
	}
	if err = requireRunningSourceMetadata(metadata.inventory.source); err != nil {
		return zero, err
	}
	registry, err := x.observeWriterRegistry(ctx)
	if err != nil {
		return zero, err
	}
	api, err := x.observeWriterAPI(ctx)
	if err != nil {
		return zero, err
	}
	native, err := x.observeNativeWriters(ctx, metadata.inventory.source, registry, api, metadata.inventory.sql.metadata)
	if err != nil {
		return zero, err
	}
	lastAPI, err := x.observeWriterAPI(ctx)
	if err != nil || lastAPI.sha256 != api.sha256 {
		return zero, ErrSourceWriterObservationIncomplete
	}
	lastRegistry, err := x.observeWriterRegistry(ctx)
	if err != nil || lastRegistry.sha256 != registry.sha256 {
		return zero, ErrSourceWriterObservationIncomplete
	}
	lastNative, err := x.observeNativeWriters(ctx, metadata.inventory.source, lastRegistry, lastAPI, metadata.inventory.sql.metadata)
	if err != nil || native != lastNative {
		return zero, ErrSourceWriterObservationIncomplete
	}
	lastMetadata, err := x.observeMetadata(ctx)
	if err != nil || metadata.SHA256() != lastMetadata.SHA256() || !reflect.DeepEqual(metadata.inventory.sql.metadata, lastMetadata.inventory.sql.metadata) || x.recheck(ctx) != nil || !time.Now().Before(x.delegation.until) {
		return zero, ErrSourceWriterObservationIncomplete
	}
	raw, _ := json.Marshal([]string{registry.sha256, api.sha256, native})
	metadataRaw, err := json.Marshal(struct {
		Metadata, Config, Profile, Scope string
		Version                          uint64
		SQL                              productionSQLSourceMetadata
	}{lastMetadata.SHA256(), lastMetadata.inventory.sql.configSHA256, lastMetadata.inventory.sql.profileSHA256, lastMetadata.inventory.sql.sourceScopeSHA256, lastMetadata.inventory.sql.configVersion, lastMetadata.inventory.sql.metadata})
	if err != nil || len(metadataRaw) > 8<<20 {
		return zero, ErrSourceWriterObservationIncomplete
	}
	return SourceDependencyObservation{metadata: lastMetadata, metadataSHA256: hash(metadataRaw), writerSHA256: hash(raw), checkedAt: lastMetadata.CheckedAt(), until: x.delegation.until}, nil
}

func requireRunningSourceMetadata(source b.SourceInventory) error {
	for _, instance := range source.Instances {
		if instance.Status == "stopped" && !isCurrentStoppedPro(instance) {
			return c.ErrSourceRecoveryStoppedWitnessRequired
		}
		if instance.Status != "running" && !isCurrentStoppedPro(instance) {
			return ErrSourceWriterObservationIncomplete
		}
	}
	return nil
}

func (x *sourceSQLObservation) observeNativeWriters(ctx context.Context, source b.SourceInventory, registry *observedSourceWriterRegistry, api *observedWriterAPI, observedSQL ...productionSQLSourceMetadata) (string, error) {
	if x == nil || x.delegation == nil {
		return "", ErrSourceWriterObservationIncomplete
	}
	s := x.delegation.service
	if x.recheck(ctx) != nil || registry == nil || api == nil || requireRunningSourceMetadata(source) != nil {
		return "", ErrSourceWriterObservationIncomplete
	}
	if err := checkObservedWriterGraph(s, source, api); err != nil {
		return "", err
	}
	for _, object := range api.objects {
		if object.Kind != "Pod" {
			continue
		}
		if object.Node == "" || s.Config.Security.NodeUIDs[object.Node] == "" || x.recheck(ctx) != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
		node, err := x.delegation.owner.Client.CoreV1().Nodes().Get(ctx, object.Node, metav1.GetOptions{})
		if err != nil || string(node.UID) != s.Config.Security.NodeUIDs[object.Node] || node.Labels[corev1.LabelOSStable] != "linux" || node.DeletionTimestamp != nil || x.recheck(ctx) != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
	}
	bindings, pods := map[int]observedSourceRuntimeBinding{}, map[int]observedSourceRuntimePod{}
	for _, row := range registry.bindings {
		bindings[row.Instance] = row
	}
	for _, row := range registry.pods {
		pods[row.ID] = row
	}
	var sqlMetadata productionSQLSourceMetadata
	if len(observedSQL) > 1 {
		return "", ErrSourceWriterObservationIncomplete
	}
	if len(observedSQL) == 1 {
		sqlMetadata = observedSQL[0]
	}
	if checkCurrentStoppedProSQL(s.captureMaterials.Discovery.PersistentMounts, sqlMetadata, source.Instances) != nil {
		return "", ErrSourceWriterObservationIncomplete
	}
	current := []CurrentStoppedProSourceMaterial{}
	actual := []b.RuntimeWriterSpec{}
	seen := map[int]bool{}
	for _, instance := range source.Instances {
		if isCurrentStoppedPro(instance) {
			m, err := currentStoppedProMaterialFor(s.captureMaterials.Discovery.PersistentMounts, instance)
			if err != nil || recheckCurrentStoppedProMaterial(ctx, x.delegation.owner.Client, s.Config, *m) != nil {
				return "", ErrSourceWriterObservationIncomplete
			}
			current = append(current, *m)
			continue
		}
		if instance.Mode != "lite" {
			continue
		}
		if x.recheck(ctx) != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
		// Existing read-only resolver authenticates actual SQL locator, Pod /
		// ReplicaSet / Deployment and native agent capabilities. It writes no
		// runtime reservation, key material or task journal.
		if s.RuntimeControl == nil {
			return "", ErrSourceWriterObservationIncomplete
		}
		spec, err := s.RuntimeControl.ResolveGatewaySource(ctx, instance)
		if err != nil {
			return "", err
		}
		binding, pod := bindings[instance.ID], pods[spec.Runtime.RuntimePodID]
		if binding.RuntimePod != pod.ID || binding.Generation != instance.Generation || binding.Gateway != fmt.Sprintf("gw-%d-%d", instance.ID, instance.Generation) || binding.PID != spec.Runtime.GatewayPID || binding.Port != spec.Port || binding.Workspace != instance.Workspace || binding.State != "running" || pod.Namespace != spec.Runtime.Namespace || pod.Name != spec.Runtime.Pod || pod.Endpoint != spec.Endpoint || pod.Deployment != spec.Runtime.Deployment || pod.State != "ready" || pod.Draining || pod.UID != "" && pod.UID != spec.UID {
			return "", ErrSourceWriterObservationIncomplete
		}
		agent, err := nativeBackupAgent(*s.Config.RuntimeSources)
		if err != nil {
			return "", err
		}
		state, err := agent.GatewayState(ctx, spec.Endpoint, binding.Gateway)
		if err != nil || state == nil || state.State != "running" || state.InstanceID != instance.ID || state.UserID != instance.UserID || state.Generation != instance.Generation || state.GatewayID != binding.Gateway || state.PID <= 0 || state.PID != binding.PID || state.Port != binding.Port || x.recheck(ctx) != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
		seen[instance.ID] = true
		actual = append(actual, spec)
	}
	for _, binding := range registry.bindings {
		if binding.State == "running" && !seen[binding.Instance] {
			return "", ErrSourceWriterObservationIncomplete
		}
	}
	for _, pod := range registry.pods {
		if pod.State != "ready" || pod.Draining {
			continue
		}
		found := false
		for _, object := range api.objects {
			found = found || object.Kind == "Pod" && object.Namespace == pod.Namespace && object.Name == pod.Name && (pod.UID == "" || object.UID == pod.UID) && object.Running
		}
		if !found {
			return "", ErrSourceWriterObservationIncomplete
		}
	}
	if s.checkRuntimeWorkspace(ctx, x.delegation.owner.Client, source.Instances) != nil || x.recheck(ctx) != nil {
		return "", ErrSourceWriterObservationIncomplete
	}
	raw, err := json.Marshal(actual)
	if len(current) > 0 {
		raw, err = json.Marshal(struct {
			Running           []b.RuntimeWriterSpec
			CurrentStoppedPro []CurrentStoppedProSourceMaterial
		}{actual, current})
	}
	if err != nil || len(raw) > 8<<20 {
		return "", ErrSourceWriterObservationIncomplete
	}
	if len(s.Config.ProviderDependencies) != 0 {
		dependencies, e := x.observeSourceVaultDependencies(ctx)
		if e != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
		raw, err = json.Marshal(struct {
			Native               json.RawMessage
			ProviderDependencies []formalVaultProviderFacts
		}{raw, dependencies})
		if err != nil || x.recheck(ctx) != nil {
			return "", ErrSourceWriterObservationIncomplete
		}
	}
	return hash(raw), nil
}

func checkObservedWriterGraph(s *DeploymentService, source b.SourceInventory, api *observedWriterAPI) error {
	if s == nil || s.Config.RuntimeSources == nil || s.captureMaterials == nil || s.captureMaterials.Discovery == nil || api == nil || requireRunningSourceMetadata(source) != nil {
		return ErrSourceWriterObservationIncomplete
	}
	ns, p := s.Config.Namespace, s.captureMaterials.Discovery
	controller := "Deployment/" + ns + "/" + p.ControllerDeployment
	want := map[string]string{controller: p.ControllerDeploymentUID}
	platformIDs := map[string]bool{}
	for _, ref := range s.Config.Writers {
		platformIDs["deployment/"+ref.Namespace+"/"+ref.Name] = true
	}
	for id := range p.TeamPlatformUnits {
		if !strings.HasPrefix(id, "deployment/") || !platformIDs[id] {
			return ErrSourceWriterObservationIncomplete
		}
	}
	for _, refs := range [][]PlatformDeployment{s.Config.Writers, s.Config.RuntimeSources.Deployments} {
		for _, ref := range refs {
			key := "Deployment/" + ref.Namespace + "/" + ref.Name
			if ref.Namespace != ns || key == controller || ref.UID == "" || want[key] != "" && want[key] != ref.UID {
				return ErrSourceWriterObservationIncomplete
			}
			want[key] = ref.UID
		}
	}
	for _, dependency := range s.Config.ProviderDependencies {
		w := dependency.Workload
		key := "Deployment/" + ns + "/" + w.Deployment
		if key == controller || want[key] != "" || w.DeploymentUID == "" {
			return ErrSourceWriterObservationIncomplete
		}
		want[key] = w.DeploymentUID
	}
	stoppedRoots, err := currentStoppedProGraphRoots(s.Config, source, api, want)
	if err != nil {
		return err
	}
	objects, rawPods, podCounts := map[string]observedWriterAPIObject{}, map[string]bool{}, map[string]int32{}
	for _, instance := range source.Instances {
		if instance.Mode == "pro" && !isCurrentStoppedPro(instance) {
			if instance.Namespace != ns || instance.Pod == "" {
				return ErrSourceWriterObservationIncomplete
			}
			rawPods["Pod/"+ns+"/"+instance.Pod] = false
		}
	}
	for _, object := range api.objects {
		key := object.Kind + "/" + object.Namespace + "/" + object.Name
		if objects[key].UID != "" {
			return ErrSourceWriterObservationIncomplete
		}
		objects[key] = object
	}
	for key, uid := range want {
		object, exists := objects[key]
		if !exists || object.UID != uid {
			return ErrSourceWriterObservationIncomplete
		}
		if key != controller && !stoppedRoots[key] {
			if object.Replicas == 0 {
				return c.ErrSourceRecoveryStoppedWitnessRequired
			}
			if object.Replicas < 0 || object.Ready != object.Replicas || object.ObservedGeneration != object.Generation {
				return ErrSourceWriterObservationIncomplete
			}
		}
	}
	for key, object := range objects {
		switch object.Kind {
		case "PersistentVolume", "PersistentVolumeClaim":
			continue
		case "Deployment":
			if want[key] == "" {
				return ErrSourceWriterObservationIncomplete
			}
		case "ReplicaSet", "Pod":
			root, err := observedWriterRoot(object, objects)
			if _, raw := rawPods[key]; raw && len(object.Owners) == 0 {
				root, err = key, nil
			}
			if err != nil || want[root] == "" && root != key {
				return ErrSourceWriterObservationIncomplete
			}
			if root == key {
				if _, raw := rawPods[key]; !raw {
					return ErrSourceWriterObservationIncomplete
				}
			}
			if stoppedRoots[root] && (object.Kind == "Pod" || object.Replicas != 0) {
				return ErrSourceWriterObservationIncomplete
			}
			if object.Kind == "Pod" {
				if root != controller && !object.Running {
					return ErrSourceWriterObservationIncomplete
				}
				if _, raw := rawPods[key]; raw {
					rawPods[key] = true
				}
				podCounts[root]++
				for _, claim := range object.Claims {
					if objects["PersistentVolumeClaim/"+ns+"/"+claim].UID == "" {
						return ErrSourceWriterObservationIncomplete
					}
				}
			}
		default:
			return ErrSourceWriterObservationIncomplete
		}
	}
	for key := range want {
		if key != controller && podCounts[key] != objects[key].Replicas {
			return ErrSourceWriterObservationIncomplete
		}
	}
	for _, found := range rawPods {
		if !found {
			return ErrSourceWriterObservationIncomplete
		}
	}
	return nil
}

func observedWriterRoot(object observedWriterAPIObject, objects map[string]observedWriterAPIObject) (string, error) {
	for depth := 0; depth < 4; depth++ {
		key := object.Kind + "/" + object.Namespace + "/" + object.Name
		if object.Kind == "Deployment" {
			return key, nil
		}
		var owner *metav1.OwnerReference
		for i := range object.Owners {
			ref := &object.Owners[i]
			if ref.Controller != nil && *ref.Controller {
				if owner != nil {
					return "", ErrSourceWriterObservationIncomplete
				}
				owner = ref
			}
		}
		if owner == nil {
			return key, nil
		}
		parent, exists := objects[owner.Kind+"/"+object.Namespace+"/"+owner.Name]
		if !exists || parent.UID != string(owner.UID) {
			return "", ErrSourceWriterObservationIncomplete
		}
		object = parent
	}
	return "", ErrSourceWriterObservationIncomplete
}
