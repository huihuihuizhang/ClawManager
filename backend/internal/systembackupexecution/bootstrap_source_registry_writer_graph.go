package systembackupexecution

import (
	"strings"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
)

func (x *bootstrapSourceRegistryReader) checkWriterGraph(source b.SourceInventory, api *observedWriterAPI) error {
	if x == nil || x.config.RuntimeSources == nil || x.materials.Discovery == nil || api == nil || requireRunningSourceMetadata(source) != nil {
		return ErrSourceWriterObservationIncomplete
	}
	ns, p := x.config.Namespace, x.materials.Discovery
	controller := "Deployment/" + ns + "/" + p.ControllerDeployment
	want := map[string]string{controller: p.ControllerDeploymentUID}
	platformIDs := map[string]bool{}
	for _, ref := range x.config.Writers {
		platformIDs["deployment/"+ref.Namespace+"/"+ref.Name] = true
	}
	for id := range p.TeamPlatformUnits {
		if !strings.HasPrefix(id, "deployment/") || !platformIDs[id] {
			return ErrSourceWriterObservationIncomplete
		}
	}
	for _, refs := range [][]PlatformDeployment{x.config.Writers, x.config.RuntimeSources.Deployments} {
		for _, ref := range refs {
			key := "Deployment/" + ref.Namespace + "/" + ref.Name
			if ref.Namespace != ns || key == controller || ref.UID == "" || want[key] != "" && want[key] != ref.UID {
				return ErrSourceWriterObservationIncomplete
			}
			want[key] = ref.UID
		}
	}
	stoppedRoots, err := currentStoppedProGraphRoots(x.config, source, api, want)
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
