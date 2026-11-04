package systembackupcontroller

import (
	"encoding/json"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
)

type sourceRecoverySemanticPod struct {
	Namespace, Name, UID, Node, NodeUID, ResourceVersion, SpecSHA256 string
	Containers                                                       []string
	Volumes                                                          []struct{ Name, Kind, Claim, ClaimUID, PV, PVUID, PVSpecSHA256, NFSServer, NFSExport string }
}

type sourceRecoverySemanticFacts struct {
	Version, Kind string
	Runtime       *SourceRecoveryRuntime
	Recovered     []sourceRecoverySemanticPod
}

// Pure verification of the complete historical writer set. All comparisons use
// the already authenticated ORIGINAL source/checkpoints and immutable staged
// observations; this is never a fresh physical probe or an authority callback.
func (p *PreparedSourceRecovery) validateProducerLeaves() error {
	var source b.SourceInventory
	var metadata struct {
		Mounts []struct {
			InstanceID                int
			CurrentStoppedPro         json.RawMessage
			MountID, SourceSpecSHA256 string
		}
		PlatformMounts []struct {
			WriterID, Namespace, DeploymentUID, OriginalSpecSHA256 string
			Source                                                 corev1.Volume
			Claim                                                  *kube.MountIdentity
		}
	}
	if json.Unmarshal(p.desc.Source, &source) != nil || json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		return ErrSourceRecoveryProofRequired
	}
	instances := map[int]b.InstanceIdentity{}
	for _, instance := range source.Instances {
		if instances[instance.ID].ID != 0 {
			return ErrSourceRecoveryProofRequired
		}
		instances[instance.ID] = instance
	}
	for i, writer := range sourceRecoverySorted(p.desc.Writers) {
		var leaf sourceRecoveryLeaf
		if json.Unmarshal(p.entries[i+1].Payload, &leaf) != nil {
			return ErrSourceRecoveryProofRequired
		}
		if leaf.SourceRecoveryObservation.Scope == "registered_application_mutation_lease_boundary" {
			if writer.Original.UID != p.gate.Authority.ApplicationScope+"/"+writer.ID || writer.Original.Generation != int64(p.a.ConfigVersion) || writer.Original.Checkpoint != recordHash([]byte(p.gate.Authority.ApplicationScope+"/"+writer.ID+"/"+p.a.ConfigSHA256)) {
				return ErrSourceRecoveryProofRequired
			}
			continue
		}
		if leaf.SourceRecoveryObservation.Scope == MinIOReadServiceRecoveryScope {
			if p.validateMinIOReadServiceLeaf(writer, leaf, source) != nil {
				return ErrSourceRecoveryProofRequired
			}
			continue
		}
		if leaf.SourceRecoveryObservation.Scope == RedisReadServiceRecoveryScope {
			if p.validateRedisReadServiceLeaf(writer, leaf, source) != nil {
				return ErrSourceRecoveryProofRequired
			}
			continue
		}
		if leaf.SourceRecoveryObservation.Scope == sharedTaskRecoveryScope {
			if validateSharedTaskRecoveryLeaf(p.a, writer, leaf, instances) != nil {
				return ErrSourceRecoveryProofRequired
			}
			continue
		}
		if !writer.Original.Running {
			var stoppedFacts struct{ Runtime *SourceRecoveryRuntime }
			if json.Unmarshal(leaf.Facts, &stoppedFacts) != nil || stoppedFacts.Runtime == nil {
				return ErrSourceRecoveryStoppedWitnessRequired
			}
			materials := []json.RawMessage{}
			for _, mount := range metadata.Mounts {
				if mount.InstanceID == stoppedFacts.Runtime.Spec.Source.ID && mount.SourceSpecSHA256 == stoppedFacts.Runtime.SpecSHA256 && mount.MountID == "workspace" && len(mount.CurrentStoppedPro) > 0 {
					materials = append(materials, mount.CurrentStoppedPro)
				}
			}
			if p.validateStoppedProLeaf(writer, leaf, instances, materials) != nil {
				return ErrSourceRecoveryStoppedWitnessRequired
			}
			continue
		}
		var facts sourceRecoverySemanticFacts
		if json.Unmarshal(leaf.Facts, &facts) != nil || facts.Version != "source-recovery-physical-observation.v1" || len(facts.Recovered) == 0 {
			return ErrSourceRecoveryProofRequired
		}
		var cp struct {
			Version, Namespace, Name, SpecSHA256 string
			Replicas                             int32
			Process                              quiesce.PodIdentity
			Pods                                 []quiesce.PodIdentity
		}
		if facts.Kind != "gateway" && json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil {
			return ErrSourceRecoveryProofRequired
		}
		originalPods := cp.Pods
		if cp.Process.UID != "" {
			originalPods = []quiesce.PodIdentity{cp.Process}
		}
		if facts.Runtime != nil {
			r := facts.Runtime
			rawSpec, err := json.Marshal(r.Spec)
			if err != nil || recordHash(rawSpec) != r.SpecSHA256 {
				return ErrSourceRecoveryProofRequired
			}
			instance, exists := instances[r.Spec.Source.ID]
			if !exists || r.Spec.Source != instance || runtimeWriterID(r.Spec) != writer.ID || r.Spec.Kind != facts.Kind {
				return ErrSourceRecoveryProofRequired
			}
			delete(instances, instance.ID)
			pins := 0
			for _, mount := range metadata.Mounts {
				if mount.InstanceID == instance.ID && mount.MountID == "workspace" && mount.SourceSpecSHA256 == r.SpecSHA256 {
					pins++
				}
			}
			if pins != 1 {
				return ErrSourceRecoveryProofRequired
			}
			var control struct {
				Spec               b.RuntimeWriterSpec
				Completed, Claimed bool
				Resumed            json.RawMessage
			}
			var actualSource b.InstanceIdentity
			if json.Unmarshal(r.ControlRow, &control) != nil || !control.Completed || !sourceRecoveryEqual(control.Spec, r.Spec) || !sourceRecoveryEqual(control.Resumed, r.Resumed) || json.Unmarshal(r.SourceRow, &actualSource) != nil {
				return ErrSourceRecoveryProofRequired
			}
			want := instance
			switch facts.Kind {
			case "deployment":
				var resumed deploymentResume
				if json.Unmarshal(r.Resumed, &resumed) != nil || len(facts.Recovered) != 1 || facts.Recovered[0].Namespace != r.Spec.Source.Namespace || facts.Recovered[0].Name != resumed.PodName || facts.Recovered[0].UID != resumed.PodUID {
					return ErrSourceRecoveryProofRequired
				}
				want.Pod = resumed.PodName
			case "pod", "gateway":
				var resumed b.RestartObservation
				if json.Unmarshal(r.Resumed, &resumed) != nil || len(facts.Recovered) != 1 || facts.Recovered[0].UID != resumed.PodUID || facts.Recovered[0].Namespace != r.Spec.RuntimeNamespace() || facts.Recovered[0].Name != r.Spec.RuntimePod() {
					return ErrSourceRecoveryProofRequired
				}
				if facts.Kind == "gateway" {
					want.Generation = r.Spec.ResumeGeneration
					var binding gatewayBindingRow
					if !control.Claimed || r.GatewayRequest == nil || r.GatewayPID <= 0 || json.Unmarshal(r.BindingRow, &binding) != nil || !bindingMatchesSource(binding, want, r.Spec.RuntimeNamespace()) || binding.PID != r.GatewayPID || binding.UID != r.Spec.UID || binding.Endpoint != r.Spec.Endpoint || binding.ID != r.Spec.Runtime.RuntimePodID {
						return ErrSourceRecoveryProofRequired
					}
				}
			default:
				return ErrSourceRecoveryProofRequired
			}
			if actualSource != want {
				return ErrSourceRecoveryProofRequired
			}
		} else {
			if facts.Kind != "deployment" || cp.Version != "deployment-quiesce.v1" || writer.ID != "deployment/"+cp.Namespace+"/"+cp.Name || len(facts.Recovered) != int(cp.Replicas) {
				return ErrSourceRecoveryProofRequired
			}
			for _, pod := range facts.Recovered {
				want := map[string]bool{}
				for _, pin := range metadata.PlatformMounts {
					if pin.WriterID != writer.ID {
						continue
					}
					if pin.Namespace != cp.Namespace || pin.DeploymentUID != writer.Original.UID || pin.OriginalSpecSHA256 != cp.SpecSHA256 || want[pin.Source.Name] {
						return ErrSourceRecoveryProofRequired
					}
					want[pin.Source.Name] = true
					found := false
					for _, volume := range pod.Volumes {
						if volume.Name != pin.Source.Name {
							continue
						}
						if pin.Claim != nil {
							found = volume.Kind == "PersistentVolumeClaim" && volume.Claim == pin.Claim.Name && volume.ClaimUID == pin.Claim.UID && volume.PV == pin.Claim.PVName && volume.PVUID == pin.Claim.PVUID && volume.PVSpecSHA256 == pin.Claim.SHA256
						}
						if pin.Source.NFS != nil {
							found = volume.Kind == "NFS" && volume.NFSServer == pin.Source.NFS.Server && volume.NFSExport == pin.Source.NFS.Path
						}
					}
					if !found {
						return ErrSourceRecoveryProofRequired
					}
				}
				if len(want) != len(pod.Volumes) {
					return ErrSourceRecoveryProofRequired
				}
			}
		}
		if facts.Kind != "gateway" {
			want := map[string]bool{}
			for _, pod := range originalPods {
				if pod.UID == "" || want[pod.UID] {
					return ErrSourceRecoveryProofRequired
				}
				want[pod.UID] = true
			}
			seen := map[string]bool{}
			for _, ref := range leaf.References {
				if ref.Kind != "runtime_stop" {
					continue
				}
				if !want[ref.Identity] || seen[ref.Identity] {
					return ErrSourceRecoveryProofRequired
				}
				seen[ref.Identity] = true
			}
			if len(want) == 0 || len(want) != len(seen) {
				return ErrSourceRecoveryProofRequired
			}
			old := map[string]bool{}
			for _, pod := range originalPods {
				for _, id := range pod.Containers {
					old[id] = true
				}
			}
			for _, pod := range facts.Recovered {
				for _, id := range pod.Containers {
					if old[id] {
						return ErrSourceRecoveryProofRequired
					}
				}
			}
		}
		seenPods := map[string]bool{}
		for _, pod := range facts.Recovered {
			if pod.UID == "" || seenPods[pod.UID] || pod.Namespace == "" || pod.Name == "" || pod.Node == "" || pod.NodeUID == "" || pod.ResourceVersion == "" || !executionHash.MatchString(pod.SpecSHA256) || len(pod.Containers) == 0 {
				return ErrSourceRecoveryProofRequired
			}
			seenPods[pod.UID] = true
		}
	}
	if len(instances) != 0 {
		return ErrSourceRecoveryProofRequired
	}
	return nil
}
