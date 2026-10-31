package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

func validProductionOperationMounts(operation productionCaptureOperation) bool {
	formal := operation.Workload.FormalMaterials
	if formal == nil || len(operation.MountIdentities) != len(formal.Inputs)+1 {
		return false
	}
	expected := map[string][2]string{"formal-mapping": {"ConfigMap", formal.ConfigMap}}
	for _, input := range formal.Inputs {
		if expected[input.Volume][0] != "" {
			return false
		}
		expected[input.Volume] = [2]string{input.Kind, input.Name}
	}
	for _, identity := range operation.MountIdentities {
		if expected[identity.Volume] != [2]string{identity.Kind, identity.Name} || identity.UID == "" || !formalCandidateDigest(identity.SHA256) || identity.PVName != "" || identity.PVUID != "" {
			return false
		}
		delete(expected, identity.Volume)
	}
	return len(expected) == 0
}

// Expected source/formal refs come from the SAME authenticated original plan,
// rather than a global volume-name map shared by unrelated part operations.
// This remains usable during recovery without new source/Generate authority.
func (o *PublicJobOwner) originalProductionMounts(ctx context.Context, a d.Authority, part b.JobPart) ([]kube.MountIdentity, bool, error) {
	if o.productionSource == nil {
		return nil, false, nil
	}
	in, _, discovery, err := o.input(ctx, a, false)
	if err != nil {
		in, _, discovery, err = o.input(ctx, a, true)
	}
	if err != nil {
		return nil, false, err
	}
	if in.Backup == nil || in.Backup.TaskPurpose != "acceptance" {
		return nil, false, nil
	}
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if json.Unmarshal(discovery.Source, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil {
		return nil, false, d.ErrNotReady
	}
	original, err := partFor(discovery, part.Intent.JobUnitKey)
	if err != nil || !reflect.DeepEqual(original, part) || hash(part.InvocationJSON) != part.InvocationSHA256 || hash(part.Intent.SpecJSON) != part.Intent.SpecSHA256 {
		return nil, false, d.ErrNotReady
	}
	refs, err := productionPartMounts(metadata, part)
	return refs, err == nil, err
}

// This pure projection is called only after originalProductionMounts has
// authenticated the sealed source and exact original part. It grants no read.
func productionPartMounts(metadata productionCaptureMetadata, part b.JobPart) ([]kube.MountIdentity, error) {
	var invocation worker.Invocation
	var job batchv1.Job
	if json.Unmarshal(part.InvocationJSON, &invocation) != nil || json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		return nil, d.ErrNotReady
	}
	refs, exists := metadata.FormalMountIdentities[invocation.Request.Operation]
	if !exists || len(refs) == 0 {
		return nil, d.ErrNotReady
	}
	out := append([]kube.MountIdentity{}, refs...)
	hasSource := false
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name != "workspace" {
			continue
		}
		if hasSource {
			return nil, d.ErrNotReady
		}
		hasSource = true
		if volume.PersistentVolumeClaim != nil {
			identity, exists := metadata.MountIdentities[part.Part]
			if !exists || identity.Volume != "workspace" || identity.Kind != "PersistentVolumeClaim" || identity.Name != volume.PersistentVolumeClaim.ClaimName || identity.UID == "" || identity.PVName == "" || identity.PVUID == "" || !formalCandidateDigest(identity.SHA256) {
				return nil, d.ErrNotReady
			}
			out = append(out, identity)
		} else if volume.NFS == nil {
			return nil, d.ErrNotReady
		}
	}
	seen := map[string]bool{}
	for _, identity := range out {
		if seen[identity.Volume] || identity.UID == "" || identity.Name == "" || !formalCandidateDigest(identity.SHA256) || identity.Volume != "workspace" && !strings.HasPrefix(identity.Volume, "formal-") {
			return nil, d.ErrNotReady
		}
		matched := false
		for _, volume := range job.Spec.Template.Spec.Volumes {
			if volume.Name != identity.Volume {
				continue
			}
			matched = identity.Kind == "ConfigMap" && volume.ConfigMap != nil && volume.ConfigMap.Name == identity.Name || identity.Kind == "Secret" && volume.Secret != nil && volume.Secret.SecretName == identity.Name || identity.Kind == "PersistentVolumeClaim" && volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == identity.Name
		}
		if !matched {
			return nil, d.ErrNotReady
		}
		seen[identity.Volume] = true
	}
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if strings.HasPrefix(volume.Name, "formal-") && !seen[volume.Name] {
			return nil, d.ErrNotReady
		}
	}
	return out, nil
}
