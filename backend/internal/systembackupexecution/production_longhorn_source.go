package systembackupexecution

import (
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/team"

	"clawreef/internal/systembackup/kube"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
)

// originalLonghornSource is covered by the original source metadata grant.
// It pins only existing objects and classes, with no task or hold authority.
type originalLonghornSource struct {
	Namespace, NamespaceUID         string
	Source                          kube.MountIdentity
	Handle                          string
	AccessMode                      corev1.PersistentVolumeAccessMode
	ProviderNamespace, ProviderUID  string
	SnapshotClass, SnapshotClassUID string
	SnapshotClassSHA256             string
	CloneClass, CloneClassUID       string
	CloneClassSHA256                string
}

func (s originalLonghornSource) pin() kube.LonghornSnapshotPin {
	return kube.LonghornSnapshotPin{Source: s.Source, NamespaceUID: s.NamespaceUID, AccessMode: s.AccessMode, SourceHandle: s.Handle,
		ProviderNamespace: s.ProviderNamespace, ProviderNamespaceUID: s.ProviderUID,
		Class: s.SnapshotClass, ClassUID: s.SnapshotClassUID, ClassSHA: s.SnapshotClassSHA256}
}

func (s originalLonghornSource) plan(a d.Authority, workerNamespace, workerUID string) plannedLonghornClone {
	material, _ := json.Marshal([]any{a.TaskPublicID, a.AttemptNo, s, workerNamespace, workerUID})
	id := hash(material)[:48]
	plan := plannedLonghornClone{Original: s, Snapshot: kube.Identity{Namespace: s.Namespace, Name: "sbk-cut-" + id, Owner: a.TaskPublicID},
		Target: kube.LonghornCaptureClone{Claim: kube.Identity{Namespace: workerNamespace, Name: "sbk-clone-" + id, Owner: a.TaskPublicID},
			NamespaceUID: workerUID, Class: s.CloneClass, ClassUID: s.CloneClassUID, ClassSHA256: s.CloneClassSHA256}}
	if s.Namespace != workerNamespace {
		plan.Target.Alias = kube.Identity{Namespace: workerNamespace, Name: "sbk-snapref-" + id, Owner: a.TaskPublicID}
	}
	return plan
}

func (x *originalSourceMetadataAuthority) freezeLonghornSources(ctx context.Context, mounts map[string]kube.MountIdentity, facts *team.SourceFacts) (map[string]plannedLonghornClone, error) {
	authored := x.service.captureMaterials.Discovery.LonghornSources
	if len(authored) == 0 {
		return nil, nil
	}
	out := make(map[string]plannedLonghornClone, len(authored))
	volumes := make(map[string]bool, len(authored))
	for part, source := range authored {
		if identity, ok := mounts[part]; !ok || identity != source.Source {
			return nil, d.ErrNotReady
		}
		plan := source.plan(x.input.Authority, x.owner.Namespace, x.owner.NamespaceUID)
		if source.Namespace != x.owner.Namespace && source.AccessMode != corev1.ReadWriteOnce {
			if err := verifyTenantTeamLonghornSource(ctx, x.owner.Client, x.service.Config, part, source, facts); err != nil {
				return nil, err
			}
		}
		if err := kube.VerifyLonghornCaptureSource(ctx, x.owner.Client, x.owner.Dynamic, source.pin(), source.Namespace, plan.Target); err != nil {
			return nil, err
		}
		out[part] = plan
		volumes[source.Source.PVUID] = true
	}
	for part, identity := range mounts {
		if _, covered := out[part]; volumes[identity.PVUID] && !covered {
			return nil, d.ErrNotReady
		}
	}
	if err := x.Recheck(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
