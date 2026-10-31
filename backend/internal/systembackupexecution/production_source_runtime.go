package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strconv"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type productionRuntimeRecord struct {
	ID, Digest string
	Spec       b.RuntimeWriterSpec
	Stopped    bool
}

func (x *originalSourceMetadataAuthority) runtimeMetadata(ctx context.Context, source b.SourceInventory, writers []b.FrozenWriter) ([]productionRuntimeRecord, error) {
	gate := x.owner.Gate.Authority
	tx, err := gate.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, d.ErrNotReady
	}
	defer tx.Rollback()
	guard, err := gate.Bind(ctx, tx, x.input.Authority)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT writer_id,spec_json,stopped_sha256 FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? ORDER BY instance_id", x.input.Authority.TaskPublicID, x.input.Authority.AttemptNo)
	if err != nil {
		return nil, d.ErrNotReady
	}
	instances := map[int]b.InstanceIdentity{}
	for _, instance := range source.Instances {
		instances[instance.ID] = instance
	}
	originals := map[string]b.FrozenWriter{}
	for _, writer := range writers {
		originals[writer.ID] = writer
	}
	records := []productionRuntimeRecord{}
	for rows.Next() {
		var record productionRuntimeRecord
		var raw []byte
		var stopped sql.NullString
		if rows.Scan(&record.ID, &raw, &stopped) != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &record.Spec) != nil || len(records) >= 9998 {
			rows.Close()
			return nil, d.ErrNotReady
		}
		instance, exists := instances[record.Spec.Source.ID]
		if !exists || record.Spec.Source != instance || originals[record.ID].ID == "" {
			rows.Close()
			return nil, d.ErrNotReady
		}
		delete(instances, instance.ID)
		record.Digest = hash(raw)
		record.Stopped = stopped.Valid && formalCandidateDigest(stopped.String)
		records = append(records, record)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(instances) != 0 || guard.Recheck(ctx, tx) != nil {
		return nil, d.ErrNotReady
	}
	tx.Rollback()
	if x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	return records, nil
}

func (x *originalSourceMetadataAuthority) workspaceVolume(ctx context.Context) (corev1.Volume, *kube.MountIdentity, error) {
	s := x.service
	volume := corev1.Volume{Name: "source"}
	if s.Config.Workspace.NFS != nil {
		n := s.Config.Workspace.NFS
		volume.NFS = &corev1.NFSVolumeSource{Server: n.Server, Path: n.Export, ReadOnly: true}
		return volume, nil, nil
	}
	claim, err := x.owner.Client.CoreV1().PersistentVolumeClaims(s.Config.Namespace).Get(ctx, s.Config.Workspace.Claim, metav1.GetOptions{})
	if err != nil || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
		return volume, nil, d.ErrNotReady
	}
	pv, err := x.owner.Client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != claim.Namespace {
		return volume, nil, d.ErrNotReady
	}
	pinned := false
	for _, identity := range s.Config.Security.Volumes {
		if identity.Kind == "PersistentVolumeClaim" && identity.Name == claim.Name && identity.UID == string(claim.UID) && identity.PVName == pv.Name && identity.PVUID == string(pv.UID) && identity.SHA256 == kube.ContentHash(pv.Spec) {
			pinned = true
		}
	}
	if !pinned || x.Recheck(ctx) != nil {
		return volume, nil, d.ErrNotReady
	}
	volume.PersistentVolumeClaim = &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim.Name, ReadOnly: true}
	identity := &kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
	return volume, identity, nil
}

func (x *originalSourceMetadataAuthority) instanceMountMetadata(ctx context.Context, source b.SourceInventory, writers []b.FrozenWriter, sqlMetadata productionSQLSourceMetadata, skills worker.SkillObjectCaptureSpec, saved *productionCaptureMetadata) ([]productionInstanceMount, map[string]kube.MountIdentity, []productionRuntimeRecord, error) {
	fail := func() ([]productionInstanceMount, map[string]kube.MountIdentity, []productionRuntimeRecord, error) {
		return nil, nil, nil, d.ErrNotReady
	}
	if saved == nil && x.service.checkRuntimeWorkspace(ctx, x.owner.Client, source.Instances) != nil {
		return fail()
	}
	runtime, err := x.runtimeMetadata(ctx, source, writers)
	if err != nil {
		return fail()
	}
	volume, identity, err := x.workspaceVolume(ctx)
	if err != nil {
		return fail()
	}
	requirements, err := source.Skills.WorkspaceRequirements()
	if err != nil {
		return fail()
	}
	required := map[int]bool{}
	for _, id := range skills.WorkspaceRequiredBlobIDs {
		required[id] = true
	}
	byInstance := map[int]productionRuntimeRecord{}
	for _, record := range runtime {
		byInstance[record.Spec.Source.ID] = record
	}
	old := map[int]productionInstanceMount{}
	if saved != nil {
		for _, mount := range saved.Mounts {
			if mount.MountID != "workspace" || old[mount.InstanceID].InstanceID != 0 {
				return fail()
			}
			old[mount.InstanceID] = mount
		}
	}
	mounts := []productionInstanceMount{}
	identities := map[string]kube.MountIdentity{}
	for _, instance := range source.Instances {
		record, exists := byInstance[instance.ID]
		if !exists {
			return fail()
		}
		subPath, err := productionInstanceSubPath(x.service, instance)
		if err != nil {
			return fail()
		}
		var policy *worker.RuntimePolicy
		for _, candidate := range x.service.captureMaterials.Discovery.RuntimePolicies {
			if candidate.Runtime.Type != instance.Type || candidate.Runtime.Mode != instance.Mode || candidate.Runtime.Backend != instance.Backend || candidate.Runtime.Variant != instance.Variant || candidate.Runtime.OS != instance.OS {
				continue
			}
			matched := productionImageMatches(sqlMetadata.Images[instance.ID], candidate, x.service.captureMaterials.Discovery.RuntimeImageReferences)
			if saved != nil {
				previous, ok := old[instance.ID]
				if !ok || previous.SourceSpecSHA256 != record.Digest || previous.SourceImageReference != sqlMetadata.Images[instance.ID] || !reflect.DeepEqual(previous.Policy, candidate) {
					continue
				}
				matched = true
			}
			if matched {
				if policy != nil {
					return fail()
				}
				copy := candidate
				policy = &copy
			}
		}
		if policy == nil {
			return fail()
		}
		mount := productionInstanceMount{InstanceID: instance.ID, MountID: "workspace", Source: volume, SubPath: subPath, NodeName: x.service.Config.Workspace.Node, Policy: *policy, SourceImageReference: sqlMetadata.Images[instance.ID], SourceSpecSHA256: record.Digest}
		if workBuddyUIDSource(instance) {
			uid, ok := sqlMetadata.WorkBuddy[instance.ID]
			if !ok {
				return fail()
			}
			mount.WorkBuddy = &uid
		}
		selected := []sh.WorkspaceCaptureRequirement{}
		for _, requirement := range requirements {
			if requirement.InstanceID == instance.ID && required[requirement.BlobID] {
				selected = append(selected, requirement)
			}
		}
		if len(selected) > 0 {
			if instance.Type == "opencode" && instance.Mode == "pro" {
				return fail()
			}
			root, err := sh.WorkspaceSkillRoot(policy.Runtime, "")
			if err != nil {
				return fail()
			}
			workspace := &sh.WorkspaceCaptureSpec{Version: sh.WorkspaceCaptureVersion, InventorySHA256: source.Skills.SHA256(), InstanceID: instance.ID, MountID: "workspace", Runtime: policy.Runtime, WorkspaceLayout: policy.WorkspaceLayout, SkillRoot: root, Requirements: selected, MaxFiles: int64(x.service.Config.Workspace.MaxFiles), MaxBytes: x.service.Config.Workspace.MaxFileBytes, MaxProofBytes: 32 << 20}
			if workspace.Validate() != nil {
				return fail()
			}
			mount.Skills = workspace
		}
		mounts = append(mounts, mount)
		if identity != nil {
			identities["instance_"+strconv.Itoa(instance.ID)+"_workspace"] = *identity
		}
	}
	if saved != nil && len(old) != len(mounts) {
		return fail()
	}
	if x.Recheck(ctx) != nil {
		return fail()
	}
	return mounts, identities, runtime, nil
}
