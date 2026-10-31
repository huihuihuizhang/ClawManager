package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *DeploymentService) freezeProductionSource(ctx context.Context, owner *PublicJobOwner, in d.Input, source b.SourceInventory, writers []b.FrozenWriter, saved *productionCaptureMetadata) (*team.Inventory, json.RawMessage, error) {
	if source.TeamFacts == nil || source.Skills == nil || len(writers) == 0 {
		return nil, nil, d.ErrNotReady
	}
	authority, err := s.sourceMetadataAuthority(ctx, owner, in)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, authority.until)
	defer cancel()
	sqlMetadata, err := authority.sqlMetadata(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	clients, err := authority.openClients(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer clients.Close()
	skills, err := authority.skillObjectMetadata(ctx, clients, source.Skills)
	if err != nil {
		return nil, nil, err
	}
	deployment, secrets, err := authority.resourceMetadata(ctx, clients)
	if err != nil {
		return nil, nil, err
	}
	mounts, mountIdentities, runtime, err := authority.instanceMountMetadata(ctx, source, writers, sqlMetadata, skills, saved)
	if err != nil {
		return nil, nil, err
	}
	mapping := team.AutomaticStorageMapping{RedisID: s.captureMaterials.Discovery.Redis.Policy.Source.ID, RedisServerID: s.captureMaterials.Discovery.Redis.ServerID, RedisDatabase: s.captureMaterials.Discovery.Redis.Policy.DB, Claims: []team.SharedClaimIdentity{}, Objects: []team.ObjectRef{}, Writers: []team.WriterBinding{}}
	for _, fact := range source.TeamFacts.Teams {
		if fact.PVC == "" {
			continue
		}
		if fact.Namespace != s.Config.Namespace {
			return nil, nil, d.ErrNotReady
		}
		claim, err := owner.Client.CoreV1().PersistentVolumeClaims(fact.Namespace).Get(ctx, fact.PVC, metav1.GetOptions{})
		if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
			return nil, nil, d.ErrNotReady
		}
		pv, err := owner.Client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != fact.Namespace || authority.Recheck(ctx) != nil {
			return nil, nil, d.ErrNotReady
		}
		mapping.Claims = append(mapping.Claims, team.SharedClaimIdentity{Namespace: fact.Namespace, PVC: fact.PVC, UID: string(claim.UID)})
		mountIdentities["team_"+strconv.Itoa(fact.ID)+"_workspace"] = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
	}
	frozen := map[string]b.FrozenWriter{}
	for _, writer := range writers {
		if frozen[writer.ID].ID != "" {
			return nil, nil, d.ErrNotReady
		}
		frozen[writer.ID] = writer
	}
	for id, units := range s.captureMaterials.Discovery.TeamPlatformUnits {
		original, exists := frozen[id]
		if !exists {
			return nil, nil, d.ErrNotReady
		}
		mapping.Writers = append(mapping.Writers, team.WriterBinding{ID: id, Kind: "platform", UID: original.Original.UID, Generation: original.Original.Generation, Running: original.Original.Running, Checkpoint: original.Original.Checkpoint, Units: append([]string{}, units...)})
	}
	required := map[int]bool{}
	for _, member := range source.TeamFacts.Members {
		if member.InstanceID != 0 {
			required[member.InstanceID] = true
		}
	}
	for _, record := range runtime {
		if !required[record.Spec.Source.ID] {
			continue
		}
		original, exists := frozen[record.ID]
		if !exists {
			return nil, nil, d.ErrNotReady
		}
		mapping.Writers = append(mapping.Writers, team.WriterBinding{ID: record.ID, Kind: record.Spec.Kind, UID: original.Original.UID, Generation: original.Original.Generation, Running: original.Original.Running, Checkpoint: original.Original.Checkpoint, InstanceID: record.Spec.Source.ID, Units: []string{}})
	}
	sort.Slice(mapping.Writers, func(i, j int) bool { return mapping.Writers[i].ID < mapping.Writers[j].ID })
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range source.Users {
		users[id] = true
	}
	for _, instance := range source.Instances {
		owners[instance.ID] = instance.UserID
	}
	teams, err := team.BindAutomaticStorage(ctx, *source.TeamFacts, mapping, users, owners)
	if err != nil {
		return nil, nil, d.ErrNotReady
	}
	source.Teams = teams
	if b.ValidateTeamsWriters(source, writers) != nil {
		return nil, nil, d.ErrNotReady
	}
	metadata := productionCaptureMetadata{Version: productionCaptureMetadataVersion, SQLSchema: sqlMetadata.Schema, Mounts: mounts, MountIdentities: mountIdentities, Skills: skills, Redis: s.captureMaterials.Discovery.Redis, Deployment: deployment, Secrets: secrets}
	metadata.FormalMountIdentities = map[string][]kube.MountIdentity{}
	for operation, original := range s.captureMaterials.Operations {
		metadata.FormalMountIdentities[operation] = append([]kube.MountIdentity{}, original.MountIdentities...)
	}
	if saved == nil {
		ref, err := authority.registerSourceExclusion(ctx, sqlMetadata)
		if err != nil {
			return nil, nil, err
		}
		metadata.ControlEvidence, err = s.PrepareControlEvidenceLocator(ctx, in, ref)
		if err != nil {
			return nil, nil, err
		}
	} else {
		if saved.ControlEvidence.Validate() != nil || saved.ControlEvidence.Expected.Backup != in.Authority.TaskPublicID || saved.ControlEvidence.Expected.Attempt != in.Authority.AttemptNo || saved.ControlEvidence.Expected.ConfigSHA256 != in.Authority.ConfigSHA256 {
			return nil, nil, d.ErrNotReady
		}
		if err := authority.checkControlLocator(ctx, saved.ControlEvidence); err != nil {
			return nil, nil, err
		}
		metadata.ControlEvidence = saved.ControlEvidence
	}
	if authority.Recheck(ctx) != nil {
		return nil, nil, d.ErrNotReady
	}
	raw, err := json.Marshal(metadata)
	if err != nil || len(raw) > 8<<20 {
		return nil, nil, d.ErrNotReady
	}
	return teams, raw, nil
}

func (x *originalSourceMetadataAuthority) checkControlLocator(ctx context.Context, locator ce.CaptureLocator) error {
	if locator.Validate() != nil || x.Recheck(ctx) != nil {
		return d.ErrNotReady
	}
	gate := x.owner.Gate.Authority
	tx, err := gate.DB.BeginTx(ctx, nil)
	if err != nil {
		return d.ErrNotReady
	}
	defer tx.Rollback()
	guard, err := gate.Bind(ctx, tx, x.input.Authority)
	if err != nil {
		return err
	}
	entries := make([]ce.RegisteredEvidence, 0, len(locator.Evidence))
	defer func() {
		for _, entry := range entries {
			clear(entry.Payload)
		}
	}()
	for _, ref := range locator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, locator.Expected.Scope, ref)
		if err != nil {
			return d.ErrNotReady
		}
		entries = append(entries, entry)
	}
	if guard.Recheck(ctx, tx) != nil {
		return d.ErrNotReady
	}
	tx.Rollback()
	prepared, err := ce.Rebuild(ctx, locator, entries)
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	if err != nil || !reflect.DeepEqual(prepared.Locator, locator) || x.Recheck(ctx) != nil {
		return d.ErrNotReady
	}
	return nil
}
