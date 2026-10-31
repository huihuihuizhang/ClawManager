package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

func (s *DeploymentService) productionInventory(ctx context.Context, in d.Input, discovery b.Discovery) error {
	if s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.supportsCapture(in) != nil {
		return d.ErrNotReady
	}
	var source b.SourceInventory
	if decodeMetadataCanonical(discovery.Source, &source) != nil || hash(discovery.Source) != discovery.SourceSHA256 || source.Database != s.Config.SourceDatabase || source.ServerUUID != s.Config.SourceServerUUID || source.TeamFacts == nil || source.Skills == nil {
		return d.ErrNotReady
	}
	if in.Authority.TaskType == "preflight" {
		if len(discovery.Parts) != 1 || discovery.Parts[0].Part != "source_inventory" || len(discovery.Writers) != 0 {
			return d.ErrNotReady
		}
		return s.validateRuntimeInventory(source)
	}
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.Version != productionCaptureMetadataVersion || metadata.SQLSchema.Validate() != nil || metadata.SQLSchema.PolicySHA256 != domain.BusinessCapturePolicySHA256() || metadata.ControlEvidence.Validate() != nil || source.Teams == nil || !source.TeamFacts.MatchesInventory(*source.Teams) || b.ValidateTeamsWriters(source, discovery.Writers) != nil {
		return d.ErrNotReady
	}
	type expectedPart struct{ module, part, operation string }
	expected := []expectedPart{{ce.Part, ce.Part, ce.Operation}, {ce.Part, ce.ProofPart, ce.Operation}, {"deployment_and_secrets", "deployment_resources", "capture-deployment-resources"}, {"deployment_and_secrets", "secret_bundle", "capture-secret-bundle"}, {"skill_hub", b.SkillObjectsPart, "capture-skill-objects"}, {b.SourceRedisPart, b.SourceRedisPart, "capture-source-redis"}, {"users_instances", b.UsersInstancesDatabasePart, "capture-database"}}
	instances := map[int]bool{}
	for _, instance := range source.Instances {
		instances[instance.ID] = false
	}
	for _, mount := range metadata.Mounts {
		if _, exists := instances[mount.InstanceID]; !exists || instances[mount.InstanceID] || mount.MountID != "workspace" {
			return d.ErrNotReady
		}
		instances[mount.InstanceID] = true
		expected = append(expected, expectedPart{"users_instances", "instance_" + strconv.Itoa(mount.InstanceID) + "_workspace", "capture-workspace"})
	}
	for _, covered := range instances {
		if !covered {
			return d.ErrNotReady
		}
	}
	for _, mount := range source.Teams.Mounts {
		expected = append(expected, expectedPart{"teams", "team_" + strconv.Itoa(mount.TeamID) + "_workspace", "capture-workspace"})
	}
	if len(source.Teams.Objects) > 0 {
		expected = append(expected, expectedPart{"teams", "teams_objects", "capture-team-objects"})
	}
	sort.Slice(expected, func(i, j int) bool {
		a, b := expected[i], expected[j]
		if a.module != b.module {
			return a.module < b.module
		}
		return a.part < b.part
	})
	if len(expected) != len(discovery.Parts) {
		return d.ErrNotReady
	}
	for index, part := range discovery.Parts {
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil || part.Part != expected[index].part || invocation.Request.Operation != expected[index].operation || invocation.Request.Binding.PartIndex != uint32(index) || invocation.ProviderKey == nil || invocation.ProviderKey.Request.Context.PartIndex != strconv.Itoa(index) {
			return d.ErrNotReady
		}
		if invocation.Request.Database != nil && (invocation.Request.Database.SourceScope != domain.BusinessTableSourceScope || invocation.Request.Database.CaptureSchema == nil || !reflect.DeepEqual(*invocation.Request.Database.CaptureSchema, metadata.SQLSchema) || invocation.Request.Database.TeamsInventory == nil || invocation.Request.Database.TeamsInventory.SHA256() != source.Teams.SHA256() || invocation.Request.Database.SkillsInventory == nil || invocation.Request.Database.SkillsInventory.SHA256() != source.Skills.SHA256()) {
			return d.ErrNotReady
		}
	}
	if err := validateProductionControlSeeds(in, source, metadata, discovery); err != nil {
		return err
	}
	platform := map[string]bool{}
	for _, writer := range s.Config.Writers {
		platform["deployment/"+writer.Namespace+"/"+writer.Name] = true
	}
	return s.runtimeInventory(ctx, in, discovery, platform)
}
