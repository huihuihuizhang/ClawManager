package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
)

const SkillObjectsPart = "skills_objects"

type SkillObjectsModuleConfig struct {
	Revision string
	Source   SourceInventory
	Objects  CapturePartRequest
}

// Required Skill package domain, using one shared B SQL dependency. This pure
// registration grants no source permission. Unpackaged blobs remain closed
// until the original workspace-proof module is wired; they cannot be marked
// complete by an empty object archive or a fabricated TeamID.
func NewSkillObjectsModule(cfg SkillObjectsModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(cfg)
	if err != nil || len(raw) > 16<<20 {
		return zero, d.ErrNotReady
	}
	var frozen SkillObjectsModuleConfig
	if json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	cfg = frozen
	if cfg.Source.Skills == nil || cfg.Source.Database == "" || cfg.Source.ServerUUID == "" || cfg.Revision == "" || len(cfg.Revision) > 128 || !utf8.ValidString(cfg.Revision) || strings.ContainsAny(cfg.Revision, "\x00\r\n") {
		return zero, d.ErrNotReady
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range cfg.Source.Users {
		if id <= 0 || users[id] {
			return zero, d.ErrNotReady
		}
		users[id] = true
	}
	for _, instance := range cfg.Source.Instances {
		if instance.ID <= 0 || owners[instance.ID] != 0 || !users[instance.UserID] {
			return zero, d.ErrNotReady
		}
		owners[instance.ID] = instance.UserID
	}
	if cfg.Source.Skills.Validate(users, owners) != nil {
		return zero, d.ErrNotReady
	}
	r := cfg.Objects
	s := r.Invocation.Request.SkillObjects
	if r.Part != SkillObjectsPart || r.Category != "skill_hub" || r.Invocation.Request.Operation != "capture-skill-objects" || s == nil || s.InventorySHA256 != cfg.Source.Skills.SHA256() || r.Workload.FormalMaterials == nil || r.Invocation.FormalCapture == nil || r.Invocation.ProviderKey == nil || !worker.ValidateRecordedInvocation(r.Invocation) || len(s.WorkspaceRequiredBlobIDs) != 0 || len(s.Blobs) != len(cfg.Source.Skills.Blobs) {
		return zero, d.ErrNotReady
	}
	blobs := map[int]worker.SkillObjectBlobRef{}
	for _, blob := range s.Blobs {
		if blobs[blob.ID].ID != 0 {
			return zero, d.ErrNotReady
		}
		blobs[blob.ID] = blob
	}
	for _, blob := range cfg.Source.Skills.Blobs {
		actual := blobs[blob.ID]
		if actual.ID != blob.ID || actual.ObjectKey != blob.ObjectKey || actual.SizeBytes != blob.SizeBytes || blob.ObjectKey == "" {
			return zero, d.ErrNotReady
		}
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: "skill_hub", Owner: "D", Revision: cfg.Revision, Required: true, Parts: []CaptureModulePart{{SkillObjectsPart, "skill_hub", "object_storage", "capture-skill-objects"}}, Requires: []CaptureModuleDependency{{Part: UsersInstancesDatabasePart, Owner: "B", RequestedPart: "mysql", Operation: "capture-database"}}}}
	sourceRaw, _ := json.Marshal(cfg.Source)
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		actual, _ := json.Marshal(input.Source)
		if string(actual) != string(sourceRaw) || len(input.Parts) != 1 {
			return nil, d.ErrNotReady
		}
		selection := input.Parts[0]
		if selection.Part != SkillObjectsPart || selection.Operation != "capture-skill-objects" || selection.Category != "skill_hub" || r.Invocation.Request.Binding.BackupID != input.Input.Authority.TaskPublicID || r.Invocation.Request.Binding.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || r.Invocation.Request.Binding.Path != SkillObjectsPart || r.Invocation.Request.Binding.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) || r.Invocation.ProviderKey.Request.Context.PartIndex != strconv.FormatUint(uint64(selection.PartIndex), 10) {
			return nil, d.ErrNotReady
		}
		raw, _ := json.Marshal(r)
		var copy CapturePartRequest
		if json.Unmarshal(raw, &copy) != nil {
			return nil, d.ErrNotReady
		}
		copy.Invocation.Request.Binding.PartIndex = selection.PartIndex
		return []CapturePartRequest{copy}, nil
	}
	return registration, nil
}

// WithSkillCaptureInventory installs the concrete reader, not a supplied DTO.
// The discovery owner authenticates the same transaction on both sides.
func WithSkillCaptureInventory(source LinuxProfileConfig) LinuxProfileConfig {
	source.ReadSkills = func(ctx context.Context, tx *sql.Tx, inv SourceInventory) (*sh.CaptureInventory, error) {
		users, owners := map[int]bool{}, map[int]int{}
		for _, id := range inv.Users {
			users[id] = true
		}
		for _, instance := range inv.Instances {
			owners[instance.ID] = instance.UserID
		}
		actual, err := domain.ReadSkillCaptureInventory(ctx, tx, users, owners)
		if err != nil {
			return nil, err
		}
		return &actual, nil
	}
	return source
}
