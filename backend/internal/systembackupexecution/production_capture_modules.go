package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	sh "clawreef/internal/systembackupskillhub"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

const productionCaptureMetadataVersion = "original-six-part-source-metadata.v1"

// These are independently observed SOURCE coordinates, never prepared Job
// requests. They cannot contain a task claim, provider permit or bearer key.
type productionCaptureMetadata struct {
	Version               string
	SQLSchema             domain.BusinessCaptureSchema
	ControlEvidence       ce.CaptureLocator
	MountIdentities       map[string]kube.MountIdentity   `json:",omitempty"`
	FormalMountIdentities map[string][]kube.MountIdentity `json:",omitempty"`
	Mounts                []productionInstanceMount
	Skills                worker.SkillObjectCaptureSpec
	Redis                 c.RedisCapturePolicy
	Deployment, Secrets   worker.ResourceCaptureSpec
	PublicationFacts      *productionPublicationSourceFacts `json:",omitempty"`
}

type productionInstanceMount struct {
	InstanceID                             int
	MountID, SubPath, NodeName             string
	Source                                 corev1.Volume
	Policy                                 worker.RuntimePolicy
	Skills                                 *sh.WorkspaceCaptureSpec
	WorkBuddy                              *domain.WorkBuddyUIDIdentity
	SourceImageReference, SourceSpecSHA256 string
}

type productionPartDraft struct {
	module, part, category, operation string
	request                           b.CapturePartRequest
}

// The production module factory uses all six original constructors and
// ONE shared SQL export. This function performs no I/O or resource mutation.
func productionCaptureModules(in d.Input, source b.SourceInventory, until time.Time, writers []b.FrozenWriter, operations map[string]productionCaptureOperation, revision string) (*b.CaptureModules, error) {
	if source.Teams == nil || source.Skills == nil || source.TeamFacts == nil || !source.TeamFacts.MatchesInventory(*source.Teams) || len(source.CaptureMetadata) > 8<<20 || revision == "" || len(writers) == 0 {
		return nil, d.ErrNotReady
	}
	var metadata productionCaptureMetadata
	decoder := json.NewDecoder(bytes.NewReader(source.CaptureMetadata))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || decoder.Decode(new(any)) != io.EOF || metadata.Version != productionCaptureMetadataVersion || len(metadata.Mounts) > 9996 || metadata.ControlEvidence.Version != "system-backup-control-evidence-source.v1" || metadata.ControlEvidence.Finalization != nil || metadata.ControlEvidence.Validate() != nil || metadata.SQLSchema.PolicySHA256 != domain.BusinessCapturePolicySHA256() {
		return nil, d.ErrNotReady
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || !bytes.Equal(canonical, source.CaptureMetadata) {
		return nil, d.ErrNotReady
	}
	writers = append([]b.FrozenWriter{}, writers...)
	sort.Slice(writers, func(i, j int) bool { return writers[i].ID < writers[j].ID })
	for n, original := range writers {
		if original.ID == "" || original.Original.UID == "" || original.Original.Generation < 1 || (n > 0 && writers[n-1].ID == original.ID) {
			return nil, d.ErrNotReady
		}
	}
	point, err := productionModuleContext(in, source, until, writers, "")
	if err != nil {
		return nil, err
	}
	var drafts []productionPartDraft
	add := func(module, part, category, operation string, prepare func(*b.CapturePartRequest) error) error {
		template, exists := operations[operation]
		if !exists {
			return d.ErrNotReady
		}
		raw, err := json.Marshal(template)
		var frozen productionCaptureOperation
		if err != nil || len(raw) > 2<<20 || json.Unmarshal(raw, &frozen) != nil {
			return d.ErrNotReady
		}
		r := b.CapturePartRequest{Part: part, Category: category, Generation: 1, JobUnitKey: part, Invocation: worker.Invocation{Request: frozen.Request, FormalCapture: &frozen.Formal, ProviderKey: &frozen.Provider, StagingPath: "/staging"}, Workload: frozen.Workload}
		r.Invocation.Request.Version, r.Invocation.Request.Operation = worker.Version, operation
		r.Invocation.Request.Deadline = until
		r.Invocation.Request.Resources, r.Invocation.Request.Teams, r.Invocation.Request.SkillObjects, r.Invocation.Request.SkillWorkspace = nil, nil, nil, nil
		r.Invocation.Request.ControlEvidence, r.Invocation.Request.SourceRedis = nil, nil
		r.Invocation.Request.RuntimePolicy, r.Invocation.Request.WorkBuddyIdentity = nil, nil
		if operation != "capture-database" {
			r.Invocation.Request.Database = nil
		}
		if r.Invocation.FormalCapture.PermitDelivery == nil || r.Workload.FormalMaterials == nil || r.Invocation.ProviderKey.Operation != k.Generate {
			return d.ErrNotReady
		}
		if err := prepare(&r); err != nil {
			return err
		}
		drafts = append(drafts, productionPartDraft{module, part, category, operation, r})
		return nil
	}
	if add("users_instances", b.UsersInstancesDatabasePart, "users_instances", "capture-database", func(r *b.CapturePartRequest) error {
		if r.Invocation.Request.Database == nil {
			return d.ErrNotReady
		}
		r.Invocation.Request.Database.SourceScope = domain.BusinessTableSourceScope
		if metadata.SQLSchema.Validate() != nil {
			return d.ErrNotReady
		}
		r.Invocation.Request.Database.CaptureSchema = &metadata.SQLSchema
		return nil
	}) != nil {
		return nil, d.ErrNotReady
	}
	for _, part := range []string{ce.Part, ce.ProofPart} {
		if add(ce.Part, part, ce.Part, ce.Operation, func(r *b.CapturePartRequest) error {
			r.Invocation.Request.ControlEvidence = &metadata.ControlEvidence
			r.Invocation.Request.MaxFiles, r.Invocation.Request.MaxFileBytes = 0, 0
			r.Invocation.Request.MaxArchiveBytes, r.Invocation.Request.MaxCompressedBytes = ce.MaxBytes, ce.MaxBytes
			if part == ce.ProofPart {
				r.Invocation.Request.MaxArchiveBytes, r.Invocation.Request.MaxCompressedBytes = ce.MaxProofBytes, ce.MaxProofBytes
			}
			return nil
		}) != nil {
			return nil, d.ErrNotReady
		}
	}
	for _, mount := range metadata.Mounts {
		mount := mount
		var instance b.InstanceIdentity
		for _, original := range source.Instances {
			if original.ID == mount.InstanceID {
				instance = original
				break
			}
		}
		if instance.ID == 0 || mount.Policy.Runtime.Type != instance.Type || mount.Policy.Runtime.Mode != instance.Mode || mount.Policy.Runtime.Backend != instance.Backend || mount.Policy.Runtime.Variant != instance.Variant || mount.Policy.Runtime.OS != instance.OS {
			return nil, d.ErrNotReady
		}
		part := "instance_" + strconv.Itoa(mount.InstanceID) + "_" + mount.MountID
		if add("users_instances", part, "instances", "capture-workspace", func(r *b.CapturePartRequest) error {
			r.Invocation.WorkspacePath = "/workspace"
			r.Invocation.Request.RuntimePolicy = &mount.Policy
			r.Invocation.Request.SkillWorkspace = mount.Skills
			r.Workload.Source, r.Workload.SourceSubPath, r.Workload.NodeName = mount.Source, mount.SubPath, mount.NodeName
			if workBuddyUIDSource(instance) {
				if mount.WorkBuddy == nil || mount.WorkBuddy.Schema != 1 || mount.WorkBuddy.InstanceID != instance.ID || mount.WorkBuddy.UserID != instance.UserID || mount.WorkBuddy.UID < 10000 || mount.WorkBuddy.UID > 65533 || mount.WorkBuddy.GID != mount.WorkBuddy.UID {
					return d.ErrNotReady
				}
				r.Invocation.Request.WorkBuddyIdentity = mount.WorkBuddy
			} else if mount.WorkBuddy != nil {
				return d.ErrNotReady
			}
			return nil
		}) != nil {
			return nil, d.ErrNotReady
		}
	}
	for _, mount := range source.Teams.Mounts {
		mount := mount
		if add("teams", "team_"+strconv.Itoa(mount.TeamID)+"_workspace", "teams", "capture-workspace", func(r *b.CapturePartRequest) error {
			r.Invocation.WorkspacePath = "/workspace"
			r.Workload.Source = corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: mount.PVC, ReadOnly: true}}}
			r.Workload.SourceSubPath = ""
			return nil
		}) != nil {
			return nil, d.ErrNotReady
		}
	}
	if add(b.SourceRedisPart, b.SourceRedisPart, "source", "capture-source-redis", func(r *b.CapturePartRequest) error {
		r.Invocation.Request.SourceRedis = &metadata.Redis
		return nil
	}) != nil {
		return nil, d.ErrNotReady
	}
	if len(source.Teams.Objects) > 0 {
		if add("teams", "teams_objects", "teams", "capture-team-objects", func(r *b.CapturePartRequest) error {
			r.Invocation.Request.Teams = &worker.TeamCaptureSpec{InventorySHA256: source.Teams.SHA256(), Objects: source.Teams.Objects, MaxItems: 10000}
			return nil
		}) != nil {
			return nil, d.ErrNotReady
		}
	}
	if add("skill_hub", b.SkillObjectsPart, "skill_hub", "capture-skill-objects", func(r *b.CapturePartRequest) error {
		r.Invocation.Request.SkillObjects = &metadata.Skills
		return nil
	}) != nil {
		return nil, d.ErrNotReady
	}
	for _, part := range []string{"deployment_resources", "secret_bundle"} {
		part := part
		if add("deployment_and_secrets", part, part, "capture-"+map[string]string{"deployment_resources": "deployment-resources", "secret_bundle": "secret-bundle"}[part], func(r *b.CapturePartRequest) error {
			spec := metadata.Deployment
			if part == "secret_bundle" {
				spec = metadata.Secrets
			}
			spec.OriginalWriters = []worker.ResourceWriterOriginal{}
			required := map[string]string{}
			for _, selection := range spec.Selections {
				if selection.Resource == "deployments" {
					required["deployment/"+spec.Namespace+"/"+selection.Name] = selection.UID
				}
			}
			for _, original := range writers {
				if uid, exists := required[original.ID]; exists {
					if uid != original.Original.UID {
						return d.ErrNotReady
					}
					spec.OriginalWriters = append(spec.OriginalWriters, worker.ResourceWriterOriginal{ID: original.ID, State: original.Original})
					delete(required, original.ID)
				}
			}
			if len(required) != 0 {
				return d.ErrNotReady
			}
			r.Invocation.Request.Resources = &spec
			return nil
		}) != nil {
			return nil, d.ErrNotReady
		}
	}
	// Same canonical module/part order as B's original catalog; every provider
	// context is bound to its actual GLOBAL part index before constructors freeze.
	sort.Slice(drafts, func(i, j int) bool {
		if drafts[i].module != drafts[j].module {
			return drafts[i].module < drafts[j].module
		}
		return drafts[i].part < drafts[j].part
	})
	byPart := map[string]b.CapturePartRequest{}
	for index, draft := range drafts {
		r := draft.request
		name := "capture-" + hash([]byte(in.Authority.TaskPublicID + "/" + strconv.FormatUint(in.Authority.AttemptNo, 10) + "/" + draft.part))[:40]
		binding := staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: strconv.FormatUint(in.Authority.AttemptNo, 10), Path: draft.part, PartIndex: uint32(index), CaptureContextHash: point.CaptureContextSHA256, EnvelopeID: "envelope-" + name}
		r.Invocation.Request.Binding = binding
		r.Invocation.Request.ArtifactName = name + ".enc"
		if draft.part == ce.Part {
			r.Invocation.Request.ArtifactName = ce.LogicalCipherName
		}
		if draft.part == ce.ProofPart {
			r.Invocation.Request.ArtifactName = ce.LogicalProofCipherName
		}
		r.Invocation.FormalCapture.EnvelopeName = name + ".envelope.json"
		r.Invocation.FormalCapture.SourceConfigSHA256 = ""
		if r.Invocation.Request.ControlEvidence != nil || r.Invocation.Request.SourceRedis != nil || r.Invocation.Request.Database != nil || r.Invocation.Request.Teams != nil || r.Invocation.Request.SkillObjects != nil {
			r.Invocation.FormalCapture.SourceConfigSHA256 = in.Authority.ConfigSHA256
		}
		r.Invocation.ProviderKey.Request.Context = w.KeyContext{InstallationID: in.Authority.InstallationID, BackupPublicID: binding.BackupID, AttemptNo: binding.Attempt, Phase: "capture", Part: binding.Path, PartIndex: strconv.Itoa(index), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}
		r.Workload.Identity.Name, r.Workload.Identity.Owner = name, in.Authority.TaskPublicID
		if r.Workload.WorkerControl == nil {
			return nil, d.ErrNotReady
		}
		r.Workload.WorkerControl.InvocationConfigMap = name + "-invocation"
		r.Workload.WorkerControl.IdentitySecret = name + "-identity"
		// Relative Job duration is an original signed template bound, never
		// recomputed from a later wall clock while rebuilding the same plan.
		// BuildCapturePart still refuses a duration beyond the original hold.
		if r.Workload.DeadlineSeconds < 1 || r.Workload.DeadlineSeconds > 3600 || byPart[r.Part].Part != "" {
			return nil, d.ErrNotReady
		}
		byPart[r.Part] = r
	}
	users := b.UsersInstancesModuleConfig{Revision: revision, Source: source, Database: byPart[b.UsersInstancesDatabasePart]}
	for _, mount := range metadata.Mounts {
		users.Workspaces = append(users.Workspaces, b.InstanceWorkspaceCapture{InstanceID: mount.InstanceID, MountID: mount.MountID, Request: byPart["instance_"+strconv.Itoa(mount.InstanceID)+"_"+mount.MountID]})
	}
	teams := b.TeamsModuleConfig{Revision: revision, Source: source, SharedWorkspaces: map[string]b.CapturePartRequest{}, Redis: map[string]b.CapturePartRequest{}, SharedRedisPart: b.SourceRedisPart, SharedRedis: &metadata.Redis}
	for _, mount := range source.Teams.Mounts {
		teams.SharedWorkspaces[mount.ID] = byPart["team_"+strconv.Itoa(mount.TeamID)+"_workspace"]
	}
	if r, exists := byPart["teams_objects"]; exists {
		teams.Objects = &r
	}
	skills := b.SkillObjectsModuleConfig{Revision: revision, Source: source, Objects: byPart[b.SkillObjectsPart], Workspaces: map[int]string{}}
	if len(metadata.Skills.WorkspaceRequiredBlobIDs) > 0 {
		requirements, err := source.Skills.WorkspaceRequirements()
		if err != nil {
			return nil, d.ErrNotReady
		}
		required := map[int]bool{}
		for _, id := range metadata.Skills.WorkspaceRequiredBlobIDs {
			required[id] = true
		}
		instances := map[int]bool{}
		for _, requirement := range requirements {
			if required[requirement.BlobID] {
				instances[requirement.InstanceID] = true
			}
		}
		for _, mount := range metadata.Mounts {
			if mount.MountID == "workspace" && instances[mount.InstanceID] {
				skills.Workspaces[mount.InstanceID] = "instance_" + strconv.Itoa(mount.InstanceID) + "_workspace"
			}
		}
	}
	constructors := []func() (b.CaptureModuleRegistration, error){func() (b.CaptureModuleRegistration, error) { return b.NewUsersInstancesModule(users) }, func() (b.CaptureModuleRegistration, error) { return b.NewTeamsModule(teams) }, func() (b.CaptureModuleRegistration, error) { return b.NewSkillObjectsModule(skills) }, func() (b.CaptureModuleRegistration, error) {
		return b.NewControlEvidenceModule(b.ControlEvidenceModuleConfig{Revision: revision, Sidecar: byPart[ce.Part], Proofs: byPart[ce.ProofPart]})
	}, func() (b.CaptureModuleRegistration, error) {
		return b.NewResourceCaptureModule(b.ResourceCaptureModuleConfig{Revision: revision, Deployment: byPart["deployment_resources"], Secrets: byPart["secret_bundle"]})
	}, func() (b.CaptureModuleRegistration, error) {
		return b.NewSourceRedisModule(b.SourceRedisModuleConfig{Revision: revision, Source: source, Request: byPart[b.SourceRedisPart]})
	}}
	construct := func() (*b.CaptureModules, error) {
		registrations := []b.CaptureModuleRegistration{}
		for index, constructor := range constructors {
			registration, err := constructor()
			if err != nil {
				return nil, fmt.Errorf("capture module %d: %w", index, err)
			}
			registrations = append(registrations, registration)
		}
		return b.NewCaptureModules(registrations, func(actual d.Input, inventory b.SourceInventory, hold time.Time, catalog string) (b.ModuleCaptureContext, error) {
			return productionModuleContext(actual, inventory, hold, writers, catalog)
		})
	}
	// Materialize through the ORIGINAL constructors first: notably SQL adds
	// its exact Teams/Skills projections. The complete Source stays unchanged.
	// Only the CE pair receives the derived policy before the final plan freezes.
	base, err := construct()
	if err != nil {
		return nil, err
	}
	parts, err := base.BuildParts(in, source, until)
	if err != nil {
		return nil, err
	}
	policy, err := productionFinalizationPolicy(point.CaptureContextSHA256, parts)
	if err != nil {
		return nil, err
	}
	seed, err := ce.RequireOwnedFinalization(metadata.ControlEvidence, policy)
	if err != nil {
		return nil, d.ErrNotReady
	}
	for _, name := range []string{ce.Part, ce.ProofPart} {
		request := byPart[name]
		request.Invocation.Request.ControlEvidence = &seed
		byPart[name] = request
	}
	return construct()
}

func workBuddyUIDSource(instance b.InstanceIdentity) bool {
	return b.RequiresWorkBuddyUIDIdentity(instance)
}

func productionModuleContext(in d.Input, source b.SourceInventory, until time.Time, writers []b.FrozenWriter, catalog string) (b.ModuleCaptureContext, error) {
	writers = append([]b.FrozenWriter{}, writers...)
	sort.Slice(writers, func(i, j int) bool { return writers[i].ID < writers[j].ID })
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > 16<<20 {
		return b.ModuleCaptureContext{}, d.ErrNotReady
	}
	a := in.Authority
	material, err := json.Marshal(struct {
		Installation, Task, Request, Config, Profile, Revision, Phase, Inventory string
		Version, Attempt                                                         uint64
		Until                                                                    time.Time
		Writers                                                                  []b.FrozenWriter
	}{a.InstallationID, a.TaskPublicID, a.RequestID, a.ConfigSHA256, in.ProfileID, in.ProfileRevision, a.Phase, hash(raw), a.ConfigVersion, a.AttemptNo, until, writers})
	if err != nil || len(material) > 16<<20 {
		return b.ModuleCaptureContext{}, d.ErrNotReady
	}
	return b.ModuleCaptureContext{InstallationID: a.InstallationID, TaskPublicID: a.TaskPublicID, ConfigVersion: a.ConfigVersion, AttemptNo: a.AttemptNo, Phase: a.Phase, ConfigSHA256: a.ConfigSHA256, ProfileID: in.ProfileID, ProfileRevision: in.ProfileRevision, InventorySHA256: hash(raw), CatalogSHA256: catalog, CaptureContextSHA256: hash(material), HoldUntil: until}, nil
}
