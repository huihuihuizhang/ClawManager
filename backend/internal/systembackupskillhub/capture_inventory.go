package systembackupskillhub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"sort"
	"strings"
)

const CaptureInventoryVersion = "skill-hub-capture-inventory.v1"

// These are explicit capture-plan projections, not JSON-marshaled business
// models. Full column values (including ManifestJSON/FindingsJSON) belong to
// the ONE raw SQL snapshot, not this identity/keyset projection.
type CaptureInventory struct {
	Version  string                  `json:"schema_version"`
	Tables   []CaptureTableKeys      `json:"tables"`
	Skills   []CaptureSkill          `json:"skills"`
	Blobs    []CaptureBlob           `json:"blobs"`
	Versions []CaptureVersion        `json:"versions"`
	Bindings []CaptureBinding        `json:"bindings"`
	Jobs     []CaptureMaterializeJob `json:"jobs"`
}
type CaptureTableKeys struct {
	Name, SchemaSHA256 string
	IDs                []int
}
type CaptureSkill struct{ ID, UserID, CurrentVersionID int }
type CaptureBlob struct {
	ID                     int
	ContentHash, ObjectKey string
	SizeBytes              int64
}
type CaptureVersion struct{ ID, SkillID, BlobID int }
type CaptureBinding struct {
	ID, InstanceID, SkillID, SkillVersionID int
	WorkspaceDir, ObservedHash              string
}
type CaptureMaterializeJob struct {
	ID, InstanceID, SkillID, BlobID int
	WorkspaceDir, ContentHash       string
}
type WorkspaceCaptureRequirement struct {
	BlobID, InstanceID, BindingID, JobID int
	RelativeDirectory, ContentMD5        string
}

func CaptureTableNames() []string {
	return []string{"skills", "skill_blobs", "skill_versions", "instance_skills", "skill_scan_results", "skill_package_materialize_jobs", "skill_hub_tags", "skill_hub_tag_assignments"}
}
func (c CaptureInventory) SHA256() string {
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func CloneCaptureInventory(c *CaptureInventory) *CaptureInventory {
	if c == nil {
		return nil
	}
	raw, err := json.Marshal(c)
	var out CaptureInventory
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return &out
}

func (c CaptureInventory) Validate(users map[int]bool, instanceOwners map[int]int) error {
	if c.Version != CaptureInventoryVersion || len(c.Tables) != 8 || len(c.Blobs) > 100000 || len(c.Bindings) > 100000 || len(c.Jobs) > 100000 {
		return ErrRows
	}
	wanted := map[string]bool{}
	for _, name := range CaptureTableNames() {
		wanted[name] = true
	}
	ids := map[string]map[int]bool{}
	for _, table := range c.Tables {
		if !wanted[table.Name] || ids[table.Name] != nil || !validSHA256(table.SchemaSHA256) || len(table.IDs) > 100000 {
			return ErrRows
		}
		ids[table.Name] = map[int]bool{}
		previous := 0
		for _, id := range table.IDs {
			if !validID(id) || id <= previous {
				return ErrRows
			}
			ids[table.Name][id] = true
			previous = id
		}
	}
	skills := map[int]CaptureSkill{}
	blobs := map[int]CaptureBlob{}
	versions := map[int]CaptureVersion{}
	for _, skill := range c.Skills {
		if !ids["skills"][skill.ID] || skills[skill.ID].ID != 0 || !users[skill.UserID] {
			return ErrRows
		}
		skills[skill.ID] = skill
	}
	for _, blob := range c.Blobs {
		if !ids["skill_blobs"][blob.ID] || blobs[blob.ID].ID != 0 || blob.SizeBytes < 0 || (blob.ObjectKey != "" && !validObjectKey(blob.ObjectKey)) {
			return ErrRows
		}
		blobs[blob.ID] = blob
	}
	for _, version := range c.Versions {
		if !ids["skill_versions"][version.ID] || versions[version.ID].ID != 0 || skills[version.SkillID].ID == 0 || blobs[version.BlobID].ID == 0 {
			return ErrRows
		}
		versions[version.ID] = version
	}
	if len(skills) != len(ids["skills"]) || len(blobs) != len(ids["skill_blobs"]) || len(versions) != len(ids["skill_versions"]) || len(c.Bindings) != len(ids["instance_skills"]) || len(c.Jobs) != len(ids["skill_package_materialize_jobs"]) {
		return ErrRows
	}
	for _, skill := range skills {
		if skill.CurrentVersionID != 0 && versions[skill.CurrentVersionID].SkillID != skill.ID {
			return ErrRows
		}
	}
	seen := map[int]bool{}
	for _, binding := range c.Bindings {
		if !ids["instance_skills"][binding.ID] || seen[binding.ID] || instanceOwners[binding.InstanceID] == 0 || skills[binding.SkillID].UserID != instanceOwners[binding.InstanceID] || (binding.SkillVersionID != 0 && versions[binding.SkillVersionID].SkillID != binding.SkillID) {
			return ErrRows
		}
		seen[binding.ID] = true
	}
	seen = map[int]bool{}
	for _, job := range c.Jobs {
		if !ids["skill_package_materialize_jobs"][job.ID] || seen[job.ID] || instanceOwners[job.InstanceID] == 0 || skills[job.SkillID].UserID != instanceOwners[job.InstanceID] || blobs[job.BlobID].ID == 0 {
			return ErrRows
		}
		seen[job.ID] = true
	}
	return nil
}

// Requirements retain every available original source location. They are NOT
// proof that any directory exists or was archived. The actual workspace
// collector must authenticate bytes and the finalizer must cover EVERY
// unpackaged blob with a matching original capture in the same task/barrier.
func (c CaptureInventory) WorkspaceRequirements() ([]WorkspaceCaptureRequirement, error) {
	blobs := map[int]CaptureBlob{}
	versions := map[int]CaptureVersion{}
	current := map[int]int{}
	for _, blob := range c.Blobs {
		blobs[blob.ID] = blob
	}
	for _, version := range c.Versions {
		versions[version.ID] = version
	}
	for _, skill := range c.Skills {
		current[skill.ID] = skill.CurrentVersionID
	}
	var result []WorkspaceCaptureRequirement
	covered := map[int]bool{}
	add := func(blobID, instanceID, bindingID, jobID int, directory, expected string) error {
		blob, ok := blobs[blobID]
		if !ok {
			return ErrObjectCoverage
		}
		if blob.ObjectKey != "" {
			return nil
		}
		if directory == "" || path.IsAbs(directory) || path.Clean(directory) != directory || directory == "." || directory == ".." || strings.HasPrefix(directory, "../") || strings.ContainsAny(directory, "\\\x00\r\n:") {
			return nil
		}
		if !captureMD5(blob.ContentHash) || !strings.EqualFold(expected, blob.ContentHash) {
			return nil
		}
		result = append(result, WorkspaceCaptureRequirement{BlobID: blobID, InstanceID: instanceID, BindingID: bindingID, JobID: jobID, RelativeDirectory: directory, ContentMD5: strings.ToLower(blob.ContentHash)})
		covered[blobID] = true
		return nil
	}
	for _, binding := range c.Bindings {
		version := binding.SkillVersionID
		if version == 0 {
			version = current[binding.SkillID]
		}
		blobID := versions[version].BlobID
		if blobID == 0 {
			continue
		}
		if err := add(blobID, binding.InstanceID, binding.ID, 0, binding.WorkspaceDir, binding.ObservedHash); err != nil {
			return nil, err
		}
	}
	for _, job := range c.Jobs {
		if err := add(job.BlobID, job.InstanceID, 0, job.ID, job.WorkspaceDir, job.ContentHash); err != nil {
			return nil, err
		}
	}
	for _, blob := range c.Blobs {
		if blob.ObjectKey == "" && !covered[blob.ID] {
			return nil, ErrWorkspaceProof
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.InstanceID != b.InstanceID {
			return a.InstanceID < b.InstanceID
		}
		if a.BlobID != b.BlobID {
			return a.BlobID < b.BlobID
		}
		if a.RelativeDirectory != b.RelativeDirectory {
			return a.RelativeDirectory < b.RelativeDirectory
		}
		if a.BindingID != b.BindingID {
			return a.BindingID < b.BindingID
		}
		return a.JobID < b.JobID
	})
	return result, nil
}
func captureMD5(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
