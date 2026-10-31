package systembackupskillhub

import (
	"strings"
	"testing"
)

func captureInventoryFixture() CaptureInventory {
	c := CaptureInventory{Version: CaptureInventoryVersion, Skills: []CaptureSkill{{ID: 1, UserID: 7, CurrentVersionID: 3}}, Blobs: []CaptureBlob{{ID: 2, ContentHash: strings.Repeat("a", 32), SizeBytes: 12}}, Versions: []CaptureVersion{{ID: 3, SkillID: 1, BlobID: 2}}, Bindings: []CaptureBinding{{ID: 4, InstanceID: 9, SkillID: 1, SkillVersionID: 3, WorkspaceDir: "skills/original", ObservedHash: strings.Repeat("a", 32)}}, Jobs: []CaptureMaterializeJob{{ID: 5, InstanceID: 9, SkillID: 1, BlobID: 2, WorkspaceDir: "skills/previous", ContentHash: strings.Repeat("a", 32)}}}
	for _, name := range CaptureTableNames() {
		k := CaptureTableKeys{Name: name, SchemaSHA256: strings.Repeat("b", 64), IDs: []int{}}
		switch name {
		case "skills":
			k.IDs = []int{1}
		case "skill_blobs":
			k.IDs = []int{2}
		case "skill_versions":
			k.IDs = []int{3}
		case "instance_skills":
			k.IDs = []int{4}
		case "skill_package_materialize_jobs":
			k.IDs = []int{5}
		default:
			k.IDs = []int{6}
		}
		c.Tables = append(c.Tables, k)
	}
	return c
}

func TestCaptureInventoryRetainsEightKeysetsAndOriginalWorkspaceRequirements(t *testing.T) {
	c := captureInventoryFixture()
	if c.Validate(map[int]bool{7: true}, map[int]int{9: 7}) != nil {
		t.Fatal("valid inventory")
	}
	requirements, err := c.WorkspaceRequirements()
	if err != nil || len(requirements) != 2 || requirements[0].BlobID != 2 || requirements[0].InstanceID != 9 {
		t.Fatal("lost unpackaged original workspace candidates", err)
	}
	frozen := CloneCaptureInventory(&c)
	hash := frozen.SHA256()
	c.Bindings[0].WorkspaceDir = "changed"
	c.Tables[0].IDs[0] = 99
	if frozen.SHA256() != hash || frozen.Bindings[0].WorkspaceDir != "skills/original" {
		t.Fatal("inventory aliases discovery")
	}
	// Candidate locations are requirements only. Without an original matching
	// hash/path at either location, this blob cannot silently disappear.
	frozen.Bindings[0].ObservedHash = strings.Repeat("c", 32)
	frozen.Jobs[0].WorkspaceDir = "../foreign"
	if _, err := frozen.WorkspaceRequirements(); err == nil {
		t.Fatal("missing workspace source became success")
	}
}

func TestCaptureInventoryRejectsBrokenOwnershipAndKeysetClosure(t *testing.T) {
	for _, mode := range []string{"missing-table", "extra-key", "duplicate-id", "foreign-user", "foreign-instance", "foreign-version", "foreign-blob"} {
		t.Run(mode, func(t *testing.T) {
			c := captureInventoryFixture()
			switch mode {
			case "missing-table":
				c.Tables = c.Tables[1:]
			case "extra-key":
				c.Tables[0].IDs = append(c.Tables[0].IDs, 8)
			case "duplicate-id":
				c.Tables[0].IDs = append(c.Tables[0].IDs, 1)
			case "foreign-user":
				c.Skills[0].UserID = 100
			case "foreign-instance":
				c.Bindings[0].InstanceID = 100
			case "foreign-version":
				c.Skills[0].CurrentVersionID = 100
			case "foreign-blob":
				c.Versions[0].BlobID = 100
			}
			if c.Validate(map[int]bool{7: true}, map[int]int{9: 7}) == nil {
				t.Fatal("broken original Skills closure", mode)
			}
		})
	}
}
