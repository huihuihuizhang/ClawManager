package domain

import (
	"clawreef/internal/systembackup/team"
	"regexp"
)

const TeamWorkspaceVersion = "teams-shared-workspace.v1"

// TeamWorkspaceSpec binds inert shared-file recovery to the FINAL original
// authenticated SQL capture. D must authorize both digests and the original
// part/target; choosing a Team ID or constructing this value is no grant.
type TeamWorkspaceSpec struct {
	Version                   string   `json:"version"`
	TeamID                    int      `json:"team_id"`
	InventorySHA256           string   `json:"inventory_sha256"`
	SourceSQLCiphertextSHA256 string   `json:"source_sql_ciphertext_sha256"`
	ArtifactRefs              []string `json:"artifact_refs"`
}

var teamCipherDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func NewTeamWorkspaceSpec(source Snapshot, inventory team.Inventory, teamID int, sourceSQLCiphertextSHA256 string) (*TeamWorkspaceSpec, error) {
	// Public configuration binds the original authenticated ciphertext reference,
	// never a dictionary-testable digest of plaintext SQL or individual rows.
	if !teamCipherDigest.MatchString(sourceSQLCiphertextSHA256) {
		return nil, ErrData
	}
	if err := VerifyTeamCapture(source, inventory); err != nil {
		return nil, err
	}
	found := false
	for _, t := range inventory.Teams {
		if t.ID == teamID && t.SharedMountID != "" {
			found = true
		}
	}
	if !found {
		return nil, ErrData
	}
	refs, err := TeamArtifactReferences(source, teamID)
	if err != nil {
		return nil, err
	}
	return &TeamWorkspaceSpec{TeamWorkspaceVersion, teamID, inventory.SHA256(), sourceSQLCiphertextSHA256, refs}, nil
}
