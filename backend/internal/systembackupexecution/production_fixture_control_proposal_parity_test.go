package systembackupexecution

import (
	"errors"
	"testing"

	root "clawreef/internal/systembackup"
)

// Additional fixture invariant AFTER the actual root.NewControlScopeProposal
// constructor has authenticated schema/policy structure. It never approves
// the draft or adds capture permission for a control table.
func checkOriginalControlProposalCensus(proposal root.ControlScopeProposal, expected []string) error {
	if proposal.Status != "draft_requires_independent_owner_review" || len(expected) == 0 || len(proposal.Tables) != len(expected) {
		return errors.New("original control draft/census name set differs")
	}
	for n, table := range proposal.Tables {
		policy, known := root.Policy(expected[n])
		if !known || n > 0 && expected[n-1] >= expected[n] || table.Schema.Name != expected[n] || table.Policy != policy || policy.Category != "system_backup" || policy.BackupStrategy != "metadata_only" || policy.RestoreStrategy != "reference_only" {
			return errors.New("original control draft/census classification differs")
		}
	}
	return nil
}

func TestOriginalControlProposalRequiresExactObservedControlNames(t *testing.T) {
	// Name projection DATA only; not a proposal constructor/approval fixture.
	for _, fault := range []string{"current", "omitted-signer-head", "same-count-wrong-name", "duplicate-census", "business-substitution", "non-draft"} {
		t.Run(fault, func(t *testing.T) {
			expected := []string{"schema_migrations", "system_backup_signing_resource_grants", "system_backup_signing_resource_heads"}
			proposal := root.ControlScopeProposal{Status: "draft_requires_independent_owner_review"}
			for _, name := range expected {
				policy, known := root.Policy(name)
				if !known {
					t.Fatal("missing original registry policy")
				}
				proposal.Tables = append(proposal.Tables, root.ControlScopeTable{Policy: policy, Schema: root.SQLTable{Name: name}})
			}
			switch fault {
			case "omitted-signer-head":
				proposal.Tables = proposal.Tables[:2]
			case "same-count-wrong-name":
				proposal.Tables[2].Schema.Name = "system_backup_minio_owner_heads"
			case "duplicate-census":
				expected[2] = expected[1]
			case "business-substitution":
				expected[2] = "users"
			case "non-draft":
				proposal.Status = "approved"
			}
			if err := checkOriginalControlProposalCensus(proposal, expected); (err == nil) != (fault == "current") {
				t.Fatal("control draft accepted different names or manufactured approval", fault, err)
			}
		})
	}
}
