package systembackupexecution

import (
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestFormalVaultRosterReconcilesEveryRoleBeforeIssuance(t *testing.T) {
	for _, fault := range []string{"valid", "controller-writer", "controller-uid", "database-writer", "database-uid", "missing-agent", "missing-writer", "duplicate-writer", "unknown-role", "provider-uid", "duplicate-uid"} {
		t.Run(fault, func(t *testing.T) {
			cfg := DeploymentConfig{Namespace: "ns", ControllerOwner: "controller-uid", DatabaseWorkload: &PlatformDeployment{Namespace: "ns", Name: "sql", UID: "sql-uid"}, Writers: []PlatformDeployment{{Namespace: "ns", Name: "app", UID: "app-uid"}, {Namespace: "ns", Name: "vault", UID: "vault-uid"}}, RuntimeSources: &RuntimeSourceConfig{Deployments: []PlatformDeployment{{Namespace: "ns", Name: "agent", UID: "agent-uid"}}}}
			selected := install.OriginalWriterSetSelection{Deployments: []install.OriginalDeploymentSelection{{Name: "controller", UID: "controller-uid", Role: "writer"}, {Name: "sql", UID: "sql-uid", Role: "database"}, {Name: "app", UID: "app-uid", Role: "writer"}, {Name: "vault", UID: "vault-uid", Role: "provider-dependency"}, {Name: "agent", UID: "agent-uid", Role: "agent"}}, PreAdoptionVaultDependencies: []install.PreAdoptionVaultDependencySelection{{Workload: install.VaultProviderWorkloadSelection{Deployment: "vault", DeploymentUID: "vault-uid"}}}}
			switch fault {
			case "controller-writer":
				cfg.Writers = append(cfg.Writers, PlatformDeployment{Namespace: "ns", Name: "controller", UID: "controller-uid"})
			case "controller-uid":
				selected.Deployments[0].UID = "new"
			case "database-writer":
				cfg.Writers = append(cfg.Writers, *cfg.DatabaseWorkload)
			case "database-uid":
				cfg.DatabaseWorkload.UID = "new"
			case "missing-agent":
				cfg.RuntimeSources.Deployments = nil
			case "missing-writer":
				cfg.Writers = cfg.Writers[1:]
			case "duplicate-writer":
				cfg.Writers = append(cfg.Writers, cfg.Writers[0])
			case "unknown-role":
				selected.Deployments[2].Role = "unrecognized"
			case "provider-uid":
				selected.PreAdoptionVaultDependencies[0].Workload.DeploymentUID = "new"
			case "duplicate-uid":
				selected.Deployments[2].UID = "controller-uid"
			}
			kept, err := formalVaultWriterRoster(cfg, selected, "controller", "controller-uid")
			if fault == "valid" {
				if err != nil || len(kept) != 1 || kept[0].Name != "app" {
					t.Fatal(kept, err)
				}
			} else if err == nil {
				t.Fatal("invalid roster admitted")
			}
		})
	}
}
