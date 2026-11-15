package install

import "testing"

func TestSourceRefreshRequiresActualUnconfiguredInstallation(t *testing.T) {
	for _, mode := range []string{"fresh", "missing-identity", "foreign-identity", "configured", "controller-seen", "v2-engine", "read-error", "legacy-task", "orphan-grant", "v2-config", "configuration-after-admission"} {
		t.Run(mode, func(t *testing.T) {
			f, ctx, _, file, sha := sourceRegistryAuthoringFixture(t)
			state := &freshSQLIdentityState{Present: true, InstallationID: f.i.plan.Target.InstallationID, ControllerUnseen: true, EnginePresent: true, EngineScope: "installation", Engine: "legacy", EngineVersion: 1}
			f.s.refreshState = state
			f.s.refreshPresent = map[string]bool{}
			switch mode {
			case "missing-identity":
				state.Present = false
			case "foreign-identity":
				state.InstallationID = "other"
			case "configured":
				state.ConfigVersion = 1
			case "controller-seen":
				state.ControllerUnseen = false
			case "v2-engine":
				state.Engine = "v2"
			case "read-error":
				f.s.refreshError = "SELECT EXISTS(SELECT 1 FROM system_backup_v2_backups LIMIT 1)"
			case "legacy-task":
				f.s.refreshPresent["system_backup_tasks"] = true
			case "orphan-grant":
				f.s.refreshPresent["system_backup_installation_owner_grants"] = true
			case "v2-config":
				f.s.refreshPresent["system_backup_v2_configs"] = true
			}
			p, err := f.i.PrepareBootstrapSourceRegistryAuthoring(ctx, f.password, f.enrollment, file, sha)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			err = p.RequireUnconfiguredSourceRefresh(ctx)
			if mode != "fresh" && mode != "configuration-after-admission" {
				if err == nil || p.RecheckAuthority(ctx) == nil {
					t.Fatal("used or unknown source accepted")
				}
				return
			}
			if err != nil || p.RecheckAuthority(ctx) != nil {
				t.Fatal("fresh authenticated read-only author rejected", err)
			}
			if mode == "configuration-after-admission" {
				f.s.refreshPresent["system_backup_v2_configs"] = true
				if p.RecheckAuthority(ctx) == nil {
					t.Fatal("configuration created after admission was ignored")
				}
				f.s.refreshPresent["system_backup_v2_configs"] = false
				if p.RecheckAuthority(ctx) == nil {
					t.Fatal("failed author became usable again")
				}
			}
			if f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("source renewal manufactured authority")
			}
			requireNoOpenAuthorityTx(t, f.s)
		})
	}
}
