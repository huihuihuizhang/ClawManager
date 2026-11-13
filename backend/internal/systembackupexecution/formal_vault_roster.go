package systembackupexecution

import "clawreef/internal/systembackupinstallationowner/install"

// Reconcile the complete original roster before issuing a metadata token.
// The controller and SQL server remain observed roots, never stop actors.
func formalVaultWriterRoster(cfg DeploymentConfig, selected install.OriginalWriterSetSelection, controllerName, controllerUID string) ([]PlatformDeployment, error) {
	if controllerName == "" || controllerUID == "" || cfg.ControllerOwner != controllerUID || len(selected.PreAdoptionVaultDependencies) != 1 || validateDatabaseWorkload(cfg) != nil {
		return nil, install.ErrInstall
	}
	provider := selected.PreAdoptionVaultDependencies[0].Workload
	want := map[string]PlatformDeployment{}
	for _, w := range cfg.Writers {
		if w.Namespace != cfg.Namespace || w.UID == "" || want[w.Name].UID != "" || w.Name == controllerName || w.UID == controllerUID {
			return nil, install.ErrInstall
		}
		want[w.Name] = w
	}
	agents := map[string]string{}
	if cfg.RuntimeSources != nil {
		for _, a := range cfg.RuntimeSources.Deployments {
			if a.Namespace != cfg.Namespace || a.UID == "" || agents[a.Name] != "" {
				return nil, install.ErrInstall
			}
			agents[a.Name] = a.UID
		}
	}
	seenNames, seenUIDs := map[string]bool{}, map[string]bool{}
	controllers, databases, providers := 0, 0, 0
	for _, d := range selected.Deployments {
		if d.Name == "" || d.UID == "" || seenNames[d.Name] || seenUIDs[d.UID] {
			return nil, install.ErrInstall
		}
		seenNames[d.Name], seenUIDs[d.UID] = true, true
		switch {
		case d.Name == controllerName:
			if d.UID != controllerUID || d.Role != "writer" {
				return nil, install.ErrInstall
			}
			controllers++
		case d.Role == "database":
			if cfg.DatabaseWorkload == nil || d.Name != cfg.DatabaseWorkload.Name || d.UID != cfg.DatabaseWorkload.UID {
				return nil, install.ErrInstall
			}
			databases++
		case d.Role == "agent":
			if agents[d.Name] != d.UID {
				return nil, install.ErrInstall
			}
			delete(agents, d.Name)
		case d.Role == "provider-dependency":
			if d.Name != provider.Deployment || d.UID != provider.DeploymentUID || want[d.Name].UID != d.UID {
				return nil, install.ErrInstall
			}
			delete(want, d.Name)
			providers++
		case d.Role == "writer":
			if want[d.Name].UID != d.UID {
				return nil, install.ErrInstall
			}
			delete(want, d.Name)
		default:
			return nil, install.ErrInstall
		}
	}
	if controllers != 1 || providers != 1 || databases != 1 || len(want) != 0 || len(agents) != 0 {
		return nil, install.ErrInstall
	}
	kept := make([]PlatformDeployment, 0, len(cfg.Writers)-1)
	for _, w := range cfg.Writers {
		if w.Name != provider.Deployment {
			kept = append(kept, w)
		}
	}
	return kept, nil
}
