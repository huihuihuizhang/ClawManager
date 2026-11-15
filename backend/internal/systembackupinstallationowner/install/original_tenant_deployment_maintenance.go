package install

import (
	"context"
	"reflect"
)

// A tenant selection is only DATA. Construct its controller actor using the
// current authenticated installer, retained complete SQL inventory and actual
// API owner chain. This does not stop anything or provide a CSI held proof.
func (p *OriginalWriterMaintenance) prepareTenantDeployment(ctx context.Context, selected OriginalTenantProSelection, journal *originalWriterJournal) (*originalDeploymentMaintenance, error) {
	if p.check(ctx) != nil || selected.Source.Namespace == p.operator.installer.plan.Target.Namespace {
		return nil, ErrInstall
	}
	found := false
	for _, source := range p.instances {
		if source.ID == selected.Source.ID {
			if found || !reflect.DeepEqual(source, selected.Source) {
				return nil, ErrInstall
			}
			found = true
		}
	}
	if !found {
		return nil, ErrInstall
	}
	identity, pod, dep, _, err := p.readInitialTenantPro(ctx, selected.Source)
	if err != nil {
		return nil, ErrInstall
	}
	actual, err := originalTenantProCapture(selected.Source, identity, pod, dep)
	if err != nil || !reflect.DeepEqual(actual, selected) {
		return nil, ErrInstall
	}
	w, err := p.prepareDeploymentInNamespace(ctx, OriginalDeploymentSelection{Name: selected.Deployment, UID: selected.Identity.DeploymentUID, Role: "writer"}, journal, identity.Namespace, identity.NamespaceUID)
	if err != nil || len(w.pods) != 1 || w.pods[0].UID != identity.PodUID || w.replicas != 1 {
		return nil, ErrInstall
	}
	// A second full owner-chain read brackets the separate SSAR/Deployment/Pod
	// requests; a rollout during preparation cannot mix two incarnations.
	last, _, _, _, err := p.readInitialTenantPro(ctx, selected.Source)
	if err != nil || last != identity || p.check(ctx) != nil {
		return nil, ErrInstall
	}
	return w, nil
}

// Compare the complete live tenant census before acquiring any gate. An
// extra Pod or reconciler cannot disappear behind the selected writer list.
func (s *PreparedOriginalWriterSet) recheckTenantPreflight(ctx context.Context) error {
	if s.recheckTeamAttachments(ctx, nil) != nil {
		return ErrInstall
	}
	groups := map[string][]OriginalTenantProSelection{}
	for _, selected := range s.selection.TenantPro {
		groups[selected.Identity.Namespace] = append(groups[selected.Identity.Namespace], selected)
	}
	seen := map[string]bool{}
	for _, initial := range s.selection.TenantNamespaces {
		if seen[initial.Namespace] || initial.Namespace == s.initial.Namespace || originalTenantProCensusMatches(initial, groups[initial.Namespace], s.selection.TeamAttachments...) != nil {
			return ErrInstall
		}
		seen[initial.Namespace] = true
		current, _, _, _, err := s.owner.readKubernetesNamespaceCensus(ctx, initial.Namespace, initial.NamespaceUID)
		if err != nil || !reflect.DeepEqual(current, initial) {
			return ErrInstall
		}
	}
	if len(groups) != len(seen) {
		return ErrInstall
	}
	return nil
}
