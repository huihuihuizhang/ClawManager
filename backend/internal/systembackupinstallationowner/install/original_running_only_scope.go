package install

import (
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
)

func (p *OriginalWriterMaintenance) checkSelectionRuntimeTestScope(s *domain.RuntimeTestScope) error {
	if s == nil {
		return nil
	}
	t := p.operator.installer.plan.Target
	if s.Version != domain.RunningOnlyRuntimeTestScopeVersion || s.InstallationID != t.InstallationID || s.ServerUUID != t.ServerUUID || s.Database != t.Database || s.NamespaceUID != t.NamespaceUID || s.Validate(p.instances) != nil {
		return ErrInstall
	}
	return nil
}

// Compare the explicit user-approved roster to the already validated complete
// SQL projection. The option never supplies source facts or chooses new rows.
func matchesRunningOnlyRoster(scope *domain.RuntimeTestScope, rows []domain.SourceInstance, approved string) bool {
	var active, deferred []string
	for _, row := range rows {
		if scope.IsDeferred(row) {
			deferred = append(deferred, strconv.Itoa(row.ID))
		} else {
			active = append(active, strconv.Itoa(row.ID))
		}
	}
	return approved == strings.Join(active, ",")+":"+strings.Join(deferred, ",")
}
