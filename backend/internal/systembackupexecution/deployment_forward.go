package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"time"
)

type deploymentAuthorization struct{ Service *DeploymentService }

func forwardCaptureActions(g c.ExecutionGrant) bool {
	if len(g.Actions) != 3 {
		return false
	}
	have := map[string]bool{}
	for _, a := range g.Actions {
		if have[a] || (a != "prepare" && a != "capture" && a != "issue_worker") {
			return false
		}
		have[a] = true
	}
	return have["prepare"] && have["capture"] && have["issue_worker"]
}

func (p deploymentAuthorization) check(ctx context.Context, tx *sql.Tx, a d.Authority) error {
	if !p.Service.ForwardEnabled {
		return c.ErrExecutionAuthority
	}
	if _, e := pinnedDeploymentFile(p.Service.ConfigPath, p.Service.ConfigDigest, 256<<10); e != nil {
		return e
	}
	var enabled bool
	if tx.QueryRowContext(ctx, "SELECT last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", a.InstallationID).Scan(&enabled) != nil || !enabled {
		return c.ErrExecutionAuthority
	}
	return nil
}
func (p deploymentAuthorization) AuthorizeExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) (c.ExecutionAuthorizationGuard, error) {
	if e := p.check(ctx, tx, a); e != nil {
		return nil, e
	}
	grant, e := p.Service.Forward.AuthorizeExecution(ctx, tx, a, now)
	if e != nil {
		return nil, e
	}
	return deploymentForwardGuard{Policy: p, Grant: grant}, nil
}

type deploymentForwardGuard struct {
	Policy deploymentAuthorization
	Grant  c.ExecutionAuthorizationGuard
}

func (g deploymentForwardGuard) ValidUntil() time.Time { return g.Grant.ValidUntil() }
func (g deploymentForwardGuard) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	if e := g.Policy.check(ctx, tx, a); e != nil {
		return e
	}
	return g.Grant.RecheckExecution(ctx, tx, a, now)
}
