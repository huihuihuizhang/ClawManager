package install

import (
	"context"
	"database/sql"
)

// RequireUnconfiguredSourceRefresh narrows an authenticated read-only author.
// It cannot retire a task or authorize a capture. Every subsequent authority
// recheck also requires the original, never-configured installation state.
func (p *BootstrapSourceRegistryAuthoring) RequireUnconfiguredSourceRefresh(ctx context.Context) error {
	if p == nil || p.origin != p {
		return p.reject()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local(ctx) != nil || p.initial != (HeadCAS{}) || p.operator.authority(p.physical, p.enrollment) != nil {
		return p.reject()
	}
	p.unconfiguredRefresh = true
	if p.checkUnconfiguredSourceRefresh() != nil || p.local(ctx) != nil {
		return p.reject()
	}
	return nil
}

func (p *BootstrapSourceRegistryAuthoring) checkUnconfiguredSourceRefresh() error {
	s := p.operator
	tx, err := s.installer.db.BeginTx(p.physical, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	before, err := s.lockAdmin(p.physical, tx)
	if err != nil || before.Before(p.floor) {
		return ErrInstall
	}
	state, err := readFreshSQLInstallation(p.physical, tx, s.installer.plan.Target.InstallationID)
	if err != nil || state != freshIdentityInitialized {
		return ErrInstall
	}
	after, err := s.installer.database(p.physical, tx, p.until)
	if err != nil || after.Before(before) || tx.Rollback() != nil {
		return ErrInstall
	}
	p.floor = after
	return nil
}
