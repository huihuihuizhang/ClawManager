package systembackupsecurity

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"sync"
	"time"
)

// ProcessDeploymentSwitch observes the same process environment selected by
// the admitted public-v1 task writer. It is independent of config.enabled.
// There is no caller supplied boolean, JSON receipt or environment callback.
type ProcessDeploymentSwitch struct {
	installation string
	database     DatabaseIdentity
}

func NewProcessDeploymentSwitch(installation string, database DatabaseIdentity) (*ProcessDeploymentSwitch, error) {
	if !configMutationInstallation.MatchString(installation) || !database.valid() {
		return nil, ErrConfigMutation
	}
	return &ProcessDeploymentSwitch{installation: installation, database: database}, nil
}

type processDeploymentObservation struct {
	mu                    sync.Mutex
	origin                *processDeploymentObservation
	owner                 *ProcessDeploymentSwitch
	ctx                   context.Context
	protocol, execution   string
	started, until, floor time.Time
	tx                    *sql.Tx
	failed                bool
}

func (s *ProcessDeploymentSwitch) Observe(ctx context.Context, installation string) (ConfigMutationDeploymentObservation, error) {
	if s == nil || nilConfigMutationBoundary(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || installation != s.installation {
		return nil, ErrConfigMutation
	}
	end, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrConfigMutation
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(30 * time.Second)
	if end.Before(until) {
		until = end
	}
	p, x := os.Getenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL"), os.Getenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED")
	if p != "public-v1" || (x != "true" && x != "false") || !start.Before(until) {
		return nil, ErrConfigMutation
	}
	o := &processDeploymentObservation{owner: s, ctx: ctx, protocol: p, execution: x, started: start, until: until}
	o.origin = o
	return o, nil
}
func (*processDeploymentObservation) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
func (o *processDeploymentObservation) current() bool {
	return o != nil && o.origin == o && o.owner != nil && !o.failed && o.ctx != nil && o.ctx.Err() == nil && time.Now().Before(o.until) && os.Getenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL") == o.protocol && os.Getenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED") == o.execution
}
func (o *processDeploymentObservation) Enabled() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.current() && o.execution == "true"
}
func (o *processDeploymentObservation) ValidUntil() time.Time {
	if o == nil {
		return time.Time{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.current() {
		return time.Time{}
	}
	return o.until
}
func (o *processDeploymentObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return ErrConfigMutation
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	fail := func() error { o.failed = true; return ErrConfigMutation }
	if !o.current() || nilConfigMutationBoundary(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx != o.ctx || tx == nil || o.tx != nil && tx != o.tx || now.Before(o.started) || !now.Before(o.until) || !o.floor.IsZero() && now.Before(o.floor) {
		return fail()
	}
	var d DatabaseIdentity
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&d.ServerUUID, &d.Database, &tail) != nil || d != o.owner.database || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !tail.Before(o.until) || !o.current() {
		return fail()
	}
	o.tx = tx
	o.floor = tail
	return nil
}

var _ ConfigMutationDeploymentObservation = (*processDeploymentObservation)(nil)
