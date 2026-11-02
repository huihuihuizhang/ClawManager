package systembackupbootstrapsecurity

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func (*RBAC) TerminalKeys() []string { return []string{"registry:rbac_bindings"} }
func (*Issuers) TerminalKeys() []string {
	return []string{"registry:provider_proof_issuers", "registry:strong_auth_issuers"}
}

// These concrete registry owners retain the original closed codec, complete
// role/issuer policy and five-minute key runway. No arbitrary read callback or
// aggregate Original is accepted or supplied by this adapter.
func (v *RBAC) BindingSHA256() (string, error) {
	if v == nil || !filepath.IsAbs(v.directory) || filepath.Clean(v.directory) != v.directory {
		return "", sec.ErrRegistrationUnavailable
	}
	raw, e := json.Marshal(struct{ Owner, Directory string }{"bootstrap-rbac-source.v1", v.directory})
	if e != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	return shaBytes(raw), nil
}
func (v *Issuers) BindingSHA256() (string, error) {
	if v == nil || !filepath.IsAbs(v.directory) || filepath.Clean(v.directory) != v.directory {
		return "", sec.ErrRegistrationUnavailable
	}
	raw, e := json.Marshal(struct{ Owner, Directory string }{"bootstrap-two-issuer-sources.v1", v.directory})
	if e != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	return shaBytes(raw), nil
}
func (v *RBAC) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	prepared, e := v.Prepare(ctx, grant, config)
	if e != nil {
		return nil, e
	}
	c, ok := prepared.(*rbacCheck)
	if !ok {
		return nil, sec.ErrRegistrationUnavailable
	}
	return newRegistryTerminalCheck(ctx, grant, c, nil), nil
}
func (v *Issuers) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	prepared, e := v.Prepare(ctx, grant, config)
	if e != nil {
		return nil, e
	}
	c, ok := prepared.(*issuerCheck)
	if !ok {
		return nil, sec.ErrRegistrationUnavailable
	}
	return newRegistryTerminalCheck(ctx, grant, nil, c), nil
}

type registryTerminalCheck struct {
	origin        *registryTerminalCheck
	ctx           context.Context
	grant         sec.OfflineBootstrapGrant
	rbac          *rbacCheck
	issuers       *issuerCheck
	until         time.Time
	identityUntil time.Time
	tx            pd.BootstrapSQL
	failed        bool
	locked        bool
}

func newRegistryTerminalCheck(ctx context.Context, grant sec.OfflineBootstrapGrant, rbac *rbacCheck, issuers *issuerCheck) *registryTerminalCheck {
	until := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline.UTC().Truncate(time.Microsecond)
	}
	identityUntil, ok := ctx.Deadline()
	if !ok {
		identityUntil = until
	}
	c := &registryTerminalCheck{ctx: ctx, grant: grant, rbac: rbac, issuers: issuers, until: until, identityUntil: identityUntil.UTC().Truncate(time.Microsecond)}
	c.origin = c
	return c
}
func (c *registryTerminalCheck) DependencyDeadline() *pd.Timestamp {
	if c == nil || c.failed || c.until.IsZero() {
		return nil
	}
	stamp := pd.Timestamp(c.until.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &stamp
}
func (c *registryTerminalCheck) current(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return sec.ErrRegistrationUnavailable
	}
	fail := func() error { c.failed = true; return sec.ErrRegistrationUnavailable }
	if c.origin != c || c.failed || ctx == nil || c.ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != c.ctx || ctx.Err() != nil || !pd.SameBootstrapTransaction(c.tx, view) {
		if c.origin != nil {
			c.origin.failed = true
		}
		return fail()
	}
	before, e := view.SampleTime(ctx)
	if e != nil || !before.Before(c.identityUntil) {
		return fail()
	}
	var server, database string
	if view.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE()`).Scan(&server, &database) != nil || server != c.grant.ServerUUID || database != c.grant.Database {
		return fail()
	}
	if c.rbac != nil {
		if c.rbac.authorize(ctx) != nil {
			return fail()
		}
	} else if c.issuers != nil {
		if c.issuers.validate(ctx, before) != nil {
			return fail()
		}
	} else {
		return fail()
	}
	after, e := view.SampleTime(ctx)
	if e != nil || after.Before(before) || !after.Before(c.identityUntil) {
		return fail()
	}
	return nil
}
func (c *registryTerminalCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if c == nil {
		return sec.ErrRegistrationUnavailable
	}
	if c.locked {
		c.failed = true
		return sec.ErrRegistrationUnavailable
	}
	if e := c.fresh(ctx, tx); e != nil {
		return e
	}
	c.locked = true
	return nil
}
func (c *registryTerminalCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return sec.ErrRegistrationUnavailable
	}
	if !c.locked {
		c.failed = true
		return sec.ErrRegistrationUnavailable
	}
	return c.fresh(ctx, view)
}
func (c *registryTerminalCheck) fresh(ctx context.Context, view pd.BootstrapReadSQL) error {
	if e := c.current(ctx, view); e != nil {
		return e
	}
	now, e := view.SampleTime(ctx)
	if e != nil || !now.Before(c.until) {
		c.failed = true
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (c *registryTerminalCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if c == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	if c.tx != nil && !pd.SameBootstrapTransaction(c.tx, tx) {
		c.failed = true
		return nil, sec.ErrRegistrationUnavailable
	}
	c.tx = tx
	if e := c.current(ctx, tx); e != nil {
		return nil, e
	}
	end := pd.Timestamp(c.identityUntil.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &end, nil
}
func (c *registryTerminalCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	return c.current(ctx, view)
}

var _ sec.BootstrapTerminalResource = (*RBAC)(nil)
var _ sec.BootstrapTerminalResource = (*Issuers)(nil)
