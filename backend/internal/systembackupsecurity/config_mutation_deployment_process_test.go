package systembackupsecurity

import (
	"context"
	"testing"
	"time"
)

// Actual process environment, not a callback/JSON/config enabled observation.
// SQL/native complete-enable integration is separately required.
func TestProcessDeploymentSwitchUsesActualWriterEnvironmentAndCannotRenew(t *testing.T) {
	db := DatabaseIdentity{"12345678-1234-1234-1234-123456789abc", "original_db"}
	s, e := NewProcessDeploymentSwitch("installation_original", db)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t.Setenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL", "public-v1")
	t.Setenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED", "true")
	o, e := s.Observe(ctx, "installation_original")
	if e != nil || !o.Enabled() || o.ValidUntil().IsZero() {
		t.Fatal("actual enabled process not observed", e)
	}
	first := o.ValidUntil()
	if first.After(time.Now().Add(30 * time.Second)) {
		t.Fatal("first native cap extended")
	}
	if o.ValidUntil() != first {
		t.Fatal("observation renewed its first cap")
	}
	actual := o.(*processDeploymentObservation)
	copy := &processDeploymentObservation{origin: actual.origin, owner: actual.owner, ctx: actual.ctx, protocol: actual.protocol, execution: actual.execution, started: actual.started, until: actual.until}
	if copy.Enabled() || !copy.ValidUntil().IsZero() {
		t.Fatal("copied observation accepted")
	}
	t.Setenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED", "false")
	if o.Enabled() || !o.ValidUntil().IsZero() {
		t.Fatal("changed deployment accepted")
	}
	disabled, e := s.Observe(ctx, "installation_original")
	if e != nil || disabled.Enabled() || disabled.ValidUntil().IsZero() {
		t.Fatal("explicit independent false observation lost", e)
	}
	if disabled.Recheck(ctx, nil, time.Now()) == nil || !disabled.ValidUntil().IsZero() {
		t.Fatal("missing real SQL transaction accepted")
	}
	if _, e = s.Observe(ctx, "installation_foreign"); e == nil {
		t.Fatal("foreign installation accepted")
	}
	t.Setenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL", "legacy")
	if _, e = s.Observe(ctx, "installation_original"); e == nil {
		t.Fatal("different writer protocol accepted")
	}
	t.Setenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL", "public-v1")
	t.Setenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED", "")
	if _, e = s.Observe(ctx, "installation_original"); e == nil {
		t.Fatal("missing independent switch accepted")
	}
	if _, e = s.Observe(context.Background(), "installation_original"); e == nil {
		t.Fatal("unbounded attempt accepted")
	}
}
