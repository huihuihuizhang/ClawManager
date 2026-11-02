package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

// Synthetic orchestration fixture only. The concrete owner tests independently
// exercise signed source/identity checks; this does not supply production owners.
type originalResourceHookFixture struct {
	state *bootstrapTestState
	calls int
	deny  bool
}

func (v *originalResourceHookFixture) Prepare(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
	return v, nil
}
func (*originalResourceHookFixture) Recheck(context.Context, *sql.Tx, time.Time) error { return nil }
func (v *originalResourceHookFixture) AuthorizeBootstrapOriginal(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error {
	v.calls++
	if v.calls == 1 {
		for _, query := range v.state.queries {
			if strings.Contains(query, "idempotency_key") {
				return errors.New("identity hook reached after operation lookup")
			}
		}
	}
	if v.deny {
		return ErrRegistrationPermission
	}
	return nil
}
func TestBootstrapOriginalResourceIdentityBeforeHistoryAndOnReplay(t *testing.T) {
	svc, grant, raw, sources, state := admissionFixture(t)
	hook := &originalResourceHookFixture{state: state}
	sources.References["capture_signing"] = hook
	var e error
	svc.Admission, e = PrepareBootstrapAdmission(context.Background(), grant, raw, sources)
	if e != nil {
		t.Fatal(e)
	}
	if result, e := svc.Bootstrap(context.Background(), grant, raw); e != nil || result.Replayed || hook.calls < 2 {
		t.Fatal("original L2 resource hook omitted", e)
	}
	before := hook.calls
	if result, e := svc.Bootstrap(context.Background(), grant, raw); e != nil || !result.Replayed || hook.calls <= before {
		t.Fatal("historical retry omitted current identity hook", e)
	}
	hook.deny = true
	if _, e := svc.Bootstrap(context.Background(), grant, raw); e != ErrRegistrationPermission {
		t.Fatal("revoked owner used committed history", e)
	}
}
func TestBootstrapOriginalResourceDenialPrecedesAnyOperationLookup(t *testing.T) {
	svc, grant, raw, sources, state := admissionFixture(t)
	hook := &originalResourceHookFixture{state: state, deny: true}
	sources.References["capture_signing"] = hook
	var e error
	svc.Admission, e = PrepareBootstrapAdmission(context.Background(), grant, raw, sources)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Bootstrap(context.Background(), grant, raw); e != ErrRegistrationPermission || hook.calls != 1 || len(state.committed) != 0 {
		t.Fatal("denied original resource escaped L2", e)
	}
	for _, query := range state.queries {
		if strings.Contains(query, "idempotency_key") {
			t.Fatal("operation lookup ran before current owner authorization")
		}
	}
}
