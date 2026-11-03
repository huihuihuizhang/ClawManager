package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

// Explicit orchestration doubles only. These tests establish ordering,
// identity deduplication and unchanged final guards, not native signer/source
// authority, InnoDB lock order or field first-enable permission.
type mutationSignerPrefixDouble struct {
	*mutationResolverObservation
	events             *[]string
	ctx                context.Context
	tx                 *sql.Tx
	now                time.Time
	prefixes, ordinary int
	failPrefix         bool
	onPrefix           func()
}

func (o *mutationSignerPrefixDouble) Prepare(context.Context, ConfigMutationResourceInput) (ConfigMutationResourceObservation, error) {
	o.prepares++
	return o, nil
}
func (o *mutationSignerPrefixDouble) RecheckOriginalSignerPrefix(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx != o.ctx || tx != o.tx || !now.Equal(o.now) {
		return errors.New("prefix changed original ctx/tx/time")
	}
	o.prefixes++
	*o.events = append(*o.events, "prefix:signers")
	if o.onPrefix != nil {
		o.onPrefix()
	}
	if o.failPrefix {
		return errors.New("private original signer prefix rejected")
	}
	return nil
}
func (o *mutationSignerPrefixDouble) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o.prefixes == 0 || ctx != o.ctx || tx != o.tx || !now.Equal(o.now) {
		return errors.New("ordinary signer check before exact original prefix")
	}
	o.ordinary++
	return o.mutationResolverObservation.Recheck(ctx, tx, now)
}

type mutationPrefixDeploymentDouble struct {
	*mutationResolverDeployment
	events *[]string
}

func (o *mutationPrefixDeploymentDouble) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	*o.events = append(*o.events, "deployment")
	return o.mutationResolverDeployment.Recheck(ctx, tx, now)
}

func mutationSignerPrefixFixture(t *testing.T) (*mutationResolverFixture, *mutationSignerPrefixDouble, *[]string) {
	t.Helper()
	f := newMutationResolverFixture(t)
	events := []string{}
	for slot, observed := range f.observations {
		slot := slot
		observed.check = func() { events = append(events, "ordinary:"+slot) }
	}
	prefix := &mutationSignerPrefixDouble{mutationResolverObservation: f.observations["reference:capture_signing"], events: &events}
	for _, purpose := range []string{"capture_signing", "acceptance_signing", "catalog_signing"} {
		f.sources.References[purpose] = prefix
	}
	f.sources.Deployment = func(context.Context, string) (ConfigMutationDeploymentObservation, error) {
		return &mutationPrefixDeploymentDouble{f.deployment, &events}, nil
	}
	return f, prefix, &events
}

func TestConfigMutationSignerPrefixBeforeResourcesAndDeduplicatesThreeAliases(t *testing.T) {
	f, prefix, events := mutationSignerPrefixFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready, e := f.resolver(t).Prepare(ctx, f.svc.InstallationID, f.actor, f.current, f.proposed)
	if e != nil {
		t.Fatal(e)
	}
	tx := f.tx(t)
	prefix.ctx, prefix.tx = ctx, tx
	for round := 1; round <= 2; round++ {
		*events = nil
		prefix.now = f.state.now.Add(time.Duration(round-1) * time.Microsecond)
		if _, e := ready.Recheck(ctx, tx, prefix.now); e != nil {
			t.Fatal("exact signer prefix integration", round, e)
		}
		if prefix.prepares != 3 || prefix.prefixes != round || prefix.ordinary != 3*round {
			t.Fatal("prefix aliases were not deduplicated, or ordinary checks skipped", prefix.prepares, prefix.prefixes, prefix.ordinary)
		}
		if len(*events) != 2+len(bootstrapRegistryKinds)+len(bootstrapReferencePurposes)+1 || (*events)[0] != "prefix:signers" || (*events)[1] != "deployment" {
			t.Fatal("source prefix did not precede deployment and every ordinary source", *events)
		}
		for slot, observed := range f.observations {
			want := round
			if slot == "reference:capture_signing" {
				want = 3 * round
			}
			if slot == "reference:acceptance_signing" || slot == "reference:catalog_signing" {
				want = 0
			}
			if observed.checks != want {
				t.Fatal("complete resource recheck changed", slot, observed.checks, want)
			}
		}
	}
	if f.state.commits != 0 || len(f.state.working.writes) != 0 {
		t.Fatal("prefix/readiness wrote or committed")
	}
}

func TestConfigMutationSignerPrefixFailureAndFinalGuardsStayClosed(t *testing.T) {
	for _, which := range []string{"prefix_error", "cancel", "expiry_drift", "risk_drift", "ordinary_error", "deployment_error"} {
		t.Run(which, func(t *testing.T) {
			f, prefix, events := mutationSignerPrefixFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready, e := f.resolver(t).Prepare(ctx, f.svc.InstallationID, f.actor, f.current, f.proposed)
			if e != nil {
				t.Fatal(e)
			}
			prefix.ctx, prefix.tx, prefix.now = ctx, f.tx(t), f.state.now
			switch which {
			case "prefix_error":
				prefix.failPrefix = true
			case "cancel":
				prefix.onPrefix = cancel
			case "expiry_drift":
				prefix.onPrefix = func() { prefix.until = prefix.until.Add(time.Hour) }
			case "risk_drift":
				prefix.onPrefix = func() { prefix.risk.ProtectionReduction = true }
			case "ordinary_error":
				prefix.failCheck = true
			case "deployment_error":
				f.deployment.fail = true
			}
			if _, e := ready.Recheck(ctx, prefix.tx, prefix.now); e != ErrRegistrationUnavailable {
				t.Fatal("failed prefix or changed frozen guard accepted", which, e)
			}
			if prefix.prefixes != 1 {
				t.Fatal("failed prefix call count", prefix.prefixes)
			}
			if which == "prefix_error" || which == "cancel" {
				if len(*events) != 1 || f.loads != 18 {
					t.Fatal("work continued after failed/canceled source prefix", *events, f.loads)
				}
			}
			if f.state.commits != 0 || len(f.state.working.writes) != 0 {
				t.Fatal("failed readiness wrote or committed")
			}
		})
	}
}

// A noncomparable value must never reach the interface-key dedup map or be
// treated as the concrete source object required by the original protocol.
type mutationNonPointerSignerPrefix struct {
	until         time.Time
	calls         *int
	noncomparable []byte
}

func (o mutationNonPointerSignerPrefix) Prepare(context.Context, ConfigMutationResourceInput) (ConfigMutationResourceObservation, error) {
	return o, nil
}
func (mutationNonPointerSignerPrefix) Risk() ConfigMutationRisk                          { return ConfigMutationRisk{} }
func (o mutationNonPointerSignerPrefix) ValidUntil() time.Time                           { return o.until }
func (mutationNonPointerSignerPrefix) Recheck(context.Context, *sql.Tx, time.Time) error { return nil }
func (o mutationNonPointerSignerPrefix) RecheckOriginalSignerPrefix(context.Context, *sql.Tx, time.Time) error {
	*o.calls++
	return nil
}
func TestConfigMutationSignerPrefixRejectsDetachedValueWithoutPanic(t *testing.T) {
	f := newMutationResolverFixture(t)
	calls := 0
	f.sources.References["capture_signing"] = mutationNonPointerSignerPrefix{until: f.state.now.Add(time.Hour), calls: &calls, noncomparable: []byte("data")}
	ready := f.prepared(t)
	if _, e := ready.Recheck(context.Background(), f.tx(t), f.state.now); e != ErrRegistrationUnavailable || calls != 0 {
		t.Fatal("detached/noncomparable prefix accepted", e, calls)
	}
	for _, o := range f.observations {
		if o.checks != 0 {
			t.Fatal("ordinary source used after detached prefix")
		}
	}
}

func TestConfigMutationSignerPrefixDedupUsesObservationIdentity(t *testing.T) {
	f, a, events := mutationSignerPrefixFixture(t)
	b := &mutationSignerPrefixDouble{mutationResolverObservation: f.observations["reference:catalog_signing"], events: events}
	f.sources.References["catalog_signing"] = b
	ctx := context.Background()
	ready, e := f.resolver(t).Prepare(ctx, f.svc.InstallationID, f.actor, f.current, f.proposed)
	if e != nil {
		t.Fatal(e)
	}
	tx := f.tx(t)
	a.ctx, a.tx, a.now = ctx, tx, f.state.now
	b.ctx, b.tx, b.now = ctx, tx, f.state.now
	if _, e := ready.Recheck(ctx, tx, f.state.now); e != nil {
		t.Fatal(e)
	}
	if a.prefixes != 1 || b.prefixes != 1 || a.ordinary != 2 || b.ordinary != 1 {
		t.Fatal("distinct original observations collapsed by type")
	}
	if len(*events) < 3 || !strings.HasPrefix((*events)[0], "prefix:") || !strings.HasPrefix((*events)[1], "prefix:") || (*events)[2] != "deployment" {
		t.Fatal("a distinct source prefix ran after resource locks", *events)
	}
}
