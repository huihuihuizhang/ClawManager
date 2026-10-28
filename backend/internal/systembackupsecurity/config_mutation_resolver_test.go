package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// All owner validators here are explicit orchestration doubles. Their PASS
// is not evidence of real provider/ref readiness or a production deployment.
type mutationResolverObservation struct {
	risk                   ConfigMutationRisk
	until                  time.Time
	prepare                func(ConfigMutationResourceInput)
	check                  func()
	failPrepare, failCheck bool
	prepares, checks       int
}

func (o *mutationResolverObservation) Prepare(_ context.Context, in ConfigMutationResourceInput) (ConfigMutationResourceObservation, error) {
	o.prepares++
	if o.prepare != nil {
		o.prepare(in)
	}
	if o.failPrepare {
		return nil, errors.New("PRIVATE provider prepare error")
	}
	return o, nil
}
func (o *mutationResolverObservation) Risk() ConfigMutationRisk { return o.risk }
func (o *mutationResolverObservation) ValidUntil() time.Time    { return o.until }
func (o *mutationResolverObservation) Recheck(context.Context, *sql.Tx, time.Time) error {
	o.checks++
	if o.check != nil {
		o.check()
	}
	if o.failCheck {
		return errors.New("PRIVATE provider recheck error")
	}
	return nil
}

type mutationResolverDeployment struct {
	enabled bool
	until   time.Time
	fail    bool
}

func (d *mutationResolverDeployment) Enabled() bool         { return d.enabled }
func (d *mutationResolverDeployment) ValidUntil() time.Time { return d.until }
func (d *mutationResolverDeployment) Recheck(context.Context, *sql.Tx, time.Time) error {
	if d.fail {
		return errors.New("PRIVATE deployment error")
	}
	return nil
}

type mutationResolverFixture struct {
	svc               ConfigMutationService
	actor             RegistrationActor
	state             *mutationTestState
	current, proposed ConfigValues
	sources           ConfigMutationResolverSources
	files             map[string][]byte
	observations      map[string]*mutationResolverObservation
	deployment        *mutationResolverDeployment
	loads             int
}

func newMutationResolverFixture(t *testing.T) *mutationResolverFixture {
	t.Helper()
	svc, actor, _, state, _ := mutationTransactionFixture(t)
	f := &mutationResolverFixture{svc: svc, actor: actor, state: state, files: map[string][]byte{}, observations: map[string]*mutationResolverObservation{}, deployment: &mutationResolverDeployment{true, state.now.Add(2 * time.Hour), false}}
	v := state.data.rows[1].snapshot.values
	v.Registries = state.data.rows[1].Registries()
	for i, pin := range v.Registries {
		raw := []byte(`{"synthetic_registry":"` + pin.Kind + `"}`)
		if pin.Kind == "rbac_bindings" {
			raw = configRBACFixture(t, "synthetic-v1", [3]string{"42", "user:42", "security_admin"}, [3]string{"7", "user:7", "operator"})
		}
		pin.SHA256 = registrationHash(string(raw))
		v.Registries[i] = pin
		f.files[pin.Kind+":"+pin.Version+":"+pin.SHA256] = raw
	}
	raw, _ := json.Marshal(v)
	var err error
	f.current, err = DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.proposed, err = DecodeConfigValues(bytes.Replace(f.current.CanonicalJSON(), []byte(`"enabled":false`), []byte(`"enabled":true`), 1))
	if err != nil {
		t.Fatal(err)
	}
	state.data.rows[1] = f.current
	shared := make([]byte, 0, 4096)
	f.sources = ConfigMutationResolverSources{
		RegistryBytes: func(kind, version, digest string) ([]byte, error) {
			f.loads++
			raw, ok := f.files[kind+":"+version+":"+digest]
			if !ok {
				return nil, errors.New("PRIVATE missing pinned registry")
			}
			shared = append(shared[:0], raw...)
			return shared, nil
		},
		Registries: map[string]ConfigMutationResourceValidator{}, References: map[string]ConfigMutationResourceValidator{},
		Deployment: func(_ context.Context, installation string) (ConfigMutationDeploymentObservation, error) {
			if state.activeTx || installation != svc.InstallationID {
				t.Fatal("deployment preparation inside transaction or wrong scope")
			}
			return f.deployment, nil
		},
	}
	add := func(slot string) *mutationResolverObservation {
		o := &mutationResolverObservation{until: state.now.Add(time.Hour)}
		o.prepare = func(in ConfigMutationResourceInput) {
			if state.activeTx || in.InstallationID() != svc.InstallationID || in.Actor() != actor || in.Slot() != slot {
				t.Fatal("provider preparation binding/order", slot)
			}
			a, b := in.Configs()
			if a.SHA256() != f.current.SHA256() || b.SHA256() != f.proposed.SHA256() {
				t.Fatal("configuration snapshot changed")
			}
			if _, err := json.Marshal(in); err == nil {
				t.Fatal("internal preparation serialized")
			}
			// A malicious/buggy adapter cannot overwrite the next adapter's bytes.
			pair, ok := in.RegistryPair("parts")
			if !ok || string(pair.CurrentJSON) != `{"synthetic_registry":"parts"}` {
				t.Fatal("shared registry input was not frozen")
			}
			pair.CurrentJSON[0] = '!'
			if _, _, ok = in.ReferencePair("nonce_hmac"); !ok {
				t.Fatal("full typed reference view missing")
			}
		}
		o.check = func() {
			if !state.activeTx {
				t.Fatal("recheck outside caller transaction")
			}
		}
		f.observations[slot] = o
		return o
	}
	for _, kind := range bootstrapRegistryKinds {
		f.sources.Registries[kind] = add("registry:" + kind)
	}
	for _, purpose := range bootstrapReferencePurposes {
		f.sources.References[purpose] = add("reference:" + purpose)
	}
	f.sources.CrossResources = add("cross_resources")
	return f
}
func (f *mutationResolverFixture) resolver(t *testing.T) *PinnedConfigMutationResolver {
	t.Helper()
	r, err := NewPinnedConfigMutationResolver(f.svc.InstallationID, f.svc.Database, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *mutationResolverFixture) prepared(t *testing.T) ConfigMutationReadiness {
	t.Helper()
	r, err := f.resolver(t).Prepare(context.Background(), f.svc.InstallationID, f.actor, f.current, f.proposed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *mutationResolverFixture) tx(t *testing.T) *sql.Tx {
	t.Helper()
	tx, err := f.svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx
}

func TestConfigMutationResolverRequiresAllOwnersBeforeProviderWork(t *testing.T) {
	slots := []string{"registry_bytes", "deployment_switch", "cross_resources", "unknown_registry", "unknown_reference", "typed_nil"}
	for _, kind := range bootstrapRegistryKinds {
		slots = append(slots, "registry:"+kind)
	}
	for _, purpose := range bootstrapReferencePurposes {
		slots = append(slots, "reference:"+purpose)
	}
	for _, slot := range slots {
		t.Run(slot, func(t *testing.T) {
			f := newMutationResolverFixture(t)
			s := f.sources
			switch {
			case slot == "registry_bytes":
				s.RegistryBytes = nil
			case slot == "deployment_switch":
				s.Deployment = nil
			case slot == "cross_resources":
				s.CrossResources = nil
			case slot == "unknown_registry":
				s.Registries["not_a_kind"] = &mutationResolverObservation{}
			case slot == "unknown_reference":
				s.References["not_a_purpose"] = &mutationResolverObservation{}
			case slot == "typed_nil":
				s.Registries["parts"] = (*mutationResolverObservation)(nil)
			case strings.HasPrefix(slot, "registry:"):
				delete(s.Registries, strings.TrimPrefix(slot, "registry:"))
			default:
				delete(s.References, strings.TrimPrefix(slot, "reference:"))
			}
			if r, err := NewPinnedConfigMutationResolver(f.svc.InstallationID, f.svc.Database, s); r != nil || err != ErrRegistrationUnavailable {
				t.Fatal("incomplete resolver accepted", err)
			}
			if f.loads != 0 {
				t.Fatal("provider work before completeness gate")
			}
		})
	}
}

func TestConfigMutationResolverOwnsSnapshotsAndRechecksAllThirtyResources(t *testing.T) {
	f := newMutationResolverFixture(t)
	f.observations["reference:evidence_kek"].until = f.state.now.Add(30 * time.Second)
	f.observations["cross_resources"].risk = ConfigMutationRisk{SecurityBoundary: true, ProtectionReduction: true}
	r := f.resolver(t)
	delete(f.sources.Registries, "parts") // constructor must own its adapter map
	p, err := r.Prepare(context.Background(), f.svc.InstallationID, f.actor, f.current, f.proposed)
	if err != nil || !p.DeploymentEnabled() || !p.ValidUntil().Equal(f.state.now.Add(30*time.Second)) {
		t.Fatal("resolver snapshot", err)
	}
	if f.loads != 18 {
		t.Fatal("both complete registry sets must be resolved", f.loads)
	}
	for slot, o := range f.observations {
		if o.prepares != 1 {
			t.Fatal("owner skipped", slot)
		}
	}
	tx := f.tx(t)
	risk, err := p.Recheck(context.Background(), tx, f.state.now)
	if err != nil || !risk.SecurityBoundary || !risk.ProtectionReduction || f.loads != 36 {
		t.Fatal("resolved risk or exact pins missing", err)
	}
	for slot, o := range f.observations {
		if o.checks != 1 {
			t.Fatal("owner recheck skipped", slot)
		}
	}
	if f.state.commits != 0 || len(f.state.working.writes) != 0 {
		t.Fatal("resolver wrote/committed")
	}
}

func TestConfigMutationResolverRejectsPreparationFailuresWithoutSQL(t *testing.T) {
	for _, name := range []string{"zero-value", "nil-context", "foreign-installation", "empty-config", "registry-bytes", "owner-failed", "missing-expiry", "typed-nil-deployment"} {
		t.Run(name, func(t *testing.T) {
			f := newMutationResolverFixture(t)
			ctx := context.Background()
			installation := f.svc.InstallationID
			current := f.current
			switch name {
			case "nil-context":
				ctx = nil
			case "foreign-installation":
				installation = "installation_foreign"
			case "empty-config":
				current = ConfigValues{}
			case "registry-bytes":
				for path := range f.files {
					f.files[path] = []byte(`{}`)
				}
			case "owner-failed":
				f.observations["cross_resources"].failPrepare = true
			case "missing-expiry":
				f.observations["reference:evidence_kek"].until = time.Time{}
			case "typed-nil-deployment":
				f.sources.Deployment = func(context.Context, string) (ConfigMutationDeploymentObservation, error) {
					return (*mutationResolverDeployment)(nil), nil
				}
			}
			r := f.resolver(t)
			if name == "zero-value" {
				r = &PinnedConfigMutationResolver{}
				installation = ""
			}
			if p, err := r.Prepare(ctx, installation, f.actor, current, f.proposed); p != nil || err != ErrRegistrationUnavailable {
				t.Fatal("invalid prepare admitted or diagnostics escaped", err)
			}
			if f.state.begins != 0 || f.state.commits != 0 || len(f.state.data.writes) != 0 {
				t.Fatal("preparation touched SQL")
			}
		})
	}
}

func TestConfigMutationResolverRejectsSourceAndObservationDrift(t *testing.T) {
	for _, name := range []string{"file-bytes", "risk", "resource-expiry-extended", "deployment-switch", "deployment-expiry", "resource-revoked", "deployment-revoked", "foreign-database", "expired", "cross-mutates-earlier-observation", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newMutationResolverFixture(t)
			p := f.prepared(t)
			tx := f.tx(t)
			now := f.state.now
			ctx := context.Background()
			switch name {
			case "file-bytes":
				for path := range f.files {
					if strings.HasPrefix(path, "parts:") {
						f.files[path] = []byte(`{}`)
					}
				}
			case "risk":
				f.observations["registry:parts"].risk.SecurityBoundary = true
			case "resource-expiry-extended":
				f.observations["reference:nonce_hmac"].until = f.state.now.Add(24 * time.Hour)
			case "deployment-switch":
				f.deployment.enabled = false
			case "deployment-expiry":
				f.deployment.until = f.deployment.until.Add(time.Second)
			case "resource-revoked":
				f.observations["reference:artifact_delete"].failCheck = true
			case "deployment-revoked":
				f.deployment.fail = true
			case "foreign-database":
				f.state.wrongDatabase = true
			case "expired":
				now = p.ValidUntil()
			case "cross-mutates-earlier-observation":
				f.observations["cross_resources"].check = func() { f.observations["registry:parts"].risk.SecurityBoundary = true }
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if _, err := p.Recheck(ctx, tx, now); err != ErrRegistrationUnavailable {
				t.Fatal("drift admitted or private error escaped", err)
			}
		})
	}
}

func TestConfigMutationResolverDerivesRBACRiskFromContent(t *testing.T) {
	for _, change := range []bool{false, true} {
		f := newMutationResolverFixture(t)
		role := "operator"
		if change {
			role = "viewer"
		}
		raw := configRBACFixture(t, "v2", [3]string{"42", "user:42", "security_admin"}, [3]string{"7", "user:7", role})
		v := f.proposed.snapshot.values
		v.Registries = f.proposed.Registries()
		for i, pin := range v.Registries {
			if pin.Kind == "rbac_bindings" {
				pin.Version = "v2"
				pin.SHA256 = registrationHash(string(raw))
				v.Registries[i] = pin
				f.files[pin.Kind+":"+pin.Version+":"+pin.SHA256] = raw
			}
		}
		body, _ := json.Marshal(v)
		var err error
		f.proposed, err = DecodeConfigValues(body)
		if err != nil {
			t.Fatal(err)
		}
		p := f.prepared(t)
		risk, err := p.Recheck(context.Background(), f.tx(t), f.state.now)
		if err != nil || risk.SecurityBoundary != change {
			t.Fatal("RBAC classified by pins instead of bindings", err, risk)
		}
	}
}

func TestConfigMutationResolverIntegratesWithMutationAndFinalExpiry(t *testing.T) {
	for _, name := range []string{"active", "expired-before-response-prepare", "expires-in-final-authority", "valid-final-boundary"} {
		t.Run(name, func(t *testing.T) {
			f := newMutationResolverFixture(t)
			if name != "active" {
				f.observations["cross_resources"].until = f.state.now.Add(time.Second)
			}
			if name == "expired-before-response-prepare" {
				f.observations["cross_resources"].until = f.state.now
			}
			until := f.observations["cross_resources"].until
			f.svc.Resolver = f.resolver(t)
			if name == "expires-in-final-authority" || name == "valid-final-boundary" {
				a := &mutationAContractAuthority{ConfigMutationAuthority: f.svc.Authority, s: f.state}
				a.afterAuthorize = func() {
					if len(f.state.working.writes) > 0 {
						f.state.now = until
						if name == "valid-final-boundary" {
							f.state.now = f.state.now.Add(-time.Microsecond)
						}
					}
				}
				f.svc.Authority = a
			}
			raw, _ := json.Marshal(map[string]any{"expected_version": 1, "change_reason": nil, "config": json.RawMessage(f.proposed.CanonicalJSON())})
			result, err := f.svc.Mutate(context.Background(), f.actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "resolver-chain", raw, nil)
			if name == "active" || name == "valid-final-boundary" {
				if err != nil || result.Version != 2 || f.state.data.active != 2 {
					t.Fatal("complete resolver chain rejected", err)
				}
				return
			}
			mutationARequireRollback(t, f.state, result, err)
			if err != ErrRegistrationUnavailable {
				t.Fatal("wrong expiration category", err)
			}
		})
	}
}
