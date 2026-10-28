package systembackupsecurity

// Synthetic independent authority and narrow SQL-clock fixtures exercise this
// composition only. They do not authenticate a deployment or prove SQL locks.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type pinnedSyntheticAuthority struct {
	want        pd.Hash
	calls       map[string]int
	fail, wrong string
	mutate      bool
	prepareFn   func(OfflineBootstrapGrant, BootstrapConfig, pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error)
	authorizeFn func(pd.BootstrapSQL, pd.BootstrapConsumptionRequest, time.Time) (pd.BootstrapConsumptionAdmission, error)
	recheckFn   func(pd.BootstrapReadSQL) error
}

func (a *pinnedSyntheticAuthority) visit(stage string, r pd.BootstrapConsumptionRequest) error {
	a.calls[stage]++
	h, err := pd.BootstrapConsumptionHash(r)
	if err != nil || h != a.want {
		a.wrong = stage
	}
	if a.mutate {
		next := pd.Hash(strings.Repeat("d", 64))
		if r.Candidates[0].Request.Admission.Unconfigured.PolicyHash == next {
			next = pd.Hash(strings.Repeat("e", 64))
		}
		r.Candidates[0].Request.Admission.Unconfigured.PolicyHash = next
	}
	if a.fail == stage {
		return errors.New("PRIVATE original authority detail")
	}
	return nil
}
func (a *pinnedSyntheticAuthority) PrepareBootstrapCandidates(_ context.Context, g OfflineBootstrapGrant, c BootstrapConfig, r pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	if err := a.visit("prepare", r); err != nil {
		return PreparedBootstrapCandidateAuthority{}, err
	}
	if a.prepareFn != nil {
		return a.prepareFn(g, c, r)
	}
	return PreparedBootstrapCandidateAuthority{Session: a}, nil
}
func (a *pinnedSyntheticAuthority) Authorize(_ context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	if err := a.visit("authorize", r); err != nil {
		return pd.BootstrapConsumptionAdmission{}, err
	}
	if a.authorizeFn != nil {
		return a.authorizeFn(tx, r, now)
	}
	return pd.BootstrapConsumptionAdmission{BindingHash: a.want, IdentityExpiresAt: pd.Timestamp(now.Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000000Z")), DependencyExpiresAt: pd.Timestamp(now.Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000000Z"))}, nil
}
func (a *pinnedSyntheticAuthority) LockHosts(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	return a.visit("hosts", r)
}
func (a *pinnedSyntheticAuthority) LockReferences(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	return a.visit("references", r)
}
func (a *pinnedSyntheticAuthority) Reserve(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	return a.visit("reserve", r)
}
func (a *pinnedSyntheticAuthority) LockEvidence(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	return nil, a.visit("evidence", r)
}
func (a *pinnedSyntheticAuthority) Recheck(_ context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts, _ time.Time) error {
	if err := a.visit("recheck", r); err != nil {
		return err
	}
	if a.recheckFn != nil {
		return a.recheckFn(tx)
	}
	return nil
}

// All non-clock SQL methods are intentionally unavailable through the embedded
// nil capability: any unexpected SQL/file/provider work fails this fixture.
type pinnedSyntheticSQL struct {
	pd.BootstrapSQL
	now     time.Time
	samples int
	err     error
}

func (s *pinnedSyntheticSQL) SampleTime(context.Context) (time.Time, error) {
	s.samples++
	return s.now, s.err
}

type pinnedAuthorityFixture struct {
	ctx                     context.Context
	g                       OfflineBootstrapGrant
	c                       BootstrapConfig
	r                       pd.BootstrapConsumptionRequest
	sources                 BootstrapAdmissionSources
	files                   map[string][]byte
	authority               *pinnedBootstrapCandidateAuthority
	inner                   *pinnedSyntheticAuthority
	now, notBefore, expires time.Time
	reads, registries       int
	revoked                 bool
}

func newPinnedAuthorityFixture(t *testing.T) *pinnedAuthorityFixture {
	t.Helper()
	_, g, raw, s, _ := admissionFixture(t)
	p, _ := candidateBridgeFixture(t)
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := &pinnedAuthorityFixture{ctx: context.Background(), g: g, c: c, r: p.request, files: map[string][]byte{}, now: time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)}
	f.notBefore, f.expires = f.now.Add(-time.Hour), f.now.Add(time.Minute)
	for _, ref := range c.Registries() {
		f.files[ref.Kind], err = s.RegistryBytes(ref.Kind, ref.Version, ref.SHA256)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.rebind(t)
	f.inner = &pinnedSyntheticAuthority{want: mustPinnedRequestHash(t, f.r), calls: map[string]int{}}
	s.ReadGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
		f.reads++
		if f.revoked {
			return f.g, time.Time{}, time.Time{}, errors.New("PRIVATE revoked grant")
		}
		return f.g, f.notBefore, f.expires, nil
	}
	s.RegistryBytes = func(kind, _, _ string) ([]byte, error) { f.registries++; return f.files[kind], nil }
	f.sources = s
	a, err := NewPinnedBootstrapCandidateAuthority(s, f.inner)
	if err != nil {
		t.Fatal(err)
	}
	f.authority = a.(*pinnedBootstrapCandidateAuthority)
	f.authority.clock = func() time.Time { return f.now }
	return f
}
func mustPinnedRequestHash(t *testing.T, r pd.BootstrapConsumptionRequest) pd.Hash {
	t.Helper()
	h, e := pd.BootstrapConsumptionHash(r)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (f *pinnedAuthorityFixture) rebind(t *testing.T) {
	t.Helper()
	f.g.ConfigSHA256 = f.c.SHA256()
	b, _ := json.Marshal(f.g)
	var fields map[string]json.RawMessage
	if json.Unmarshal(f.c.CanonicalJSON(), &fields) != nil {
		t.Fatal("config fixture")
	}
	f.r.Scope = pd.Scope{ServerUUID: pd.ServerUUID(f.g.ServerUUID), Database: pd.Database(f.g.Database), Installation: pd.Installation(f.g.InstallationID)}
	f.r.OfflineGrantHash = pd.Hash(registrationHash(string(b)))
	f.r.ConfigHash = pd.Hash(f.g.ConfigSHA256)
	f.r.RegistrySetHash = pd.Hash(registrationHash(string(fields["registries"])))
	f.r.RefSetHash = pd.Hash(registrationHash(string(fields["references"])))
	f.r.Username, f.r.MatrixKey, f.r.Endpoint, f.r.IdempotencyKey = f.g.Username, f.g.MatrixKey, BootstrapConfigEndpoint, f.g.IdempotencyKey
	for i := range f.r.Candidates {
		r := &f.r.Candidates[i].Request
		r.Scope = f.r.Scope
		r.Evidence.OwnerID = pd.Installation(f.g.InstallationID)
		r.Admission.Unconfigured.CandidateHash = f.r.ConfigHash
		r.Admission.Unconfigured.RegistrySetHash = f.r.RegistrySetHash
		r.Admission.Unconfigured.RefSetHash = f.r.RefSetHash
	}
	if f.inner != nil {
		f.inner.want = mustPinnedRequestHash(t, f.r)
	}
}
func (f *pinnedAuthorityFixture) replaceRegistry(t *testing.T, kind string, raw []byte) {
	t.Helper()
	var v bootstrapValues
	if json.Unmarshal(f.c.CanonicalJSON(), &v) != nil {
		t.Fatal("config fixture")
	}
	for i := range v.Registries {
		if v.Registries[i].Kind == kind {
			v.Registries[i].SHA256 = registrationHash(string(raw))
		}
	}
	b, _ := json.Marshal(v)
	var err error
	f.c, err = DecodeBootstrapConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	f.files[kind] = raw
	f.rebind(t)
}
func (f *pinnedAuthorityFixture) prepare(t *testing.T) *pinnedBootstrapCandidateSession {
	t.Helper()
	p, err := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r)
	if err != nil {
		t.Fatal(err)
	}
	return p.Session.(*pinnedBootstrapCandidateSession)
}

func TestPinnedBootstrapCandidateAuthorityRequiresFixedSourcesAndIndependentAuthority(t *testing.T) {
	f := newPinnedAuthorityFixture(t)
	var typedNil *pinnedSyntheticAuthority
	for name, tc := range map[string]struct {
		s BootstrapAdmissionSources
		a BootstrapCandidateAuthority
	}{
		"grant":      {BootstrapAdmissionSources{RegistryBytes: f.sources.RegistryBytes}, f.inner},
		"registries": {BootstrapAdmissionSources{ReadGrant: f.sources.ReadGrant}, f.inner},
		"authority":  {f.sources, nil}, "typed_nil": {f.sources, typedNil},
	} {
		t.Run(name, func(t *testing.T) {
			if a, e := NewPinnedBootstrapCandidateAuthority(tc.s, tc.a); e == nil || a != nil {
				t.Fatal("missing fixed dependency")
			}
		})
	}
	for _, typed := range []bool{false, true} {
		t.Run(fmt.Sprint("session_", typed), func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			f.inner.prepareFn = func(OfflineBootstrapGrant, BootstrapConfig, pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
				var s BootstrapCandidateAuthoritySession
				if typed {
					s = typedNil
				}
				return PreparedBootstrapCandidateAuthority{Session: s}, nil
			}
			if _, e := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); e == nil {
				t.Fatal("missing independent session")
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityRefreshesOriginalGrantOnEveryRetry(t *testing.T) {
	f := newPinnedAuthorityFixture(t)
	f.prepare(t)
	f.prepare(t)
	if f.reads != 2 || f.registries != 18 || f.inner.calls["prepare"] != 2 {
		t.Fatal(f.reads, f.registries, f.inner.calls)
	}
	f.revoked = true
	if _, e := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); e != ErrRegistrationPermission || f.reads != 3 || f.inner.calls["prepare"] != 2 {
		t.Fatal("revoked historical attempt", e, f.reads, f.inner.calls)
	}
	changes := map[string]func(*OfflineBootstrapGrant){"installation": func(g *OfflineBootstrapGrant) { g.InstallationID += "_other" }, "server": func(g *OfflineBootstrapGrant) { g.ServerUUID = "11111111-1111-1111-1111-111111111111" }, "database": func(g *OfflineBootstrapGrant) { g.Database += "_other" }, "username": func(g *OfflineBootstrapGrant) { g.Username += "_other" }, "actor": func(g *OfflineBootstrapGrant) { g.UserID++ }, "matrix": func(g *OfflineBootstrapGrant) { g.MatrixKey = "k3s-single-node" }, "config": func(g *OfflineBootstrapGrant) { g.ConfigSHA256 = strings.Repeat("a", 64) }, "key": func(g *OfflineBootstrapGrant) { g.IdempotencyKey += "_other" }, "reason": func(g *OfflineBootstrapGrant) { g.ChangeReason += "_other" }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			original := f.g
			change(&f.g)
			if _, e := f.authority.PrepareBootstrapCandidates(f.ctx, original, f.c, f.r); e != ErrRegistrationPermission || f.inner.calls["prepare"] != 0 {
				t.Fatal("original grant semantics replaced", e)
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityOriginalWindowAndRequestCannotBeRebound(t *testing.T) {
	for _, mode := range []string{"zero_start", "equal_bounds", "inverted_bounds", "future_start", "expiry_equal", "expiry_past"} {
		t.Run(mode, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			switch mode {
			case "zero_start":
				f.notBefore = time.Time{}
			case "equal_bounds":
				f.expires = f.notBefore
			case "inverted_bounds":
				f.expires = f.notBefore.Add(-time.Second)
			case "future_start":
				f.notBefore = f.now.Add(time.Second)
			case "expiry_equal":
				f.expires = f.now
			case "expiry_past":
				f.expires = f.now.Add(-time.Nanosecond)
			}
			if _, err := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); err == nil || f.inner.calls["prepare"] != 0 {
				t.Fatal("invalid original window", err)
			}
		})
	}
	for _, mode := range []string{"grant_hash", "username", "actor", "endpoint", "matrix", "key", "config", "zero_config", "canceled", "nil_context"} {
		t.Run(mode, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			switch mode {
			case "grant_hash":
				f.r.OfflineGrantHash = pd.Hash(strings.Repeat("a", 64))
			case "username":
				f.r.Username += "_other"
			case "actor":
				f.r.ActorID = "43"
			case "endpoint":
				f.r.Endpoint += "_other"
			case "matrix":
				f.r.MatrixKey = "k3s-single-node"
			case "key":
				f.r.IdempotencyKey += "_other"
			case "config":
				f.g.ConfigSHA256 = strings.Repeat("a", 64)
			case "zero_config":
				f.c = BootstrapConfig{}
			case "canceled":
				ctx, cancel := context.WithCancel(f.ctx)
				cancel()
				f.ctx = ctx
			case "nil_context":
				f.ctx = nil
			}
			if _, err := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); err == nil || f.inner.calls["prepare"] != 0 {
				t.Fatal("request rebound before independent authority", err)
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityValidatesAllNineRegistryFiles(t *testing.T) {
	for _, kind := range bootstrapRegistryKinds {
		for _, mode := range []string{"empty", "oversize", "wrong_bytes", "read_error"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newPinnedAuthorityFixture(t)
				switch mode {
				case "empty":
					f.files[kind] = nil
				case "oversize":
					f.files[kind] = make([]byte, 262145)
				case "read_error":
					read := f.authority.registryBytes
					f.authority.registryBytes = func(k, v, h string) ([]byte, error) {
						if k == kind {
							f.registries++
							return nil, errors.New("PRIVATE registry read")
						}
						return read(k, v, h)
					}
				default:
					f.files[kind] = []byte(`{"synthetic":"changed"}`)
				}
				prepared, e := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r)
				if f.registries != 9 {
					t.Fatal("source error shrank nine-registry attempt", f.registries)
				}
				if kind == "rbac_bindings" {
					if e == nil || f.inner.calls["prepare"] != 0 {
						t.Fatal("current RBAC missing but authority reached")
					}
					return
				}
				if e != nil {
					t.Fatal("non-RBAC resource blocked L3 historical branch", e)
				}
				s := prepared.Session.(*pinnedBootstrapCandidateSession)
				x := &pinnedSyntheticSQL{now: f.now}
				if _, e = s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, f.now); e != nil {
					t.Fatal("valid current identity blocked", e)
				}
				if e = s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{Replayed: true}, f.now); e != nil {
					t.Fatal("authenticated historical read blocked", e)
				}
				for stage, call := range map[string]func() error{
					"hosts":      func() error { return s.LockHosts(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) },
					"references": func() error { return s.LockReferences(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) },
					"reserve":    func() error { return s.Reserve(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) },
					"evidence":   func() error { _, err := s.LockEvidence(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}); return err },
				} {
					if err := call(); err == nil || f.inner.calls[stage] != 0 {
						t.Fatal("missing resource authorized new consumption", stage, err)
					}
				}
				if e = s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}, f.now); e == nil || f.inner.calls["recheck"] != 1 {
					t.Fatal("missing resources passed new-use recheck", e)
				}
			})
		}
	}
	for name, raw := range map[string]string{
		"role":         `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"synthetic-v1","installation_id":"installation_synthetic","bindings":[{"actor_id":"42","subject":"user:42","role":"config_admin"}]}`,
		"subject":      `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"synthetic-v1","installation_id":"installation_synthetic","bindings":[{"actor_id":"42","subject":"user:43","role":"security_admin"}]}`,
		"installation": `{"schema_version":"system-backup-registration-rbac.draft.v1","version":"synthetic-v1","installation_id":"installation_other","bindings":[{"actor_id":"42","subject":"user:42","role":"security_admin"}]}`,
	} {
		t.Run("rbac/"+name, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			f.replaceRegistry(t, "rbac_bindings", []byte(raw))
			if _, e := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); e == nil || f.inner.calls["prepare"] != 0 {
				t.Fatal("pinned bytes treated as permission")
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityOwnsSourcesAndDelegatesEveryStage(t *testing.T) {
	f := newPinnedAuthorityFixture(t)
	f.inner.mutate = true
	observed := f.now.Add(-time.Hour)
	f.inner.prepareFn = func(_ OfflineBootstrapGrant, c BootstrapConfig, _ pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
		c.canonical[0] = '!'
		c.values.Registries[0].SHA256 = "PRIVATE mutation"
		return PreparedBootstrapCandidateAuthority{Session: f.inner, CapacityObservedAt: &observed}, nil
	}
	p, err := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r)
	if err != nil {
		t.Fatal(err)
	}
	s := p.Session.(*pinnedBootstrapCandidateSession)
	observed = observed.Add(time.Hour)
	if p.CapacityObservedAt.Equal(observed) {
		t.Fatal("borrowed capacity timestamp")
	}
	for _, raw := range f.files {
		for i := range raw {
			raw[i] = '!'
		}
	}
	f.authority.readGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
		t.Fatal("grant file read under locks")
		return f.g, time.Time{}, time.Time{}, nil
	}
	f.authority.registryBytes = func(string, string, string) ([]byte, error) {
		t.Fatal("registry file read under locks")
		return nil, nil
	}
	x := &pinnedSyntheticSQL{now: f.now}
	a, e := s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, f.now)
	if e != nil || a.BindingHash != f.inner.want {
		t.Fatal(e, a)
	}
	if expiry, _ := a.DependencyExpiresAt.Time(); !expiry.Before(f.now) {
		t.Fatal("historical dependency was refreshed")
	}
	for stage, call := range map[string]func() error{"hosts": func() error { return s.LockHosts(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) }, "references": func() error { return s.LockReferences(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) }, "reserve": func() error { return s.Reserve(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}) }, "evidence": func() error { _, e := s.LockEvidence(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}); return e }, "recheck": func() error { return s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}, f.now) }} {
		if e = call(); e != nil || f.inner.calls[stage] != 1 {
			t.Fatal(stage, e, f.inner.calls)
		}
	}
	if f.inner.wrong != "" || mustPinnedRequestHash(t, f.r) != f.inner.want || mustPinnedRequestHash(t, s.request) != f.inner.want || f.reads != 1 || f.registries != 9 {
		t.Fatal("callback mutated original snapshot", f.inner.wrong, f.reads, f.registries)
	}
}

func TestPinnedBootstrapCandidateAuthorityDetachesCallerNestedRequestAndReusedBuffers(t *testing.T) {
	f := newPinnedAuthorityFixture(t)
	// Intermediate facts contain legitimate empty unions. Copying is not wire
	// parsing and must preserve those zeros while detaching populated children.
	facts := pd.BootstrapConsumptionFacts{Candidates: []pd.ResultFacts{{Receipt: &pd.ReceiptRecord{Request: f.r.Candidates[0].Request}}}}
	factsCopy, copyErr := pinnedCandidateCopy(facts)
	if copyErr != nil {
		t.Fatal("zero observation unions must be copyable", copyErr)
	}
	factsCopy.Candidates[0].Receipt.Request.Admission.Unconfigured.PolicyHash = pd.Hash(strings.Repeat("a", 64))
	if factsCopy.Candidates[0].Receipt.Request.Admission.Unconfigured.PolicyHash == facts.Candidates[0].Receipt.Request.Admission.Unconfigured.PolicyHash {
		t.Fatal("observation callback shares caller request")
	}
	// Deliberately reuse one source-owned byte buffer for all registry calls.
	buffer := make([]byte, 262144)
	f.authority.registryBytes = func(kind, _, _ string) ([]byte, error) {
		f.registries++
		raw := f.files[kind]
		copy(buffer, raw)
		return buffer[:len(raw)], nil
	}
	original, err := pinnedCandidateCopy(f.r)
	if err != nil {
		t.Fatal(err)
	}
	s := f.prepare(t)
	for i := range buffer {
		buffer[i] = '!'
	}
	f.r.Candidates[0].Request.Admission.Unconfigured.PolicyHash = pd.Hash(strings.Repeat("a", 64))
	x := &pinnedSyntheticSQL{now: f.now}
	if _, err = s.Authorize(f.ctx, x, original, pd.DomainRecord{}, f.now); err != nil || f.inner.wrong != "" {
		t.Fatal("caller/source owns retained bytes", err, f.inner.wrong)
	}
	if mustPinnedRequestHash(t, s.request) != mustPinnedRequestHash(t, original) {
		t.Fatal("private original request mutated")
	}
}

func TestPinnedBootstrapCandidateAuthorityClipsIdentityWithExactSQLPrecision(t *testing.T) {
	for _, offset := range []bool{false, true} {
		for _, fraction := range []int{0, 1, 999} {
			t.Run(fmt.Sprintf("offset_%v_fraction_%d", offset, fraction), func(t *testing.T) {
				f := newPinnedAuthorityFixture(t)
				floor := f.now.Add(30 * time.Second)
				f.expires = floor.Add(time.Duration(fraction) * time.Nanosecond)
				if offset {
					f.expires = f.expires.In(time.FixedZone("original +08", 8*60*60))
					f.notBefore = f.notBefore.In(time.FixedZone("original -05", -5*60*60))
				}
				s := f.prepare(t)
				x := &pinnedSyntheticSQL{now: floor}
				a, e := s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, floor)
				if fraction == 0 {
					if e == nil {
						t.Fatal("aligned equal expiry allowed")
					}
					return
				}
				if e != nil {
					t.Fatal("last legal SQL sample rejected", e)
				}
				deadline, err := a.IdentityExpiresAt.Time()
				if err != nil || !deadline.Equal(floor.Add(time.Microsecond)) {
					t.Fatal("expiry floored/offset changed", deadline, err)
				}
				x.now = deadline
				if _, e = s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, deadline); e == nil {
					t.Fatal("ceil equality allowed")
				}
				if e = s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{Replayed: true}, deadline); e == nil {
					t.Fatal("historical expiry equality allowed")
				}
			})
		}
	}
	f := newPinnedAuthorityFixture(t)
	s := f.prepare(t)
	x := &pinnedSyntheticSQL{now: f.now}
	short := f.now.Add(time.Second)
	f.inner.authorizeFn = func(_ pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ time.Time) (pd.BootstrapConsumptionAdmission, error) {
		return pd.BootstrapConsumptionAdmission{BindingHash: f.inner.want, IdentityExpiresAt: pd.Timestamp(short.Format("2006-01-02T15:04:05.000000Z"))}, nil
	}
	a, e := s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, f.now)
	if e != nil || string(a.IdentityExpiresAt) != short.Format("2006-01-02T15:04:05.000000Z") {
		t.Fatal("short independent identity extended", a, e)
	}
	if _, e := pinnedCandidateDeadline(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)); e == nil {
		t.Fatal("unrepresentable ceil accepted")
	}
}

func TestPinnedBootstrapCandidateAuthorityRechecksAfterCallbackWait(t *testing.T) {
	for _, stage := range []string{"prepare", "authorize", "recheck"} {
		t.Run(stage, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			x := &pinnedSyntheticSQL{now: f.now}
			if stage == "prepare" {
				f.inner.prepareFn = func(OfflineBootstrapGrant, BootstrapConfig, pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
					f.now = f.expires
					return PreparedBootstrapCandidateAuthority{Session: f.inner}, nil
				}
				if _, e := f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); e == nil {
					t.Fatal("prepare wait expired original grant")
				}
				return
			}
			s := f.prepare(t)
			if stage == "authorize" {
				f.inner.authorizeFn = func(_ pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ time.Time) (pd.BootstrapConsumptionAdmission, error) {
					x.now = f.expires
					return pd.BootstrapConsumptionAdmission{BindingHash: f.inner.want, IdentityExpiresAt: pd.Timestamp(f.expires.Add(time.Hour).Format("2006-01-02T15:04:05.000000Z"))}, nil
				}
				if _, e := s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, f.now); e == nil {
					t.Fatal("authorize wait expired grant")
				}
			} else {
				f.inner.recheckFn = func(pd.BootstrapReadSQL) error { x.now = f.expires; return nil }
				if e := s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{Replayed: true}, f.now); e == nil {
					t.Fatal("final wait expired grant")
				}
			}
			if x.samples != 2 {
				t.Fatal("missing shared post callback sample", x.samples)
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityRejectsReplacedRequestAndUnsafeClock(t *testing.T) {
	for _, stage := range []string{"authorize", "hosts", "references", "reserve", "evidence", "recheck"} {
		t.Run(stage, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			s := f.prepare(t)
			bad, err := pinnedCandidateCopy(f.r)
			if err != nil {
				t.Fatal(err)
			}
			bad.Candidates[0].MappingHash = pd.Hash(strings.Repeat("a", 64))
			x := &pinnedSyntheticSQL{now: f.now}
			var e error
			switch stage {
			case "authorize":
				_, e = s.Authorize(f.ctx, x, bad, pd.DomainRecord{}, f.now)
			case "hosts":
				e = s.LockHosts(f.ctx, x, bad, pd.BootstrapConsumptionFacts{})
			case "references":
				e = s.LockReferences(f.ctx, x, bad, pd.BootstrapConsumptionFacts{})
			case "reserve":
				e = s.Reserve(f.ctx, x, bad, pd.BootstrapConsumptionFacts{})
			case "evidence":
				_, e = s.LockEvidence(f.ctx, x, bad, pd.BootstrapConsumptionFacts{})
			case "recheck":
				e = s.Recheck(f.ctx, x, bad, pd.BootstrapConsumptionFacts{}, f.now)
			}
			if e == nil || f.inner.calls[stage] != 0 {
				t.Fatal("request replacement reached original authority")
			}
		})
	}
	for _, mode := range []string{"zero", "rollback", "fractional_SQL", "clock_error", "nil_SQL", "typed_nil_SQL"} {
		t.Run(mode, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			s := f.prepare(t)
			x := &pinnedSyntheticSQL{now: f.now}
			var tx pd.BootstrapSQL = x
			switch mode {
			case "zero":
				x.now = time.Time{}
			case "rollback":
				x.now = f.now.Add(-time.Microsecond)
			case "fractional_SQL":
				x.now = f.now.Add(time.Nanosecond)
			case "clock_error":
				x.err = errors.New("PRIVATE clock")
			case "nil_SQL":
				tx = nil
			case "typed_nil_SQL":
				var absent *pinnedSyntheticSQL
				tx = absent
			}
			if _, e := s.Authorize(f.ctx, tx, f.r, pd.DomainRecord{}, f.now); e == nil || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatal("unsafe clock allowed/leaked", e)
			}
		})
	}
}

func TestPinnedBootstrapCandidateAuthorityRedactsAndRetainsDelegatedFailures(t *testing.T) {
	for _, stage := range []string{"prepare", "authorize", "hosts", "references", "reserve", "evidence", "recheck"} {
		t.Run(stage, func(t *testing.T) {
			f := newPinnedAuthorityFixture(t)
			f.inner.fail = stage
			var s *pinnedBootstrapCandidateSession
			var err error
			if stage == "prepare" {
				_, err = f.authority.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r)
			} else {
				s = f.prepare(t)
				x := &pinnedSyntheticSQL{now: f.now}
				switch stage {
				case "authorize":
					_, err = s.Authorize(f.ctx, x, f.r, pd.DomainRecord{}, f.now)
				case "hosts":
					err = s.LockHosts(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{})
				case "references":
					err = s.LockReferences(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{})
				case "reserve":
					err = s.Reserve(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{})
				case "evidence":
					_, err = s.LockEvidence(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{})
				case "recheck":
					err = s.Recheck(f.ctx, x, f.r, pd.BootstrapConsumptionFacts{}, f.now)
				}
			}
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || f.inner.calls[stage] != 1 {
				t.Fatal("delegation bypassed/leaked", err, f.inner.calls)
			}
		})
	}
	f := newPinnedAuthorityFixture(t)
	s := f.prepare(t)
	for _, v := range []any{f.authority, *f.authority, s, *s} {
		text := fmt.Sprintf("%v %+v %#v", v, v, v)
		if strings.Contains(text, f.g.ChangeReason) || strings.Contains(text, f.g.ConfigSHA256) || strings.Contains(text, "security_admin") {
			t.Fatal("format leaked private sources")
		}
		if b, e := json.Marshal(v); e == nil || len(b) != 0 {
			t.Fatal("JSON source leak")
		}
	}
	var a pinnedBootstrapCandidateAuthority
	var p pinnedBootstrapCandidateSession
	if json.Unmarshal([]byte(`{}`), &a) == nil || json.Unmarshal([]byte(`{}`), &p) == nil {
		t.Fatal("JSON manufactured authority")
	}
}
