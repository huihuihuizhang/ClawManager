package systembackupevidence

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Only the private seam is simulated. Production's exported constructor takes
// concrete D services, not this driver. D's suite owns SQL/commit/renewal proof;
// these tests exercise A's mapping and real local JWT/Transit/body pipeline.
type systemExecutionTestSnapshot struct{ v pd.SnapshotView }

func (s *systemExecutionTestSnapshot) View() pd.SnapshotView { return s.v }
func (s *systemExecutionTestSnapshot) Deadline() time.Time   { v, _ := s.v.ValidUntil.Time(); return v }
func (s *systemExecutionTestSnapshot) BindingHash() pd.Hash  { return s.v.BindingHash }
func (s *systemExecutionTestSnapshot) Purpose() string       { return s.v.Binding.Call.Purpose }

type systemExecutionTestCalls struct {
	c         SystemExecutionPreparationPolicy
	x         *systemTransitFixture
	requests  []pd.CallRequest
	snapshots []*systemExecutionTestSnapshot
	checks    int
	mutate    func(int, *pd.SnapshotView)
	deny      string
}

func systemExecutionStamp(v time.Time) pd.Timestamp {
	return pd.Timestamp(v.UTC().Format("2006-01-02T15:04:05.000000Z"))
}
func (f *systemExecutionTestCalls) begin(ctx context.Context, r pd.CallRequest) (systemCallSnapshot, error) {
	f.requests = append(f.requests, r)
	if ctx.Err() != nil || f.deny == r.Purpose {
		return nil, ErrDenied
	}
	c := f.c
	observed, expires := systemExecutionStamp(time.Now().Add(-time.Minute)), systemExecutionStamp(c.Content.ValidUntil)
	v := pd.SnapshotView{Binding: pd.ExecutionBinding{Kind: "call", Scope: c.Scope, Subject: pd.Hash(c.SubjectIdentityHash), GrantID: "grant_1", GrantGeneration: "1", GrantVersion: "2", RunID: c.RunID, Call: r}, CapturedAt: systemExecutionStamp(time.Now()), ValidUntil: r.BudgetUntil, BindingHash: pd.Hash(hash([]byte(r.Purpose)))}
	v.Facts = pd.ExecutionFacts{
		Domain:     pd.DomainRecord{Scope: c.Scope, IssuerIdentityHash: pd.Hash(c.IssuerIdentityHash), State: "open"},
		Grant:      pd.GrantRecord{Scope: c.Scope, Target: pd.Target{Role: pd.Role(c.Content.Role), IdentityHash: pd.Hash(c.Content.ProviderIdentity), RefVersion: pd.ProviderVersion(c.Content.ProviderVersion), ProbeScopeHash: pd.Hash(c.Content.ScopeHash), EvaluatorProfileHash: pd.Hash(c.EvaluatorProfileHash)}},
		Run:        pd.RunRecord{Scope: c.Scope, RunID: c.RunID, EvidenceID: pd.EvidenceID(c.Identity.ID), InputHash: pd.Hash(c.InputHash), State: "acquired", ObservedAt: &observed, ObservationExpiresAt: &expires},
		Target:     pd.TargetRecord{Scope: c.Scope},
		References: pd.ReferenceApproval{PolicyHash: r.PolicyHash},
		Evidence:   &pd.CallEvidence{EvidenceID: r.EvidenceID, OwnerType: "system", OwnerID: c.Scope.Installation, EvidenceType: "capability_snapshot", State: "reserved", RowVersion: "0"},
	}
	// Shared facts must be precisely stable between purposes.
	if len(f.snapshots) > 0 {
		v.Facts.Run.ObservedAt = f.snapshots[0].v.Facts.Run.ObservedAt
	}
	if f.mutate != nil {
		f.mutate(len(f.requests), &v)
	}
	s := &systemExecutionTestSnapshot{v}
	f.snapshots = append(f.snapshots, s)
	return s, nil
}
func (f *systemExecutionTestCalls) recheck(ctx context.Context, s systemCallSnapshot) error {
	f.checks++
	if ctx.Err() != nil || f.x.revoked.Load() || f.deny == s.Purpose() {
		return ErrDenied
	}
	return nil
}
func systemExecutionFixture(t *testing.T, mode string) (*systemTransitFixture, *systemExecutionTestCalls) {
	t.Helper()
	x := newSystemTransitFixture(t, mode)
	c := SystemExecutionPreparationPolicy{Scope: pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: pd.Installation(x.i.Installation)}, RunID: "cap-runtime-12345678", InputHash: strings.Repeat("a", 64), EvaluatorProfileHash: strings.Repeat("b", 64), SubjectIdentityHash: strings.Repeat("c", 64), IssuerIdentityHash: strings.Repeat("d", 64), Identity: x.i, Content: *x.grant.Content.Capability, Wrap: x.c, AuthenticationAudience: x.grant.AuthenticationAudience, AuthenticationTokenFile: x.grant.AuthenticationTokenFile}
	return x, &systemExecutionTestCalls{c: c, x: x}
}
func systemExecutionPreparer(t *testing.T, x *systemTransitFixture, f *systemExecutionTestCalls) *systemExecutionAuthority {
	t.Helper()
	a, err := newSystemExecutionAuthority(context.Background(), f, f.c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewSystemTransitPreparer(a, x.c)
	if err != nil {
		t.Fatal(err)
	}
	x.p.Close()
	x.p = p
	t.Cleanup(p.Close)
	return a
}

func TestSystemExecutionPreparation(t *testing.T) {
	x, f := systemExecutionFixture(t, "")
	a := systemExecutionPreparer(t, x, f)
	if len(f.requests) != 2 || f.requests[0].Purpose != "content_read" || f.requests[0].RefIdentityHash != pd.Hash(f.c.Content.ProviderIdentity) || f.requests[1].Purpose != "wrap" || f.requests[1].RefIdentityHash != pd.Hash(x.c.Transit.Key.Identity) || f.requests[0].BudgetUntil != f.requests[1].BudgetUntil || f.requests[0].PolicyHash != pd.Hash(SystemExecutionPreparationPolicyHash(f.c)) {
		t.Fatal("incorrect call bindings")
	}
	var dst bytes.Buffer
	prepared, err := x.p.Prepare(context.Background(), x.i, source(x.body), &dst)
	if err != nil || prepared.Manifest().Identity != x.i || bytes.Contains(dst.Bytes(), x.body) {
		t.Fatal("fixed execution failed", err)
	}
	store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: "exact"}}
	plain, err := OpenRange(context.Background(), prepared.Manifest(), Ref{strings.Repeat("a", 64), "v1", "system/evidence", "exact"}, store, taskPreparedReadKeys{x.seed}, 0, x.i.ContentSize-1)
	if err != nil || !bytes.Equal(plain, x.body) {
		t.Fatal("pipeline did not round-trip", err)
	}
	wipe(plain)
	if f.checks != 20 || len(f.requests) != 2 || x.logins.Load() != 1 || x.encrypts.Load() != 1 {
		t.Fatal("snapshot was refreshed or missed a check", f.checks)
	}
	g, err := a.AuthorizeSystemPreparation(context.Background(), x.i, a.grant.ProfileHash)
	if err != nil {
		t.Fatal(err)
	}
	g.Content.Capability.Role = "secret"
	if a.grant.Content.Capability.Role == "secret" {
		t.Fatal("mutable policy escaped")
	}
}

func TestSystemExecutionSnapshotBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*pd.SnapshotView){
		"scope":      func(v *pd.SnapshotView) { v.Binding.Scope.Database = "other" },
		"subject":    func(v *pd.SnapshotView) { v.Binding.Subject = pd.Hash(strings.Repeat("e", 64)) },
		"run":        func(v *pd.SnapshotView) { v.Binding.RunID = "other" },
		"generation": func(v *pd.SnapshotView) { v.Binding.GrantGeneration = "2" },
		"renewal":    func(v *pd.SnapshotView) { v.Binding.GrantVersion = "3" },
		"input":      func(v *pd.SnapshotView) { v.Facts.Run.InputHash = pd.Hash(strings.Repeat("e", 64)) },
		"issuer":     func(v *pd.SnapshotView) { v.Facts.Domain.IssuerIdentityHash = pd.Hash(strings.Repeat("e", 64)) },
		"role":       func(v *pd.SnapshotView) { v.Facts.Grant.Target.Role = "secret" },
		"evaluator":  func(v *pd.SnapshotView) { v.Facts.Grant.Target.EvaluatorProfileHash = pd.Hash(strings.Repeat("e", 64)) },
		"ref":        func(v *pd.SnapshotView) { v.Binding.Call.RefVersion = "other" },
		"policy":     func(v *pd.SnapshotView) { v.Facts.References.PolicyHash = pd.Hash(strings.Repeat("e", 64)) },
		"unobserved": func(v *pd.SnapshotView) { v.Facts.Run.ObservedAt = nil },
		"observation_expiry": func(v *pd.SnapshotView) {
			s := systemExecutionStamp(time.Now().Add(time.Hour))
			v.Facts.Run.ObservationExpiresAt = &s
		},
		"already_pending":  func(v *pd.SnapshotView) { v.Facts.Run.State = "pending" },
		"evidence_exists":  func(v *pd.SnapshotView) { v.Facts.Evidence.State = "pending" },
		"no_evidence_lock": func(v *pd.SnapshotView) { v.Facts.Evidence = nil },
		"wrong_owner":      func(v *pd.SnapshotView) { v.Facts.Evidence.OwnerType = "task" },
		"deadline":         func(v *pd.SnapshotView) { v.ValidUntil = systemExecutionStamp(time.Now().Add(-time.Second)) },
		"identity_version": func(v *pd.SnapshotView) { v.Facts.Admission.IdentityVersionHash = pd.Hash(strings.Repeat("e", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			x, f := systemExecutionFixture(t, "")
			f.mutate = func(n int, v *pd.SnapshotView) {
				if n == 2 {
					mutate(v)
				}
			}
			if a, e := newSystemExecutionAuthority(context.Background(), f, f.c); e == nil || a != nil {
				t.Fatal("incompatible call admitted")
			}
			if x.logins.Load() != 0 || x.encrypts.Load() != 0 {
				t.Fatal("provider reached before admission")
			}
		})
	}
}

func TestSystemExecutionLiveChecks(t *testing.T) {
	for _, mode := range []string{"before_read", "content_revoked", "wrap_revoked", "after login", "after encrypt", "after staging", "snapshot_replaced", "expired", "wrong_body", "wrong_profile", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			x, f := systemExecutionFixture(t, mode)
			a := systemExecutionPreparer(t, x, f)
			ctx := context.Background()
			switch mode {
			case "before_read":
				x.revoked.Store(true)
			case "content_revoked":
				f.deny = "content_read"
			case "wrap_revoked":
				f.deny = "wrap"
			case "snapshot_replaced":
				f.snapshots[0].v.BindingHash = pd.Hash(strings.Repeat("f", 64))
			case "expired":
				a.grant.Content.ValidUntil = time.Now().Add(-time.Second)
			case "wrong_body":
				x.i.ContentHash = strings.Repeat("f", 64)
			case "wrong_profile":
				a.grant.ProfileHash = strings.Repeat("f", 64)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			dst := systemTransitWriter(func(b []byte) (int, error) {
				if mode == "after staging" {
					x.revoked.Store(true)
				}
				return len(b), nil
			})
			p, e := x.p.Prepare(ctx, x.i, source(x.body), dst)
			if e == nil || len(p.Manifest().Chunks) != 0 {
				t.Fatal("revoked call returned Prepared")
			}
			if len(f.requests) != 2 {
				t.Fatal("denial replaced snapshots")
			}
			if mode != "after encrypt" && mode != "after staging" && x.encrypts.Load() != 0 {
				t.Fatal("Wrap sent after failed gate")
			}
		})
	}
}

func TestSystemExecutionPublicAndPolicyBoundaries(t *testing.T) {
	x, f := systemExecutionFixture(t, "")
	if p, e := NewSystemExecutionPreparer(context.Background(), nil, nil, f.c); e == nil || p != nil {
		t.Fatal("missing D accepted")
	}
	if p, e := NewSystemExecutionPreparer(context.Background(), &pd.Execution{}, &pd.ExecutionHandle{}, f.c); e == nil || p != nil {
		t.Fatal("zero D handle accepted")
	}
	if e := (systemDCalls{}).recheck(context.Background(), &systemExecutionTestSnapshot{}); e != ErrDenied {
		t.Fatal("fake view accepted by concrete D bridge")
	}
	base := SystemExecutionPreparationPolicyHash(f.c)
	for name, change := range map[string]func(*SystemExecutionPreparationPolicy){
		"body":            func(c *SystemExecutionPreparationPolicy) { c.Identity.ContentHash = strings.Repeat("e", 64) },
		"input":           func(c *SystemExecutionPreparationPolicy) { c.InputHash = strings.Repeat("e", 64) },
		"auth_projection": func(c *SystemExecutionPreparationPolicy) { c.AuthenticationTokenFile += "-other" },
		"jwt_subject":     func(c *SystemExecutionPreparationPolicy) { c.Wrap.Subject = "other" },
		"jwt_issuer":      func(c *SystemExecutionPreparationPolicy) { c.Wrap.Issuer += "/other" },
		"key_version":     func(c *SystemExecutionPreparationPolicy) { c.Wrap.Transit.KeyVersion++ },
		"profile":         func(c *SystemExecutionPreparationPolicy) { c.EvaluatorProfileHash = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.c
			change(&c)
			if SystemExecutionPreparationPolicyHash(c) == base {
				t.Fatal("policy omitted field")
			}
		})
	}
	for name, change := range map[string]func(*SystemExecutionPreparationPolicy){
		"same_audience":  func(c *SystemExecutionPreparationPolicy) { c.AuthenticationAudience = c.Wrap.Audience },
		"same_file":      func(c *SystemExecutionPreparationPolicy) { c.AuthenticationTokenFile = c.Wrap.TokenFile },
		"wrong_ca":       func(c *SystemExecutionPreparationPolicy) { c.Wrap.Transit.CAPEM = []byte("wrong") },
		"identity":       func(c *SystemExecutionPreparationPolicy) { c.Identity.OwnerType = "task" },
		"classification": func(c *SystemExecutionPreparationPolicy) { c.Content.Classification = "sensitive" },
		"invalid_run":    func(c *SystemExecutionPreparationPolicy) { c.RunID = "bad run" },
	} {
		t.Run(name, func(t *testing.T) {
			c := f.c
			change(&c)
			if a, e := newSystemExecutionAuthority(context.Background(), f, c); e == nil || a != nil {
				t.Fatal("invalid local binding admitted")
			}
		})
	}
	if x.logins.Load() != 0 {
		t.Fatal("configuration checks read credentials")
	}
	if _, e := x.p.Prepare(context.Background(), Identity{}, source(nil), io.Discard); e == nil {
		t.Fatal("zero body accepted")
	}
}
