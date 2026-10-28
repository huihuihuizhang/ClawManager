package systembackupevidence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type systemSTSTestSnapshot struct {
	t *testing.T
	v pd.SnapshotView
}

func (s *systemSTSTestSnapshot) View() pd.SnapshotView {
	raw, err := json.Marshal(s.v)
	if err != nil {
		s.t.Fatal(err)
	}
	var v pd.SnapshotView
	if err := json.Unmarshal(raw, &v); err != nil {
		s.t.Fatal(err)
	}
	return v
}
func (s *systemSTSTestSnapshot) Deadline() time.Time  { v, _ := s.v.ValidUntil.Time(); return v }
func (s *systemSTSTestSnapshot) BindingHash() pd.Hash { return s.v.BindingHash }
func (s *systemSTSTestSnapshot) Purpose() string      { return s.v.Binding.Call.Purpose }

type systemSTSTestCalls struct {
	t         *testing.T
	c         SystemSTSPolicy
	requests  []pd.CallRequest
	snapshots []*systemSTSTestSnapshot
	checks    int
	revoked   atomic.Bool
	mutate    func(int, *pd.SnapshotView)
}

func (f *systemSTSTestCalls) begin(ctx context.Context, r pd.CallRequest) (systemCallSnapshot, error) {
	if ctx.Err() != nil {
		return nil, ErrDenied
	}
	h := f.c.History
	f.requests = append(f.requests, r)
	owner, manifest, expiry := pd.ID(strings.Repeat("1", 64)), h.Evidence.ManifestHash, h.ObservationExpiresAt
	claim := pd.ClaimBinding{EvidenceID: h.Evidence.EvidenceID, EvidenceVersion: "2", ManifestHash: manifest, Owner: owner, ExpiresAt: expiry, PolicyHash: r.PolicyHash, RefsVersionHash: pd.Hash(strings.Repeat("2", 64))}
	v := pd.SnapshotView{Binding: pd.ExecutionBinding{Kind: "call", Scope: h.Scope, Subject: pd.Hash(f.c.SubjectIdentityHash), GrantID: h.GrantID, GrantGeneration: h.GrantGeneration, GrantVersion: "2", RunID: h.RunID, Call: r, Claim: &claim}, CapturedAt: systemExecutionStamp(time.Now()), ValidUntil: r.BudgetUntil, BindingHash: pd.Hash(hash([]byte(r.Purpose)))}
	v.Facts = pd.ExecutionFacts{
		Domain:     pd.DomainRecord{Scope: h.Scope, Epoch: h.DomainEpoch, Admission: h.Admission, IssuerIdentityHash: pd.Hash(f.c.IssuerIdentityHash)},
		Grant:      pd.GrantRecord{Scope: h.Scope, GrantID: h.GrantID, Generation: h.GrantGeneration, RowVersion: "2", Admission: h.Admission, Host: pd.Host{Service: &pd.ServiceHost{Kind: "service", WorkloadIdentityHash: pd.Hash(f.c.SubjectIdentityHash)}}},
		Run:        pd.RunRecord{Scope: h.Scope, RunID: h.RunID, TargetHash: h.TargetHash, InputHash: h.InputHash, EvidenceID: h.Evidence.EvidenceID, State: "pending", OwnerWriteExpiresAt: h.OwnerWriteExpiresAt, ObservedAt: &h.ObservedAt, ObservationExpiresAt: &h.ObservationExpiresAt},
		Target:     pd.TargetRecord{Scope: h.Scope, TargetHash: h.TargetHash},
		References: pd.ReferenceApproval{PolicyHash: r.PolicyHash, VersionHash: claim.RefsVersionHash},
		Evidence:   &pd.CallEvidence{EvidenceID: h.Evidence.EvidenceID, OwnerType: "system", OwnerID: h.Scope.Installation, EvidenceType: "capability_snapshot", State: "pending", RowVersion: "2", ManifestHash: &manifest, ClaimOwner: &owner, ClaimExpiresAt: &expiry},
	}
	if f.mutate != nil {
		f.mutate(len(f.requests), &v)
	}
	s := &systemSTSTestSnapshot{f.t, v}
	f.snapshots = append(f.snapshots, s)
	return s, nil
}
func (f *systemSTSTestCalls) recheck(ctx context.Context, _ systemCallSnapshot) error {
	f.checks++
	if ctx.Err() != nil || f.revoked.Load() {
		return ErrDenied
	}
	return nil
}

type systemSTSTestVerifier struct {
	checks  int
	fail    bool
	hook    func()
	request SystemSTSProfileRequest
}

func (v *systemSTSTestVerifier) VerifySystemSTSProfile(_ context.Context, r SystemSTSProfileRequest) error {
	v.checks++
	v.request = r
	if v.hook != nil {
		v.hook()
	}
	if v.fail {
		return ErrDenied
	}
	return nil
}

type systemSTSTestFixture struct {
	f             *systemPendingTestFixture
	c             SystemSTSPolicy
	calls         *systemSTSTestCalls
	verifier      *systemSTSTestVerifier
	s             *SystemSTSCredentials
	requests      atomic.Int32
	policy        atomic.Value
	afterExchange func()
	token         string
}

func newSystemSTSTestFixture(t *testing.T, mode string) *systemSTSTestFixture {
	t.Helper()
	f := newSystemPendingTestFixture(t)
	x := &systemSTSTestFixture{f: f, verifier: &systemSTSTestVerifier{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Authorization") != "" {
			t.Error("unsafe STS transport")
			w.WriteHeader(403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		if r.ParseForm() != nil || r.Form.Get("WebIdentityToken") != x.token || r.Form.Get("RoleArn") != x.c.STS.RoleARN || r.Form.Get("DurationSeconds") != "900" {
			t.Error("wrong system STS exchange")
			w.WriteHeader(403)
			return
		}
		x.policy.Store(r.Form.Get("Policy"))
		if x.afterExchange != nil {
			x.afterExchange()
		}
		if mode == "denied" {
			w.WriteHeader(403)
			io.WriteString(w, "private-provider-error")
			return
		}
		if mode == "redirect" {
			w.Header().Set("Location", "/other")
			w.WriteHeader(307)
			return
		}
		session := r.Form.Get("RoleSessionName")
		body := fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>system-sts</Audience><Provider>https://system.example</Provider><SubjectFromWebIdentityToken>system-producer</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/system-evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), session, session)
		if mode == "subject" {
			body = strings.Replace(body, "system-producer", "other-subject", 1)
		}
		if mode == "audience" {
			body = strings.Replace(body, "system-sts", "other-audience", 1)
		}
		if mode == "duplicate" {
			body = strings.Replace(body, "</AccessKeyId>", "</AccessKeyId><AccessKeyId>other</AccessKeyId>", 1)
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	dir := t.TempDir()
	x.c = SystemSTSPolicy{History: f.b.Request.History, Channel: f.channel, SubjectIdentityHash: strings.Repeat("a", 64), IssuerIdentityHash: strings.Repeat("b", 64), Subject: "system-producer", TokenFile: filepath.Join(dir, "sts-jwt"), AuthenticationAudience: "system-auth", AuthenticationTokenFile: filepath.Join(dir, "auth-jwt"), ProviderProfileHash: strings.Repeat("c", 64), STS: S3STSConfig{Store: S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "test-bucket", Root: f.channel.Root, Installation: string(f.b.Scope.Installation), Identity: f.channel.Store.Identity, Version: f.channel.Store.Version, CAPEM: ca, CASHA256: hash(ca)}, Endpoint: server.URL, RoleARN: "arn:aws:iam::123456789012:role/system-evidence", Issuer: "https://system.example", Audience: "system-sts", CAPEM: ca, CASHA256: hash(ca)}}
	raw, _ := json.Marshal(map[string]any{"iss": x.c.STS.Issuer, "sub": x.c.Subject, "aud": x.c.STS.Audience, "exp": time.Now().Add(5 * time.Minute).Unix()})
	x.token = "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	if err := os.WriteFile(x.c.TokenFile, []byte(x.token), 0600); err != nil {
		t.Fatal(err)
	}
	x.calls = &systemSTSTestCalls{t: t, c: x.c}
	return x
}
func (x *systemSTSTestFixture) start(t *testing.T) {
	t.Helper()
	var err error
	x.s, err = newSystemSTSCredentials(context.Background(), x.calls, x.f.prepared, x.c, x.verifier)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.s.Close)
}
func (x *systemSTSTestFixture) scope(op S3Operation) S3Scope {
	s := S3Scope{Ref: x.f.env.record.Ref, Operation: op}
	if op == S3Put {
		s.Object = ObjectInfo{SHA256: x.f.env.record.Manifest.ObjectHash, Size: x.f.env.record.Manifest.ObjectSize}
		s.Deadline = x.f.env.record.OwnerDeadline
	}
	return s
}
func TestSystemSTSFixedClaimExchange(t *testing.T) {
	for _, op := range []S3Operation{S3Stat, S3Put} {
		t.Run(string(op), func(t *testing.T) {
			x := newSystemSTSTestFixture(t, "")
			x.start(t)
			v, err := x.s.Resolve(context.Background(), x.scope(op))
			if err != nil || string(v.AccessKey) != s3TestAccess || v.Scope != x.scope(op) || v.ExpiresAt.After(x.s.until) {
				t.Fatal("exchange", err)
			}
			defer wipe(v.AccessKey)
			defer wipe(v.SecretKey)
			defer wipe(v.SessionToken)
			if len(x.calls.requests) != 2 || x.calls.requests[0].Purpose != "sts" || x.calls.requests[1].Purpose != "publish" || x.calls.checks != 8 || x.verifier.checks != 2 || x.requests.Load() != 1 {
				t.Fatal("missing rechecks or snapshot renewal", x.calls.checks)
			}
			if x.calls.requests[0].RefIdentityHash != pd.Hash(x.c.Channel.Write.Identity) || x.calls.requests[1].RefIdentityHash != pd.Hash(x.c.Channel.Store.Identity) || x.verifier.request.PolicyHash != SystemSTSPolicyHash(x.c) {
				t.Fatal("wrong refs or profile")
			}
			resource := "arn:aws:s3:::test-bucket/" + v.Scope.Ref.RelativeKey
			action := "s3:GetObject"
			if op == S3Put {
				action = "s3:PutObject"
			}
			policy := x.policy.Load().(string)
			if !stsPolicyAllows(t, policy, action, resource, "", "*", true, time.Now(), false) || stsPolicyAllows(t, policy, "s3:DeleteObjectVersion", resource, "", "*", true, time.Now(), true) || stsPolicyAllows(t, policy, action, resource+"-other", "", "*", true, time.Now(), true) || stsPolicyAllows(t, policy, action, resource, "", "*", true, v.ExpiresAt, true) {
				t.Fatal("policy escaped exact object/deadline")
			}
			if op == S3Put && stsPolicyAllows(t, policy, action, resource, "", "", true, time.Now(), true) {
				t.Fatal("unconditional PUT allowed")
			}
		})
	}
}
func TestSystemSTSRejectsScopeAndCredentials(t *testing.T) {
	for _, name := range []string{"range", "delete", "key", "store", "version", "hash", "size", "deadline", "stat_body", "profile", "revoked", "token_audience", "closed"} {
		t.Run(name, func(t *testing.T) {
			x := newSystemSTSTestFixture(t, "")
			x.start(t)
			scope := x.scope(S3Put)
			switch name {
			case "range":
				scope.Operation = S3Range
			case "delete":
				scope.Operation = S3Delete
			case "key":
				scope.Ref.RelativeKey += "other"
			case "store":
				scope.Ref.Identity = strings.Repeat("f", 64)
			case "version":
				scope.Ref.ImmutableVersion = "other"
			case "hash":
				scope.Object.SHA256 = strings.Repeat("f", 64)
			case "size":
				scope.Object.Size++
			case "deadline":
				scope.Deadline = scope.Deadline.Add(time.Second)
			case "stat_body":
				scope.Operation = S3Stat
			case "profile":
				x.verifier.fail = true
			case "revoked":
				x.calls.revoked.Store(true)
			case "token_audience":
				if err := os.WriteFile(x.c.TokenFile, []byte("wrong.token.signature"), 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				x.s.Close()
			}
			v, err := x.s.Resolve(context.Background(), scope)
			if err == nil || len(v.AccessKey) != 0 || x.requests.Load() != 0 {
				t.Fatal("invalid scope reached STS", name)
			}
		})
	}
}
func TestSystemSTSRevocationAndResponseFailures(t *testing.T) {
	for _, name := range []string{"provider_revokes", "profile_revokes", "snapshot_changes", "profile_after_exchange", "denied", "redirect", "subject", "audience", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			x := newSystemSTSTestFixture(t, name)
			x.start(t)
			switch name {
			case "provider_revokes":
				x.afterExchange = func() { x.calls.revoked.Store(true) }
			case "profile_revokes":
				x.verifier.hook = func() { x.calls.revoked.Store(true) }
			case "snapshot_changes":
				x.calls.snapshots[0].v.Binding.GrantVersion = "9"
			case "profile_after_exchange":
				x.afterExchange = func() { x.verifier.fail = true }
			}
			v, err := x.s.Resolve(context.Background(), x.scope(S3Put))
			if err == nil || len(v.AccessKey) != 0 || len(v.SecretKey) != 0 || len(v.SessionToken) != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("returned credentials after rejection", name)
			}
			if (name == "profile_revokes" || name == "snapshot_changes") && x.requests.Load() != 0 {
				t.Fatal("sent before current authority")
			}
		})
	}
}
func TestSystemSTSSnapshotAdmission(t *testing.T) {
	for _, name := range []string{"scope", "run", "subject", "input", "issuer", "manifest", "claim", "claim_version", "deadline", "claim_expiry", "refs", "different_generation", "different_evidence", "policy", "historical_time", "run_target", "locked_target"} {
		t.Run(name, func(t *testing.T) {
			x := newSystemSTSTestFixture(t, "")
			x.calls.mutate = func(n int, v *pd.SnapshotView) {
				if n != 2 {
					return
				}
				switch name {
				case "scope":
					v.Binding.Scope.Database = "other"
				case "run":
					v.Binding.RunID = "other-run"
				case "subject":
					v.Binding.Subject = pd.Hash(strings.Repeat("f", 64))
				case "input":
					v.Facts.Run.InputHash = pd.Hash(strings.Repeat("f", 64))
				case "issuer":
					v.Facts.Domain.IssuerIdentityHash = pd.Hash(strings.Repeat("f", 64))
				case "manifest":
					v.Binding.Claim.ManifestHash = pd.Hash(strings.Repeat("f", 64))
				case "claim":
					v.Binding.Claim = nil
				case "claim_version":
					v.Binding.Claim.EvidenceVersion = "9"
				case "deadline":
					v.ValidUntil = systemExecutionStamp(time.Now().Add(time.Hour))
				case "claim_expiry":
					v.Binding.Claim.ExpiresAt = systemExecutionStamp(time.Now().Add(-time.Second))
				case "refs":
					v.Facts.References.VersionHash = pd.Hash(strings.Repeat("f", 64))
				case "different_generation":
					v.Binding.GrantGeneration = "9"
				case "different_evidence":
					v.Facts.Evidence.State = "write_unknown"
				case "policy":
					v.Facts.References.PolicyHash = pd.Hash(strings.Repeat("f", 64))
				case "historical_time":
					v.Facts.Run.OwnerWriteExpiresAt = systemExecutionStamp(time.Now().Add(time.Hour))
				case "run_target":
					v.Facts.Run.TargetHash = pd.Hash(strings.Repeat("f", 64))
				case "locked_target":
					v.Facts.Target.TargetHash = pd.Hash(strings.Repeat("f", 64))
				}
			}
			if s, err := newSystemSTSCredentials(context.Background(), x.calls, x.f.prepared, x.c, x.verifier); err == nil || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("admitted changed snapshot", name)
			}
			if x.requests.Load() != 0 {
				t.Fatal("provider before admission")
			}
		})
	}
}
func TestSystemSTSConstructionAndTokenIsolation(t *testing.T) {
	for _, name := range []string{"nil_verifier", "same_audience", "same_token", "relative_token", "store", "ca", "zero_prepared", "public_nil_claim"} {
		t.Run(name, func(t *testing.T) {
			x := newSystemSTSTestFixture(t, "")
			c := x.c
			p := x.f.prepared
			var verifier SystemSTSProfileVerifier = x.verifier
			switch name {
			case "nil_verifier":
				verifier = nil
			case "same_audience":
				c.AuthenticationAudience = c.STS.Audience
			case "same_token":
				c.AuthenticationTokenFile = strings.ToUpper(c.TokenFile)
			case "relative_token":
				c.TokenFile = "token"
			case "store":
				c.STS.Store.Identity = strings.Repeat("f", 64)
			case "ca":
				c.STS.CASHA256 = strings.Repeat("f", 64)
			case "zero_prepared":
				p = Prepared{}
			case "public_nil_claim":
				if s, err := NewSystemExecutionSTSCredentials(context.Background(), &pd.Execution{}, &pd.ExecutionHandle{}, nil, p, c, verifier); err == nil || s != nil {
					t.Fatal("nil private claim")
				}
				return
			}
			if s, err := newSystemSTSCredentials(context.Background(), x.calls, p, c, verifier); err == nil || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("admitted profile", name)
			}
		})
	}
	x := newSystemSTSTestFixture(t, "")
	x.start(t)
	// The wire helper owns and wipes both token copies even though the system
	// adapter shares no legacy config/attempt fields or legacy grant authority.
	scope := x.scope(S3Put)
	var copies [][]byte
	v, err := x.s.transport.exchange(context.Background(), scope, func(ctx context.Context, scope S3Scope) (stsExchangeGrant, error) {
		g, err := x.s.authorize(ctx, scope)
		copies = append(copies, g.Token)
		return g, err
	})
	if err != nil {
		t.Fatal(err)
	}
	wipe(v.AccessKey)
	wipe(v.SecretKey)
	wipe(v.SessionToken)
	if len(copies) != 2 {
		t.Fatal("wrong authorization count")
	}
	for _, b := range copies {
		for _, v := range b {
			if v != 0 {
				t.Fatal("token not erased")
			}
		}
	}
}
