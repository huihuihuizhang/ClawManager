package recovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestCheckedInSchemaMatchesTypes(t *testing.T) {
	want, err := SchemaBytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("contracts.schema.json")
	if err != nil || !bytes.Equal(bytes.TrimSpace(got), want) {
		t.Fatal("regenerate contracts.schema.json with backup-contract-schema", err)
	}
}

func TestRetentionProtectsHistoricalPointsHoldsAndLeases(t *testing.T) {
	g := RecoveryGroup{"origin", "k8s-cluster", "other-site"}
	missing := RecoveryGroup{"other-origin", "k3s-single-node", "other-site"}
	rows := []PruneArtifact{}
	for _, id := range []string{"old", "new", "held", "promotion", "leased", "active", "unfinished"} {
		a := PruneArtifact{ID: id, Group: g, Terminal: true, FinishedAt: 100, CommittedAt: 100, State: "committed", HistoricalEligible: true, Locator: Locator{"s3", "fixture", "root/fixture", "other-site"}, GuardVersion: 1}
		switch id {
		case "new":
			a.CommittedAt = 200
			a.State = "corrupt"
		case "held":
			a.ManualHold = true
			a.HistoricalEligible = false
		case "promotion":
			a.PromotionHold = true
			a.HistoricalEligible = false
		case "leased":
			a.LeaseUntil = 1001
			a.HistoricalEligible = false
		case "active":
			a.ActiveFinalizer = true
			a.HistoricalEligible = false
		case "unfinished":
			a.Terminal = false
		}
		rows = append(rows, a)
	}
	p, e := PlanRetention(1000, 100, 1, []RecoveryGroup{g, missing}, rows, ref("retention"))
	if e != nil || len(p.Candidates) != 1 || p.Candidates[0].ID != "old" || p.Shortage[groupKey(missing)] != 1 {
		t.Fatal("unsafe prune candidates", p, e)
	}
	rows[0].GuardVersion++
	changed, e := PlanRetention(1000, 100, 1, []RecoveryGroup{g, missing}, rows, ref("retention"))
	if e != nil || changed.SHA256 == p.SHA256 {
		t.Fatal("confirmation does not bind resource guard")
	}
	if _, e = PlanRetention(1000, 100, 1, nil, rows, ref("retention")); e == nil {
		t.Fatal("unconfigured recovery group pruned")
	}
}

func redisFixture() (RedisPolicy, RedisItem) {
	p := RedisPolicy{Source: ref("source-redis"), Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", Prefixes: []string{"team:"}, MaxItems: 10, MaxBytes: 8192, MaxClockSkew: 5}
	v := RedisItem{Key: []byte("team:fixture"), Type: "string", Dump: []byte("synthetic-dump"), CapturedAt: 1000, PTTL: 100, ExpiresAt: 1100}
	v.SHA256 = Hash(v.Dump)
	return p, v
}
func TestRedisAbsoluteExpiryIsolationAndClockDrift(t *testing.T) {
	p, v := redisFixture()
	if ttl, skip, e := p.RemainingTTL(v, 1050, 1050); e != nil || skip || ttl != 50 {
		t.Fatal(ttl, skip, e)
	}
	if _, skip, e := p.RemainingTTL(v, 1101, 1101); e != nil || !skip {
		t.Fatal("expired key resurrected", e)
	}
	if _, _, e := p.RemainingTTL(v, 1050, 1040); e == nil {
		t.Fatal("clock drift clamped")
	}
	p.TTLPolicy = "restart_remaining"
	if p.Validate() == nil {
		t.Fatal("acceptance resets TTL")
	}
	p.Purpose = "functional_test"
	if ttl, skip, e := p.RemainingTTL(v, 1200, 1200); e != nil || skip || ttl != 100 {
		t.Fatal(ttl, skip, e)
	}
	p.CaptureMode = "rdb"
	if p.Validate() == nil {
		t.Fatal("shared Redis full-instance snapshot allowed")
	}
}

type redisReader struct {
	pages    int
	conflict bool
}

func (r *redisReader) ServerTime(context.Context) (int64, error) { return 1000, nil }
func (r *redisReader) ScanDump(context.Context, RedisPolicy, string) ([]RedisItem, string, error) {
	r.pages++
	_, v := redisFixture()
	if r.pages == 1 {
		return []RedisItem{v}, "next", nil
	}
	if r.conflict {
		v.Dump = []byte("changed")
		v.SHA256 = Hash(v.Dump)
	}
	return []RedisItem{v}, "", nil
}

type redisSink struct{ count int }

func (s *redisSink) SealRedis(_ context.Context, _ CaptureRequest, produce func(io.Writer) error) (PartResult, error) {
	var b bytes.Buffer
	if e := produce(&b); e != nil {
		return PartResult{}, e
	}
	s.count = bytes.Count(b.Bytes(), []byte(`"key"`))
	return PartResult{Schema: Version, Part: "redis", Status: "completed", Checkpoint: ref("checkpoint"), Objects: []Object{{"redis/data.enc", "v1", 1, Hash([]byte("x"))}}}, nil
}
func TestRedisCaptureRejectsChangingDuplicatesAndReportsBoundedConsistency(t *testing.T) {
	p, _ := redisFixture()
	req := CaptureRequest{Task: "task", Attempt: 1, Deadline: 2000, Config: ref("config"), CaptureContextSHA256: ref("capture").SHA256}
	sink := &redisSink{}
	result, e := CaptureRedis(context.Background(), req, p, &redisReader{}, sink, func(context.Context) (int64, error) { return 1000, nil })
	if e != nil || result.Consistency != "bounded" || len(result.Warnings) != 1 || sink.count != 1 {
		t.Fatal("incorrect SCAN consistency/dedup", result, e)
	}
	if _, e = CaptureRedis(context.Background(), req, p, &redisReader{conflict: true}, sink, func(context.Context) (int64, error) { return 1000, nil }); !errors.Is(e, ErrConflict) {
		t.Fatal("changing SCAN duplicate accepted", e)
	}
}

func TestScanFinishRevalidatesSignedBytesAndCurrentTrust(t *testing.T) {
	p, in, _, cat := fixture(t)
	if _, e := p.Publish(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	j := &memoryScans{trust: p.Trust, failFinish: true}
	s := Scanner{cat, p.Trust, j, p.Now}
	if _, e := s.Step(context.Background(), "scan", 2000); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	j.records[0].Record.Registration.DecisionTime++
	if _, e := s.Step(context.Background(), "scan", 2000); e == nil {
		t.Fatal("parsed record tampering accepted")
	}
	j.records[0].Record.Registration.DecisionTime--
	j.trust = append(Trust(nil), p.Trust...)
	j.trust[2].Compromised = true
	if _, e := s.Step(context.Background(), "scan", 2000); e == nil {
		t.Fatal("compromised key accepted at final commit")
	}
}

func TestUncertainGrantCannotBeFinalAbsentUntilExpiry(t *testing.T) {
	r := requestFor("action", "manifest.json", []byte(`{}`), 2000)
	o := Observation{State: "absent", Key: r.Key, Strong: true, Proof: ref("absence"), ValidUntil: 3000}
	if o.ValidateOutcome(r, "absent", 1999) == nil {
		t.Fatal("in-flight grant finalized absent")
	}
	if e := o.ValidateOutcome(r, "absent", 2000); e != nil {
		t.Fatal(e)
	}
	o.Strong = false
	if o.ValidateOutcome(r, "absent", 2000) == nil {
		t.Fatal("ordinary 404 accepted")
	}
}

func TestMissingStaleOrDifferentProviderCapabilitiesDeny(t *testing.T) {
	identity := ref("catalog")
	caps := []Capability{}
	for _, code := range []string{"scoped_read_credential", "tls_verified", "versioned_absence_proof", "conditional_create", "checksum_bound_request", "content_length_bound_request", "native_deadline_enforced", "scoped_append_credential", "inventory_manifest_listing"} {
		caps = append(caps, Capability{"catalog", code, "supported", identity, 900, 2000})
	}
	if e := RequireCapabilities(caps, identity, 1000, true, true); e != nil {
		t.Fatal(e)
	}
	if RequireCapabilities(caps[:len(caps)-1], identity, 1000, true, true) == nil {
		t.Fatal("plain listing treated as immutable inventory")
	}
	if RequireCapabilities(caps, ref("changed-provider"), 1000, true, true) == nil {
		t.Fatal("other provider evidence reused")
	}
	caps[0].ExpiresAt = 1000
	if RequireCapabilities(caps, identity, 1000, true, true) == nil {
		t.Fatal("stale proof accepted")
	}
}

func TestProviderRootAndFrozenProviderIdentityCannotChange(t *testing.T) {
	p, in, art, cat := fixture(t)
	in.Locator.Bucket = "wrong-bucket"
	if _, e := p.Publish(context.Background(), in); e == nil || art.creates != 0 || cat.creates != 0 {
		t.Fatal("wrong artifact root registered", e)
	}
	s := newStore()
	s.loseReply = true
	j := newActions()
	f := Finalizer{s, j, func() int64 { return 1000 }}
	r := requestFor("action", "manifest.json", []byte(`{}`), 2000)
	if e := f.Execute(context.Background(), r); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	s.identity = ref("different-provider")
	if e := f.Execute(context.Background(), r); !errors.Is(e, ErrConflict) || s.creates != 1 {
		t.Fatal("takeover changed frozen provider", e)
	}
}

type fixtureCollector struct {
	part    string
	bounded bool
}

func (c fixtureCollector) Capture(context.Context, CaptureRequest) (PartResult, error) {
	consistency := "strong"
	if c.bounded {
		consistency = "bounded"
	}
	return PartResult{Schema: Version, Part: c.part, Status: "completed", Consistency: consistency, Checkpoint: ref(c.part), Objects: []Object{{c.part + "/fixture.enc", "version", 1, Hash([]byte("x"))}}}, nil
}

type fixtureVerifier struct{ fail bool }

func (v fixtureVerifier) Verify(context.Context, ReadOnlyTarget, string) (Summary, error) {
	if v.fail {
		return Summary{}, ErrUnavailable
	}
	return Summary{1, "passed", ref("verify")}, nil
}
func TestRegistryRequiresAllPartsAndIndependentDomainEvidence(t *testing.T) {
	r := Registry{Collectors: map[string]Collector{}, Verifiers: map[string]Verifier{}}
	for _, p := range RequiredParts() {
		r.Collectors[p] = fixtureCollector{p, p == "redis"}
	}
	for _, d := range append(SixDomains(), "control_plane") {
		r.Verifiers[d] = fixtureVerifier{}
	}
	request := CaptureRequest{"task", 1, 2000, ref("config"), Hash([]byte("capture"))}
	batch, e := r.Capture(context.Background(), request)
	if e != nil || batch.Consistency != "bounded" || len(batch.Parts) != 6 {
		t.Fatal(batch, e)
	}
	target := ReadOnlyTarget{"target", ref("read-only"), ref("isolation")}
	if got, e := r.Verify(context.Background(), target, "restore_validate"); e != nil || len(got) != 7 {
		t.Fatal(got, e)
	}
	r.Verifiers["teams"] = fixtureVerifier{true}
	if _, e = r.Verify(context.Background(), target, "restore_validate"); e == nil {
		t.Fatal("failed team verifier ignored")
	}
	delete(r.Collectors, "redis")
	if _, e = r.Capture(context.Background(), request); e == nil {
		t.Fatal("missing part substituted with empty result")
	}
}

func TestScanPageChainRejectsCursorTampering(t *testing.T) {
	p, in, _, cat := fixture(t)
	if _, e := p.Publish(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	j := &memoryScans{trust: p.Trust, failFinish: true}
	s := Scanner{cat, p.Trust, j, p.Now}
	if _, e := s.Step(context.Background(), "scan", 2000); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	j.pages[0].Page.Cursor = "wrong-cursor"
	if _, e := s.Step(context.Background(), "scan", 2000); e == nil {
		t.Fatal("page cursor tampering accepted")
	}
}
