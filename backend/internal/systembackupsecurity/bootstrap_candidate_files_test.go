package systembackupsecurity

// Real temporary files plus an explicitly synthetic independent authority.
// No deployment permission, actual database locks or production grant is proved.
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type candidateFileFixture struct {
	base   *pinnedAuthorityFixture
	a      *bootstrapCandidateFileAuthority
	config BootstrapDeploymentConfig
	paths  map[string]string
}

func newCandidateFileFixture(t *testing.T, configure func(*pinnedAuthorityFixture)) candidateFileFixture {
	t.Helper()
	f := newPinnedAuthorityFixture(t)
	if configure != nil {
		configure(f)
	}
	dir := t.TempDir()
	c := BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: f.g.InstallationID, ExpectedServerUUID: f.g.ServerUUID, ExpectedDatabase: f.g.Database, ConfigSHA256: f.g.ConfigSHA256, GrantFile: filepath.Join(dir, "original-grant.json"), RegistryDirectory: filepath.Join(dir, "original-registries")}
	grantBytes, err := json.Marshal(BootstrapGrantFile{"system-backup-offline-bootstrap-grant.v1", f.notBefore, f.expires, f.g})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.GrantFile, grantBytes, 0600); err != nil {
		t.Fatal(err)
	}
	c.GrantSHA256 = registrationHash(string(grantBytes))
	paths := map[string]string{"grant": c.GrantFile}
	for _, ref := range f.c.Registries() {
		path := filepath.Join(c.RegistryDirectory, ref.Kind, ref.Version, ref.SHA256+".json")
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, f.files[ref.Kind], 0600); err != nil {
			t.Fatal(err)
		}
		paths[ref.Kind] = path
	}
	original, err := NewBootstrapCandidateFileAuthority(c, f.inner)
	if err != nil {
		t.Fatal(err)
	}
	a := original.(*bootstrapCandidateFileAuthority)
	a.snapshot.clock = func() time.Time { return f.now }
	return candidateFileFixture{f, a, c, paths}
}
func (f candidateFileFixture) prepare(t *testing.T) *bootstrapCandidateFileSession {
	t.Helper()
	p, err := f.a.PrepareBootstrapCandidates(f.base.ctx, f.base.g, f.base.c, f.base.r)
	if err != nil {
		t.Fatal(err)
	}
	return p.Session.(*bootstrapCandidateFileSession)
}
func corruptCandidateFile(t *testing.T, path, mode string) {
	t.Helper()
	if mode == "removed" {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		return
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(bytes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapCandidateFilesRequireClosedOriginalProfileAndAuthority(t *testing.T) {
	f := newCandidateFileFixture(t, nil)
	for _, mode := range []string{"schema", "installation", "server", "database", "grant_sha", "config_sha", "relative_grant", "relative_registry", "nul_path", "nil_authority", "typed_nil_authority"} {
		t.Run(mode, func(t *testing.T) {
			c := f.config
			var original BootstrapCandidateAuthority = f.base.inner
			switch mode {
			case "schema":
				c.SchemaVersion = "other"
			case "installation":
				c.InstallationID = "other"
			case "server":
				c.ExpectedServerUUID = "other"
			case "database":
				c.ExpectedDatabase = "wrong/database"
			case "grant_sha":
				c.GrantSHA256 = "bad"
			case "config_sha":
				c.ConfigSHA256 = "bad"
			case "relative_grant":
				c.GrantFile = "grant.json"
			case "relative_registry":
				c.RegistryDirectory = "registries"
			case "nul_path":
				c.GrantFile += "\x00"
			case "nil_authority":
				original = nil
			case "typed_nil_authority":
				var absent *pinnedSyntheticAuthority
				original = absent
			}
			if a, err := NewBootstrapCandidateFileAuthority(c, original); err == nil || a != nil {
				t.Fatal("unclosed file profile accepted")
			}
		})
	}
	other := f.base.g
	other.InstallationID += "_other"
	if _, err := f.a.PrepareBootstrapCandidates(f.base.ctx, other, f.base.c, f.base.r); err == nil {
		t.Fatal("profile lost original deployment scope")
	}
}

func TestBootstrapCandidateFilesRejectLateOriginalGrantAndRBACChanges(t *testing.T) {
	for _, kind := range []string{"grant", "rbac_bindings"} {
		for _, mode := range []string{"removed", "changed"} {
			for _, phase := range []string{"before_authorize", "inside_authorize", "before_final_new", "inside_final_new", "before_final_history", "inside_final_history"} {
				t.Run(kind+"/"+mode+"/"+phase, func(t *testing.T) {
					f := newCandidateFileFixture(t, nil)
					s := f.prepare(t)
					b := f.base
					x := &pinnedSyntheticSQL{now: b.now}
					mutate := func() { corruptCandidateFile(t, f.paths[kind], mode) }
					if phase == "before_authorize" {
						mutate()
						if _, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now); err == nil || b.inner.calls["authorize"] != 0 {
							t.Fatal("cached sources authorized late revocation")
						}
						return
					}
					if phase == "inside_authorize" {
						b.inner.authorizeFn = func(pd.BootstrapSQL, pd.BootstrapConsumptionRequest, time.Time) (pd.BootstrapConsumptionAdmission, error) {
							mutate()
							return pd.BootstrapConsumptionAdmission{BindingHash: b.inner.want, IdentityExpiresAt: pd.Timestamp(b.expires.Format("2006-01-02T15:04:05.000000Z"))}, nil
						}
						if _, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now); err == nil {
							t.Fatal("inner callback hid source revocation")
						}
						return
					}
					if _, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now); err != nil {
						t.Fatal(err)
					}
					if strings.HasPrefix(phase, "inside") {
						b.inner.recheckFn = func(pd.BootstrapReadSQL) error { mutate(); return nil }
					} else {
						mutate()
					}
					if err := s.Recheck(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{Replayed: strings.HasSuffix(phase, "history")}, b.now); err == nil {
						t.Fatal("Work-end current source revocation missed")
					}
				})
			}
		}
	}
}

func TestBootstrapCandidateFilesKeepResourceFailureAfterHistoricalBranch(t *testing.T) {
	for _, when := range []string{"before_prepare", "after_prepare"} {
		t.Run(when, func(t *testing.T) {
			f := newCandidateFileFixture(t, nil)
			b := f.base
			if when == "before_prepare" {
				corruptCandidateFile(t, f.paths["parts"], "removed")
			}
			s := f.prepare(t)
			if when == "after_prepare" {
				corruptCandidateFile(t, f.paths["parts"], "removed")
			}
			x := &pinnedSyntheticSQL{now: b.now}
			if _, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now); err != nil {
				t.Fatal("resource file became current read authority", err)
			}
			if err := s.Recheck(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{Replayed: true}, b.now); err != nil {
				t.Fatal("exact historical read blocked", err)
			}
			if err := s.LockReferences(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}); err == nil || b.inner.calls["references"] != 0 || b.inner.calls["reserve"] != 0 {
				t.Fatal("new resource use passed missing original bytes")
			}
			if err := s.Recheck(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}, b.now); err == nil {
				t.Fatal("new-use final check ignored missing registry")
			}
		})
	}
	// Once source capture failed, restoration cannot renew this attempt's
	// original resource observation. A separately prepared attempt is required.
	f := newCandidateFileFixture(t, nil)
	saved, err := os.ReadFile(f.paths["parts"])
	if err != nil {
		t.Fatal(err)
	}
	corruptCandidateFile(t, f.paths["parts"], "removed")
	s := f.prepare(t)
	if err = os.WriteFile(f.paths["parts"], saved, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.LockReferences(f.base.ctx, &pinnedSyntheticSQL{now: f.base.now}, f.base.r, pd.BootstrapConsumptionFacts{}); err == nil {
		t.Fatal("restoration refreshed original failed observation")
	}
}

type candidateFileClock struct {
	*pinnedSyntheticSQL
	after   int
	advance func()
}

func (x *candidateFileClock) SampleTime(ctx context.Context) (time.Time, error) {
	x.samples++
	if x.samples == x.after {
		x.advance()
	}
	return x.now, x.err
}

func TestBootstrapCandidateFilesBoundLocalReadsByOriginalWindowAndContext(t *testing.T) {
	for _, stage := range []string{"authorize", "references", "final"} {
		t.Run(stage, func(t *testing.T) {
			f := newCandidateFileFixture(t, nil)
			s := f.prepare(t)
			b := f.base
			x := &candidateFileClock{pinnedSyntheticSQL: &pinnedSyntheticSQL{now: b.now}, after: 2}
			if stage == "references" {
				x.after = 3
			}
			if stage == "final" {
				x.after = 4
			}
			x.advance = func() { x.now = b.expires }
			var err error
			switch stage {
			case "authorize":
				_, err = s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now)
			case "references":
				err = s.LockReferences(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{})
			case "final":
				err = s.Recheck(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{Replayed: true}, b.now)
			}
			if err == nil {
				t.Fatal("local source wait extended original deadline")
			}
		})
	}
	f := newCandidateFileFixture(t, nil)
	s := f.prepare(t)
	ctx, cancel := context.WithCancel(f.base.ctx)
	cancel()
	if err := s.Recheck(ctx, &pinnedSyntheticSQL{now: f.base.now}, f.base.r, pd.BootstrapConsumptionFacts{Replayed: true}, f.base.now); err == nil {
		t.Fatal("canceled source check allowed")
	}
	for _, offset := range []int{0, 90 * 60} {
		t.Run(fmt.Sprintf("original_offset_%d", offset), func(t *testing.T) {
			f := newCandidateFileFixture(t, func(b *pinnedAuthorityFixture) {
				b.expires = b.now.Add(30*time.Second + time.Nanosecond).In(time.FixedZone("original", offset))
				b.notBefore = b.notBefore.In(time.FixedZone("original", offset))
				b.now = b.expires.UTC().Truncate(time.Microsecond)
			})
			s := f.prepare(t)
			b := f.base
			x := &pinnedSyntheticSQL{now: b.now}
			a, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now)
			if err != nil {
				t.Fatal("original fractional/offset grant narrowed", err)
			}
			deadline, err := a.IdentityExpiresAt.Time()
			if err != nil || !deadline.Equal(b.now.Add(time.Microsecond)) {
				t.Fatal("original file deadline changed", deadline, err)
			}
			x.now = deadline
			if _, err = s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, deadline); err == nil {
				t.Fatal("original expiry equality allowed")
			}
		})
	}
}

func TestBootstrapCandidateFilesDelegateResourcesOnceAndRedact(t *testing.T) {
	f := newCandidateFileFixture(t, nil)
	s := f.prepare(t)
	b := f.base
	x := &pinnedSyntheticSQL{now: b.now}
	if _, err := s.Authorize(b.ctx, x, b.r, pd.DomainRecord{}, b.now); err != nil {
		t.Fatal(err)
	}
	for stage, call := range map[string]func() error{
		"hosts":      func() error { return s.LockHosts(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}) },
		"references": func() error { return s.LockReferences(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}) },
		"reserve":    func() error { return s.Reserve(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}) },
		"evidence":   func() error { _, err := s.LockEvidence(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}); return err },
		"recheck":    func() error { return s.Recheck(b.ctx, x, b.r, pd.BootstrapConsumptionFacts{}, b.now) },
	} {
		if err := call(); err != nil || b.inner.calls[stage] != 1 {
			t.Fatal("original resource stage bypassed/double charged", stage, err, b.inner.calls)
		}
	}
	for _, value := range []any{f.a, *f.a, s, *s} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, value)
			if strings.Contains(printed, f.config.GrantFile) || strings.Contains(printed, f.config.GrantSHA256) || strings.Contains(printed, b.g.ChangeReason) {
				t.Fatal("private source profile formatted")
			}
		}
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("private source profile serialized")
		}
	}
	var authority bootstrapCandidateFileAuthority
	var session bootstrapCandidateFileSession
	if json.Unmarshal([]byte(`{}`), &authority) == nil || json.Unmarshal([]byte(`{}`), &session) == nil {
		t.Fatal("JSON manufactured current-source authority")
	}
}
