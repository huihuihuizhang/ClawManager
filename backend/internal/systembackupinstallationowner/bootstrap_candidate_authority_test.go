package systembackupinstallationowner

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Named synthetic ORIGINAL authority tests delegation only; it never supplies
// actual missing host/provider/evidence owner authority or admission evidence.
type captureOriginalFixture struct {
	phases []string
	deny   string
}

func (a *captureOriginalFixture) visit(phase string) error {
	a.phases = append(a.phases, phase)
	if a.deny == phase {
		return sec.ErrRegistrationPermission
	}
	return nil
}
func (a *captureOriginalFixture) PrepareBootstrapCandidates(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig, pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	return sec.PreparedBootstrapCandidateAuthority{Session: a}, a.visit("prepare")
}
func (a *captureOriginalFixture) Authorize(_ context.Context, _ pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, _ pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	h, e := pd.BootstrapConsumptionHash(request)
	if e != nil {
		return pd.BootstrapConsumptionAdmission{}, e
	}
	return pd.BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: captureTestStamp(now.Add(time.Hour)), DependencyExpiresAt: captureTestStamp(now.Add(time.Hour))}, a.visit("authorize")
}
func (a *captureOriginalFixture) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("hosts")
}
func (a *captureOriginalFixture) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("references")
}
func (a *captureOriginalFixture) Reserve(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("reserve")
}
func (a *captureOriginalFixture) LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	return nil, a.visit("evidence")
}
func (a *captureOriginalFixture) Recheck(context.Context, pd.BootstrapReadSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts, time.Time) error {
	return a.visit("recheck")
}
func captureTestStamp(t time.Time) pd.Timestamp {
	return pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}

type captureCandidateFixture struct {
	a        *CaptureSigningCandidateAuthority
	original *captureOriginalFixture
	state    *ownerSQLData
	request  pd.BootstrapConsumptionRequest
	grant    sec.OfflineBootstrapGrant
	config   sec.BootstrapConfig
	ctx      context.Context
	signs    *int
}

func newCaptureCandidateFixture(t *testing.T) captureCandidateFixture {
	t.Helper()
	_, state, _, ctx := newOwnerSQLFixture(t)
	observer, auth, signs := signingObserverFixture(t, "")
	t.Cleanup(observer.Close)
	key := state.f.private
	f := state.f
	f.record, f.pin = auth.record, auth.pin
	f.pin.Issuer = key.Public().(ed25519.PublicKey)
	f.record.MatrixKey = "k8s-cluster"
	bindFixtureConfig(t, &f)
	f.resign(t)
	state.f = f
	state.head.NotBefore, state.head.Until, state.head.RecordSHA256 = f.record.NotBefore, f.record.Until, f.pin.RecordSHA256
	state.headRaw, _ = EncodeHead(state.head)
	state.headSig = ed25519.Sign(key, append([]byte(HeadDomain), state.headRaw...))
	state.now = time.Now().UTC().Truncate(time.Microsecond)
	dir := t.TempDir()
	files := RecordFiles{RecordFile: filepath.Join(dir, "record"), SignatureFile: filepath.Join(dir, "signature")}
	if os.WriteFile(files.RecordFile, f.raw, 0600) != nil || os.WriteFile(files.SignatureFile, f.sig, 0600) != nil {
		t.Fatal("controlled original source files")
	}
	validator, e := NewCaptureSigningValidator(f.pin, files, observer)
	if e != nil {
		t.Fatal(e)
	}
	original := new(captureOriginalFixture)
	a, e := NewCaptureSigningCandidateAuthority(original, validator)
	if e != nil {
		t.Fatal(e)
	}
	config := captureConfigFixture(t, f.record.Reference)
	grant := fixtureGrant(f.record, config)
	var vectors struct {
		Positive []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		} `json:"positive"`
	}
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if e != nil || json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("producer vector fixture")
	}
	var result pd.ResultRequest
	for _, vector := range vectors.Positive {
		if vector.ID == "unconfigured_signing" {
			result, e = pd.DecodeResult(vector.Value)
		}
	}
	if e != nil || result.Admission.Unconfigured == nil {
		t.Fatal("unconfigured vector", e)
	}
	scope := pd.Scope{ServerUUID: pd.ServerUUID(grant.ServerUUID), Database: pd.Database(grant.Database), Installation: pd.Installation(grant.InstallationID)}
	result.Scope, result.Evidence.OwnerID = scope, scope.Installation
	result.Admission.Unconfigured.CandidateHash = pd.Hash(config.SHA256())
	result.Admission.Unconfigured.RegistrySetHash = pd.Hash(f.record.RegistrySetSHA256)
	result.Admission.Unconfigured.RefSetHash = pd.Hash(f.record.ReferenceSetSHA256)
	request := pd.BootstrapConsumptionRequest{Scope: scope, OfflineGrantHash: pd.Hash(f.record.GrantSHA256), ConfigHash: pd.Hash(config.SHA256()), RegistrySetHash: pd.Hash(f.record.RegistrySetSHA256), RefSetHash: pd.Hash(f.record.ReferenceSetSHA256), ActorID: "7", Username: grant.Username, MatrixKey: grant.MatrixKey, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: grant.IdempotencyKey, Candidates: []pd.BootstrapCandidateSelection{{Purpose: "capture_signing", ReferenceIdentityHash: pd.Hash(f.record.Reference.IdentityHash), ReferenceVersion: pd.RefVersion(f.record.Reference.Version), MappingHash: pd.Hash(strings.Repeat("a", 64)), Request: result, ResultVersion: "1"}}}
	selection, e := pd.BootstrapConsumptionHash(request)
	if e != nil {
		t.Fatal("synthetic exact candidate request", e)
	}
	// The original owner signature, not the candidate DTO, selects the exact
	// complete producer association hash consumed by PrepareCandidateAttempt.
	f.record.SelectionSHA256 = string(selection)
	f.resign(t)
	state.f = f
	state.head.RecordSHA256 = f.pin.RecordSHA256
	state.headRaw, _ = EncodeHead(state.head)
	state.headSig = ed25519.Sign(key, append([]byte(HeadDomain), state.headRaw...))
	if os.WriteFile(files.RecordFile, f.raw, 0600) != nil || os.WriteFile(files.SignatureFile, f.sig, 0600) != nil {
		t.Fatal("exact signed original selection source")
	}
	a.capture, e = NewCaptureSigningValidator(f.pin, files, observer)
	if e != nil {
		t.Fatal(e)
	}
	return captureCandidateFixture{a: a, original: original, state: state, request: request, grant: grant, config: config, ctx: ctx, signs: signs}
}

type captureGuardConnector struct{ state *ownerSQLData }

func (c captureGuardConnector) Driver() driver.Driver { return ownerSQLDriver{} }
func (c captureGuardConnector) Connect(context.Context) (driver.Conn, error) {
	return &captureGuardConn{ownerSQLData: c.state}, nil
}

type captureGuardConn struct{ *ownerSQLData }

func (c *captureGuardConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))" {
		return &ownerSQLRows{values: []driver.Value{c.f.pin.ServerUUID, c.f.pin.Database, c.now, int64(0)}}, nil
	}
	return c.ownerSQLData.QueryContext(ctx, q, args)
}

type captureCandidatePolicy struct {
	fixture   captureCandidateFixture
	session   sec.BootstrapCandidateAuthoritySession
	replay    bool
	admission pd.BootstrapConsumptionAdmission
}

func (p *captureCandidatePolicy) LockAndAuthorize(ctx context.Context, raw pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	tx := raw.(pd.BootstrapSQL)
	now, e := tx.SampleTime(ctx)
	if e != nil {
		return pd.GuardPlan{}, e
	}
	p.admission, e = p.session.Authorize(ctx, tx, p.fixture.request, pd.DomainRecord{}, now)
	if e != nil {
		return pd.GuardPlan{}, e
	}
	deadline, e := p.admission.IdentityExpiresAt.Time()
	if e != nil {
		return pd.GuardPlan{}, e
	}
	if !p.replay {
		facts := pd.BootstrapConsumptionFacts{}
		if e = p.session.LockHosts(ctx, tx, p.fixture.request, facts); e != nil {
			return pd.GuardPlan{}, e
		}
		if e = p.session.LockReferences(ctx, tx, p.fixture.request, facts); e != nil {
			return pd.GuardPlan{}, e
		}
		if e = p.session.Reserve(ctx, tx, p.fixture.request, facts); e != nil {
			return pd.GuardPlan{}, e
		}
	}
	return pd.GuardPlan{BindingHash: p.admission.BindingHash, Deadlines: []time.Time{deadline}}, nil
}
func (*captureCandidatePolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func TestCaptureSigningCandidateOriginalComposition(t *testing.T) {
	for _, mode := range []string{"current", "history_no_probe", "new_no_probe", "revoked_head", "original_deny", "late_revoke", "changed_request"} {
		t.Run(mode, func(t *testing.T) {
			f := newCaptureCandidateFixture(t)
			prepared, e := f.a.PrepareBootstrapCandidates(f.ctx, f.grant, f.config, f.request)
			if e != nil || *f.signs != 1 {
				t.Fatal("concrete capture preparation/probe", e)
			}
			f.state.now = time.Now().UTC().Truncate(time.Microsecond)
			s := prepared.Session.(*captureCandidateSession)
			if mode == "history_no_probe" || mode == "new_no_probe" {
				s.capture.observation = nil
			}
			if mode == "revoked_head" {
				f.state.headState = "revoked"
			}
			if mode == "original_deny" {
				f.original.deny = "authorize"
			}
			db := sql.OpenDB(captureGuardConnector{state: f.state})
			defer db.Close()
			policy := &captureCandidatePolicy{fixture: f, session: prepared.Session, replay: mode == "history_no_probe"}
			runner, e := pd.NewTransactions(db, f.request.Scope, policy)
			if e != nil {
				t.Fatal(e)
			}
			tx, e := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			e = runner.GuardInTx(f.ctx, tx, func(ctx context.Context, view *pd.Transaction) error {
				if !policy.replay {
					if _, e := prepared.Session.LockEvidence(ctx, view, f.request, pd.BootstrapConsumptionFacts{}); e != nil {
						return e
					}
				}
				if mode == "late_revoke" {
					f.state.grantState = "revoked"
				}
				request := f.request
				if mode == "changed_request" {
					request.IdempotencyKey = "changed-original-key"
				}
				return prepared.Session.Recheck(ctx, view, request, pd.BootstrapConsumptionFacts{Replayed: policy.replay}, f.state.now)
			})
			if mode == "current" || mode == "history_no_probe" {
				if e != nil {
					t.Fatal("valid current original composition", e, f.original.phases)
				}
				end, e := policy.admission.IdentityExpiresAt.Time()
				if e != nil || end.After(f.state.head.Until) {
					t.Fatal("owner identity expiry not retained")
				}
				if mode == "history_no_probe" && policy.admission.DependencyExpiresAt != pd.Timestamp("1000-01-01T00:00:00.000000Z") {
					t.Fatal("missing probe acquired new-use lifetime")
				}
				want := "prepare,authorize,hosts,references,reserve,evidence,recheck"
				if policy.replay {
					want = "prepare,authorize,recheck"
				}
				if strings.Join(f.original.phases, ",") != want {
					t.Fatal("original authority phase omitted", f.original.phases)
				}
			} else if e == nil {
				t.Fatal("denied/drifted source became authority")
			}
			if *f.signs != 1 {
				t.Fatal("provider called again under SQL/original callbacks")
			}
		})
	}
}
func TestCaptureSigningCandidateRequiresOriginalAndDoesNotFillOtherOwners(t *testing.T) {
	f := newCaptureCandidateFixture(t)
	if _, e := NewCaptureSigningCandidateAuthority(nil, f.a.capture); e == nil {
		t.Fatal("missing original authority replaced")
	}
	var emptyOriginal *captureOriginalFixture
	if _, e := NewCaptureSigningCandidateAuthority(emptyOriginal, f.a.capture); e == nil {
		t.Fatal("typed nil original accepted")
	}
	base := sec.BootstrapOwnerAdapters{References: map[string]sec.BootstrapResourceValidator{}}
	owners, e := f.a.Owners(base)
	if e != nil || len(owners.References) != 1 || owners.References["capture_signing"] != f.a.capture || len(sec.MissingBootstrapOwnerAdapters(owners)) != 29 || len(base.References) != 0 {
		t.Fatal("capture composition filled unrelated slots or mutated source maps", e)
	}
	if _, e = f.a.Owners(owners); e == nil {
		t.Fatal("existing owner silently replaced")
	}
	if e := (&captureCandidateSession{}).LockHosts(context.Background(), nil, f.request, pd.BootstrapConsumptionFacts{}); !errors.Is(e, ErrOwner) {
		t.Fatal("zero session acquired resource authority")
	}
}
