package systembackupexecution

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func (f *minioTerminalComponent) prepare(t *testing.T, ctx context.Context, fresh bool) sec.BootstrapTerminalResourceCheck {
	t.Helper()
	check, e := f.resource.PrepareTerminalResource(ctx, f.grant, f.config)
	if e != nil || check == nil {
		t.Fatal("actual concrete Prepare", e)
	}
	if got := check.DependencyDeadline() != nil; got != fresh {
		t.Fatalf("actual private observation fresh=%t want %t", got, fresh)
	}
	return check
}

func TestMinIOBootstrapTerminalConcretePrepareAndOriginalGuardedFresh(t *testing.T) {
	f := newMinioTerminalComponent(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Constructor detaches trust key and five path bindings from its caller.
	f.input.Pin.IssuerPublic[0] ^= 1
	f.input.ReferenceFiles[0].File = filepath.Join(t.TempDir(), "foreign-descriptor")
	check := f.prepare(t, ctx, true)
	until := check.DependencyDeadline()
	original := *until
	*until = pd.Timestamp("1000-01-01T00:00:00.000000Z")
	if *check.DependencyDeadline() != original {
		t.Fatal("caller changed original private deadline")
	}
	prepared := check.(*minioBootstrapTerminalCheck)
	limit, e := original.Time()
	if e != nil || limit.After(prepared.dependencyStart.Add(30*time.Second)) {
		t.Fatal("completion renewed original short observation")
	}
	if len(prepared.ProbeInventory()) != 4 || prepared.ProbeInventory()[2].State != "retained_reserved_probe" || prepared.ProbeInventory()[2].Version == "" {
		t.Fatal("actual catalog protocol inventory missing")
	}
	requests := f.requests.Load()
	if requests == 0 {
		t.Fatal("fresh Prepare bypassed real native requests")
	}
	e = f.guard(t, ctx, func(q *pd.Transaction) error {
		if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
			return e
		}
		if e := check.LockReferences(ctx, q); e != nil {
			return e
		}
		if e := check.RecheckIdentity(ctx, q); e != nil {
			return e
		}
		return check.Recheck(ctx, q)
	})
	if e != nil {
		t.Fatal("actual original D guard and concrete current seven-row source", e)
	}
	if f.requests.Load() != requests {
		t.Fatal("network observation performed under SQL locks")
	}
	actual := []string{}
	for _, key := range f.model.order {
		if key != "admin-prefix" && key != "admin-tail" {
			actual = append(actual, key)
		}
	}
	expected := []string{"head", "grant", "artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read"}
	if len(actual) == 0 || len(actual)%len(expected) != 0 {
		t.Fatal("incomplete seven-row current-source group", actual)
	}
	for i := 0; i < len(actual); i += len(expected) {
		if !reflect.DeepEqual(actual[i:i+len(expected)], expected) {
			t.Fatal("L2/L5/tail changed exact source order", actual)
		}
	}
	if f.model.clockQueries == 0 {
		t.Fatal("concrete source did not use original SampleTime")
	}
}

func TestMinIOBootstrapTerminalConcretePhysicalFailurePreservesOnlyHistory(t *testing.T) {
	for _, scenario := range []string{"unknown-native-version", "checksum-accepted"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinioTerminalComponent(t, scenario)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			check := f.prepare(t, ctx, false)
			requests := f.requests.Load()
			if e := f.guard(t, ctx, func(q *pd.Transaction) error {
				if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
					return e
				}
				return check.RecheckIdentity(ctx, q)
			}); e != nil {
				t.Fatal("current original identity-only history unnecessarily required physical freshness", e)
			}
			if f.requests.Load() != requests || check.DependencyDeadline() != nil {
				t.Fatal("identity-only history refreshed physical observation")
			}
			check = f.prepare(t, ctx, false)
			if e := f.guard(t, ctx, func(q *pd.Transaction) error {
				if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
					return e
				}
				return check.LockReferences(ctx, q)
			}); e == nil {
				t.Fatal("failed native observation admitted fresh use")
			}
		})
	}
}

func TestMinIOBootstrapTerminalConcreteCurrentSQLChangesRejectAndLatch(t *testing.T) {
	for _, scenario := range []string{"revoked", "disabled-admin", "foreign-consumer", "ref-index-drift", "tail-row-version"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinioTerminalComponent(t, "")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			check := f.prepare(t, ctx, true)
			switch scenario {
			case "revoked":
				f.model.revoked = true
			case "disabled-admin":
				f.model.disabled = true
			case "foreign-consumer":
				f.model.foreignAccount = true
			case "ref-index-drift":
				f.model.refDrift = true
			}
			e := f.guard(t, ctx, func(q *pd.Transaction) error {
				_, e := check.AuthorizeIdentity(ctx, q)
				if scenario == "tail-row-version" {
					if e != nil {
						return e
					}
					f.model.rowVersion++
					e = check.RecheckIdentity(ctx, q)
				}
				if e == nil {
					t.Error("changed/revoked original SQL admitted")
				}
				if check.DependencyDeadline() != nil {
					t.Error("failed current source retained admission")
				}
				if retry := check.RecheckIdentity(ctx, q); retry == nil {
					t.Error("current-source failure did not latch")
				}
				return e
			})
			if e == nil {
				t.Fatal("changed original source passed guarded attempt")
			}
		})
	}
}

type minioTerminalForeignView struct{ pd.BootstrapReadSQL }

func TestMinIOBootstrapTerminalConcreteAttemptAndClockFailuresStayLatched(t *testing.T) {
	for _, scenario := range []string{"different-context", "foreign-view", "clock-regression", "clock-failure", "before-L2", "repeat-L2", "repeat-L5", "copied-check"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinioTerminalComponent(t, "")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			check := f.prepare(t, ctx, true)
			e := f.guard(t, ctx, func(q *pd.Transaction) error {
				if scenario == "before-L2" {
					e := check.LockReferences(ctx, q)
					if e == nil {
						t.Error("out-of-order fresh stage accepted")
					}
					return e
				}
				if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
					return e
				}
				var failure error
				switch scenario {
				case "different-context":
					child, stop := context.WithCancel(ctx)
					defer stop()
					failure = check.RecheckIdentity(child, q)
				case "foreign-view":
					failure = check.RecheckIdentity(ctx, minioTerminalForeignView{BootstrapReadSQL: q})
				case "clock-regression":
					last, e := q.SampleTime(ctx)
					if e != nil {
						return e
					}
					f.model.clockAt = last.Add(-time.Microsecond)
					failure = check.RecheckIdentity(ctx, q)
					f.model.clockAt = time.Time{}
					if _, e = q.SampleTime(ctx); e == nil {
						t.Error("D original SampleTime forgot clock regression")
					}
				case "clock-failure":
					f.model.clockFailure = true
					failure = check.RecheckIdentity(ctx, q)
					f.model.clockFailure = false
					if _, e := q.SampleTime(ctx); e == nil {
						t.Error("D original SampleTime forgot sample failure")
					}
				case "repeat-L2":
					_, failure = check.AuthorizeIdentity(ctx, q)
				case "repeat-L5":
					if e := check.LockReferences(ctx, q); e != nil {
						return e
					}
					failure = check.LockReferences(ctx, q)
				case "copied-check":
					original := check.(*minioBootstrapTerminalCheck)
					copy := &minioBootstrapTerminalCheck{origin: original, owner: original.owner, ctx: ctx, tx: q, authorized: true}
					failure = copy.RecheckIdentity(ctx, q)
				}
				if failure == nil {
					t.Error("invalid concrete attempt accepted")
					return errors.New("missing expected concrete rejection")
				}
				if check.RecheckIdentity(ctx, q) == nil || check.DependencyDeadline() != nil {
					t.Error("original attempt failure was not sticky")
				}
				return failure
			})
			if e == nil {
				t.Fatal("invalid attempt completed original guard")
			}
		})
	}
}

func TestMinIOBootstrapTerminalConcreteExpiredObservationDoesNotRenewHistory(t *testing.T) {
	f := newMinioTerminalComponent(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	check := f.prepare(t, ctx, true)
	original := *check.DependencyDeadline()
	deadline, e := original.Time()
	if e != nil {
		t.Fatal(e)
	}
	f.model.clockAt = deadline.Add(time.Microsecond)
	if e = f.guard(t, ctx, func(q *pd.Transaction) error {
		if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
			return e
		}
		return check.RecheckIdentity(ctx, q)
	}); e != nil {
		t.Fatal("expired physical observation rejected otherwise current history", e)
	}
	if *check.DependencyDeadline() != original {
		t.Fatal("history renewed original physical deadline")
	}
	check = f.prepare(t, ctx, true)
	deadline, e = check.DependencyDeadline().Time()
	if e != nil {
		t.Fatal(e)
	}
	f.model.clockAt = deadline.Add(time.Microsecond)
	if e = f.guard(t, ctx, func(q *pd.Transaction) error {
		if _, e := check.AuthorizeIdentity(ctx, q); e != nil {
			return e
		}
		return check.LockReferences(ctx, q)
	}); e == nil {
		t.Fatal("expired original observation admitted fresh use")
	}
}

func TestMinIOBootstrapTerminalConcreteA20MapKeepsOtherOwnersClosed(t *testing.T) {
	f := newMinioTerminalComponent(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := filepath.Join(t.TempDir(), "absent-original-capture-input")
	original, e := install.NewBootstrapTerminalOriginal(install.NewCaptureSigningConsumer(path, path+".sha256"), install.BootstrapTerminalFiles{MappingFile: path, MappingSHA256: hash([]byte("original-mapping")), SignatureFile: path, EvidenceFile: path, RegistryDirectory: filepath.Dir(path)}, f.resource.TerminalResources())
	if e != nil {
		t.Fatal("actual A20 constructor did not accept grouped concrete owner", e)
	}
	missing := original.MissingTerminalResources()
	if len(missing) == 0 {
		t.Fatal("five MinIO purposes fabricated all other owners")
	}
	for _, key := range missing {
		for _, owned := range f.resource.TerminalKeys() {
			if key == owned {
				t.Fatal("concrete shared owner did not fill original purpose", key)
			}
		}
	}
	if prepared, e := original.PrepareBootstrapCandidates(ctx, f.grant, f.config, pd.BootstrapConsumptionRequest{}); e == nil || prepared.Session != nil {
		t.Fatal("incomplete A20 composition prepared executable candidates")
	}
	if f.requests.Load() != 0 || f.model.clockQueries != 0 {
		t.Fatal("incomplete A20 gate reached physical provider or SQL")
	}
	if _, e = f.resource.Prepare(ctx, f.grant, f.config); e == nil {
		t.Fatal("legacy lock-order route bypassed terminal")
	}
}
