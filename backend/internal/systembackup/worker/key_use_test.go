package worker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

func keyInvocation(t *testing.T) Invocation {
	r, env, _ := fixture(t)
	r.Binding.BackupID = "sbk_fixture"
	r.Binding.Path = "workspace"
	return Invocation{Request: r, WorkspacePath: env.Workspace.Name(), StagingPath: env.Staging.Name(), ProviderKey: &k.Access{Operation: k.Generate, Endpoint: "https://bao.example.invalid:8200", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("1", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: "installation_fixture", BackupPublicID: r.Binding.BackupID, AttemptNo: "1", Phase: "capture", Part: "workspace", PartIndex: "0", EnvelopeID: r.Binding.EnvelopeID, CaptureContextHash: r.Binding.CaptureContextHash}}}}
}

func TestOriginalKeyAuthorityUsesExistingMTLSControlAndFailsClosed(t *testing.T) {
	for _, mode := range []string{"valid", "revoked-before-begin", "revoked-during-use", "changed-pod", "changed-claim", "unknown-reserve", "unknown-begin", "unknown-end", "expired"} {
		t.Run(mode, func(t *testing.T) {
			i := keyInvocation(t)
			expectedHash, _ := i.Hash()
			access := *i.ProviderKey
			until := time.Now().Add(30 * time.Second).UTC()
			identity := k.JobIdentity{Namespace: "ns", PodUID: "pod", JobUID: "job", ServiceAccountUID: "sa", InvocationSHA256: expectedHash, ExecutionGrantSHA256: strings.Repeat("a", 64)}
			state := ""
			nonce := ""
			requests := 0
			revoked := false
			changed := false
			h := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, peer string, r ControlRequest) (Lease, error) {
				requests++
				if peer != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != expectedHash || revoked {
					return Lease{}, ErrExecution
				}
				switch r.Action {
				case "key-reserve":
					if state != "" {
						return Lease{}, ErrExecution
					}
					state = "reserved"
					nonce = r.Point
					if mode == "unknown-reserve" {
						return Lease{}, ErrNotReady
					}
				case "key-begin":
					if state != "reserved" {
						return Lease{}, ErrExecution
					}
					state = "using"
					if mode == "unknown-begin" {
						return Lease{}, ErrNotReady
					}
				case "key-end":
					if state != "using" {
						return Lease{}, ErrExecution
					}
					state = "finished"
					if mode == "unknown-end" {
						return Lease{}, ErrNotReady
					}
				case "key-check":
				default:
					return Lease{}, ErrExecution
				}
				if r.Point != nonce {
					return Lease{}, ErrExecution
				}
				v := KeyUseLease{Identity: identity, Access: access, AuthoritySHA256: strings.Repeat("b", 64), Nonce: nonce, Until: until, State: state}
				if changed && mode == "changed-pod" {
					v.Identity.PodUID = "replacement"
				}
				if changed && mode == "changed-claim" {
					v.AuthoritySHA256 = strings.Repeat("c", 64)
				}
				return Lease{InvocationSHA256: expectedHash, ExpiresAt: until, KeyUse: &v}, nil
			})}
			client, _ := mutualTLSFixture(t, h)
			a, e := NewOriginalKeyAuthority(context.Background(), client, i)
			if mode == "unknown-reserve" {
				if !errors.Is(e, k.ErrUnknown) || requests != 1 {
					t.Fatal("unknown reserve retried")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			// The caller no longer owns the invocation stored by the authority.
			i.ProviderKey.Request.Key.ProviderVersion = "99"
			if e = a.Recheck(context.Background(), access); e != nil {
				t.Fatal("invocation not frozen", e)
			}
			changed = true
			if mode == "revoked-before-begin" {
				revoked = true
			}
			if mode == "expired" {
				a.lease.Until = time.Now().Add(-time.Second)
			}
			used := false
			e = a.WithUse(context.Background(), access, func() error {
				used = true
				if mode == "valid" {
					job := &CaptureKeyJob{original: a, access: access, until: until}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if err := job.recheckDuringUse(ctx); err != nil {
						return err
					}
				}
				if mode == "revoked-during-use" {
					revoked = true
				}
				return nil
			})
			if mode == "valid" {
				if e != nil || !used || state != "finished" {
					t.Fatal("valid use", e)
				}
				if e = a.Recheck(context.Background(), access); e != nil {
					t.Fatal("final check", e)
				}
				if (&CaptureKeyJob{original: a, access: access, until: until}).recheckDuringUse(context.Background()) == nil {
					t.Fatal("finished use accepted as active stream")
				}
			} else {
				if e == nil {
					t.Fatal("invalid use accepted")
				}
				if (mode == "unknown-begin" || mode == "unknown-end") && !errors.Is(e, k.ErrUnknown) {
					t.Fatal("unknown commit disguised as denial", e)
				}
				if mode != "revoked-during-use" && mode != "unknown-end" && used {
					t.Fatal("denied use entered callback")
				}
			}
			if e = a.WithUse(context.Background(), access, func() error { t.Fatal("callback replay"); return nil }); e == nil {
				t.Fatal("replayed use")
			}
		})
	}
}

func TestProviderInvocationCannotBorrowFunctionalOrRecoveryCalls(t *testing.T) {
	i := keyInvocation(t)
	hash, _ := i.Hash()
	for _, action := range []string{"acquire", "complete", "check"} {
		if ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: action, Point: "prepare"}) {
			t.Fatal("old channel accepted", action)
		}
	}
	for _, field := range []string{"part", "part-index"} {
		bad := keyInvocation(t)
		if field == "part" {
			bad.ProviderKey.Request.Context.Part = "other"
		} else {
			bad.ProviderKey.Request.Context.PartIndex = "1"
		}
		h, _ := bad.Hash()
		if ValidateControl(ControlRequest{Invocation: bad, InvocationSHA256: h, Action: "key-reserve", Point: strings.Repeat("a", 32)}) {
			t.Fatal("C context changed original part", field)
		}
	}
	for _, endpoint := range []string{"https://:8200", "https://bao.example.invalid:8200?", "https://bao.example.invalid:8200#"} {
		bad := keyInvocation(t)
		bad.ProviderKey.Endpoint = endpoint
		h, _ := bad.Hash()
		if ValidateControl(ControlRequest{Invocation: bad, InvocationSHA256: h, Action: "key-reserve", Point: strings.Repeat("a", 32)}) {
			t.Fatalf("invalid provider endpoint reserved original key use: %q", endpoint)
		}
	}
	i.ProviderKey.Operation = k.Unwrap
	hash, _ = i.Hash()
	if ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "key-reserve", Point: strings.Repeat("a", 32)}) {
		t.Fatal("capture gained unwrap")
	}
	i.ProviderKey = nil
	raw, _ := json.Marshal(i)
	if strings.Contains(string(raw), "provider_key") {
		t.Fatal("legacy invocation bytes changed")
	}
}

func TestCaptureKeyJobRejectsWrongMappingBeforeOriginalReserve(t *testing.T) {
	base := keyInvocation(t)
	config := k.Config{Endpoint: base.ProviderKey.Endpoint, KeyName: base.ProviderKey.KeyName, Key: base.ProviderKey.Request.Key, InstallationID: base.ProviderKey.Request.Context.InstallationID}
	var calls atomic.Int32
	h := ControlHandler{Authorizer: authorizeFunc(func(context.Context, string, ControlRequest) (Lease, error) {
		calls.Add(1)
		return Lease{}, ErrExecution
	})}
	client, _ := mutualTLSFixture(t, h)
	for _, tc := range []struct {
		name   string
		change func(*Invocation, *k.Config)
	}{
		{"purpose", func(i *Invocation, _ *k.Config) { i.ProviderKey.Operation = k.Unwrap }},
		{"installation", func(_ *Invocation, c *k.Config) { c.InstallationID = "another_installation" }},
		{"provider key", func(_ *Invocation, c *k.Config) { c.KeyName = "another-key" }},
		{"provider version", func(_ *Invocation, c *k.Config) { c.Key.ProviderVersion = "2" }},
		{"registry version", func(_ *Invocation, c *k.Config) { c.Key.RegistryVersion = "r2" }},
		{"endpoint", func(_ *Invocation, c *k.Config) { c.Endpoint = "https://other.example.invalid:8200" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, c := base, config
			access := *base.ProviderKey
			i.ProviderKey = &access
			tc.change(&i, &c)
			if _, err := NewCaptureKeyJob(context.Background(), client, i, c, k.PermitMount{}); !errors.Is(err, ErrExecution) {
				t.Fatalf("mismatched mapping admitted: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("mismatched mapping consumed original Job reservation")
			}
		})
	}
}
