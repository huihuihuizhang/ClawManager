package systembackupevidence

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

type systemTestAuthority struct {
	grant ContentAuthorization
	calls int
	check func(int, *ContentAuthorization) error
}

func (a *systemTestAuthority) AuthorizeContent(_ context.Context, _ Identity) (ContentAuthorization, error) {
	a.calls++
	if a.check != nil {
		if err := a.check(a.calls, &a.grant); err != nil {
			return ContentAuthorization{}, err
		}
	}
	return a.grant, nil
}

func smallSystemFixture(t *testing.T) (Identity, []byte, *systemTestAuthority, testKeys) {
	t.Helper()
	v, i, body := capabilityFixture(t)
	body = bytes.TrimSpace(body)
	if len(body) == 0 || len(body) > 8192 {
		t.Fatal("fixture must exercise a real unpadded small JSON document")
	}
	i.ContentSize, i.ContentHash = int64(len(body)), hash(body)
	a := &systemTestAuthority{grant: ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("c", 64), ValidUntil: v.policy.ValidUntil, Capability: &v.policy}}
	return i, body, a, testKeys{key: bytes.Repeat([]byte{7}, 32)}
}

func TestSystemCapabilitySmallBody(t *testing.T) {
	i, body, a, keys := smallSystemFixture(t)
	key := KeyRef{strings.Repeat("b", 64), "v1"}
	var dst bytes.Buffer
	p, err := PrepareSystemCapability(context.Background(), i, key, source(body), a, keys, &dst)
	if err != nil || a.calls != 4 {
		t.Fatalf("prepare err=%v auth calls=%d", err, a.calls)
	}
	m := p.Manifest()
	if m.Identity.ContentSize != int64(len(body)) || len(m.Chunks) != 1 || m.Chunks[0].PlainLength != int64(len(body)) || bytes.Contains(dst.Bytes(), body) {
		t.Fatal("body padded or not encrypted")
	}
	ref := Ref{strings.Repeat("a", 64), "v1", "evidence/test", "v1"}
	store := &testStore{data: dst.Bytes(), present: true, info: ObjectInfo{Version: "v1"}}
	got, err := OpenRange(context.Background(), m, ref, store, keys, 0, i.ContentSize-1)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("small body round trip failed", err)
	}
	wipe(got)
	got, err = OpenRange(context.Background(), m, ref, store, keys, 3, 15)
	if err != nil || !bytes.Equal(got, body[3:16]) {
		t.Fatal("small body range failed", err)
	}
	store.tamper = true
	if got, err := OpenRange(context.Background(), m, ref, store, keys, 0, i.ContentSize-1); err != ErrIntegrity || got != nil {
		t.Fatal("tampered ciphertext returned plaintext", err)
	}
	if _, err := Prepare(context.Background(), i, key, source(body), testRedactor{}, keys, io.Discard); err != ErrInvalid {
		t.Fatal("legacy preparation admitted a small body", err)
	}
	// Fail before any DB access: the system write requires D's new transaction.
	if err := (SQLRegistry{}).PersistPending(context.Background(), Record{Manifest: m}); err != ErrInvalid {
		t.Fatal("legacy registry admitted a small body", err)
	}
}

func TestSystemCapabilityFixedCall(t *testing.T) {
	for _, stage := range []int{2, 3, 4} {
		for name, change := range map[string]func(*ContentAuthorization) error{
			"revoke":         func(*ContentAuthorization) error { return ErrDenied },
			"renew":          func(a *ContentAuthorization) error { a.ValidUntil = a.ValidUntil.Add(time.Minute); return nil },
			"shorten":        func(a *ContentAuthorization) error { a.ValidUntil = a.ValidUntil.Add(-time.Minute); return nil },
			"replace_run":    func(a *ContentAuthorization) error { a.ProducerIdentityHash = strings.Repeat("d", 64); return nil },
			"replace_policy": func(a *ContentAuthorization) error { a.Capability.ScopeHash = strings.Repeat("e", 64); return nil },
		} {
			t.Run(name+"/"+string(rune('0'+stage)), func(t *testing.T) {
				i, body, a, keys := smallSystemFixture(t)
				a.check = func(n int, grant *ContentAuthorization) error {
					if n == stage {
						return change(grant)
					}
					return nil
				}
				p, err := PrepareSystemCapability(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), a, keys, io.Discard)
				if err == nil || len(p.Manifest().Chunks) != 0 {
					t.Fatal("changed authority produced usable evidence")
				}
			})
		}
	}
}

func TestSystemCapabilityInvalidInputs(t *testing.T) {
	for name, mutate := range map[string]func(*Identity){
		"empty":    func(i *Identity) { i.ContentSize = 0 },
		"oversize": func(i *Identity) { i.ContentSize = MaxCapabilityContent + 1 },
		"task": func(i *Identity) {
			i.OwnerType = "backup"
			i.OwnerID = "sbk_11111111-2222-4333-8444-555555555555"
			i.Type = "job_log_chunk"
			i.Media = "text/plain"
		},
		"diagnostic":             func(i *Identity) { i.Type = "diagnostic" },
		"different_installation": func(i *Identity) { i.Installation = "installation_other" },
	} {
		t.Run(name, func(t *testing.T) {
			i, body, a, keys := smallSystemFixture(t)
			mutate(&i)
			if _, err := PrepareSystemCapability(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), a, keys, io.Discard); err != ErrInvalid || a.calls != 0 {
				t.Fatal("invalid input reached authority", err)
			}
		})
	}
	i, body, a, keys := smallSystemFixture(t)
	key := KeyRef{strings.Repeat("b", 64), "v1"}
	var absent *systemTestAuthority
	if _, err := PrepareSystemCapability(context.Background(), i, key, source(body), absent, keys, io.Discard); err != ErrInvalid {
		t.Fatal("typed nil authority", err)
	}
	var absentKeys *testKeys
	if _, err := PrepareSystemCapability(context.Background(), i, key, source(body), a, absentKeys, io.Discard); err != ErrInvalid {
		t.Fatal("typed nil keys", err)
	}
	calls := 0
	drift := func() (io.ReadCloser, error) {
		calls++
		b := append([]byte(nil), body...)
		if calls == 2 {
			b[0] ^= 1
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	if p, err := PrepareSystemCapability(context.Background(), i, key, drift, a, keys, io.Discard); err != ErrIntegrity || len(p.Manifest().Chunks) != 0 {
		t.Fatal("second pass drift accepted", err)
	}
}
