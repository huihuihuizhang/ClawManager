package control

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

func testVault() Vault {
	return Vault{WriteVersion: "v1", Keys: map[string][]byte{"v1": bytes.Repeat([]byte{7}, 32)}}
}
func recordStep(r sealedRecord) sqlStep {
	return sqlStep{contains: "SELECT record_kind", rows: [][]driver.Value{{r.kind, r.version, r.nonce, r.ciphertext}}}
}
func readRecordSteps(t Task, r sealedRecord) []sqlStep { return append(workerCommit(t), recordStep(r)) }

func TestVaultAuthenticationAndTakeover(t *testing.T) {
	task, _, _ := grantFixture()
	v := testVault()
	r, e := v.seal(task, "execution-plan", "plan", []byte(`{"password":"private"}`))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(r.ciphertext, []byte("private")) {
		t.Fatal("plaintext persisted")
	}
	next := task
	next.Generation++
	next.Owner = "replacement"
	if _, e = v.open(next, "execution-plan", "plan", r); e != nil {
		t.Fatal("takeover cannot recover plan", e)
	}
	for _, field := range []string{"task", "revision", "name", "kind", "nonce", "ciphertext", "key-version"} {
		t.Run(field, func(t *testing.T) {
			altered := r
			altered.nonce = bytes.Clone(r.nonce)
			altered.ciphertext = bytes.Clone(r.ciphertext)
			owner := task
			name, kind := "execution-plan", "plan"
			switch field {
			case "task":
				owner.ID = "sb-other"
			case "revision":
				owner.ProfileRevision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "name":
				name = "other-plan"
			case "kind":
				kind = "results"
			case "nonce":
				altered.nonce[0] ^= 1
			case "ciphertext":
				altered.ciphertext[0] ^= 1
			case "key-version":
				altered.version = "v2"
			}
			if _, e := v.open(owner, name, kind, altered); e == nil {
				t.Fatal("tampered record accepted")
			}
		})
	}
}
func TestVaultRetryDoesNotReplaceImmutableRecord(t *testing.T) {
	task, _, _ := grantFixture()
	v := testVault()
	plain := []byte(`{"snapshot":"original"}`)
	r, _ := v.seal(task, "execution-plan", "plan", plain)
	for _, same := range []bool{true, false} {
		store, s := scriptStore(t, readRecordSteps(task, r)...)
		v.Store = store
		candidate := plain
		if !same {
			candidate = []byte(`{"snapshot":"different"}`)
		}
		e := v.Put(context.Background(), task, "execution-plan", "plan", candidate)
		if (same && e != nil) || (!same && !errors.Is(e, ErrConflict)) || s.writes != 0 {
			t.Fatal("immutable retry failed", e)
		}
	}
}
