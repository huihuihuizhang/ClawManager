package systembackupkekadapter

import (
	reg "clawreef/internal/systembackupkekregistry"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOriginalSignatureAndRevocation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := OriginalRecord{Source: reg.SourceRecord{SourceID: "installation", RecordID: "mapping", RecordVersion: "v1"}, Revision: "v1", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	b, _ := json.Marshal(r.Binding)
	h := sha256.Sum256(b)
	r.Source.ContentSHA256 = hex.EncodeToString(h[:])
	check := func(want bool) {
		t.Helper()
		raw, _ := json.Marshal(r)
		sig := ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), raw...))
		_, e := authenticate(raw, sig, pub, now)
		if (e == nil) != want {
			t.Fatalf("authenticated=%v want %v", e == nil, want)
		}
	}
	check(true)
	r.GenerateRevoked = true
	check(false)
	r.GenerateRevoked = false
	r.UnwrapRevoked = true
	check(false)
	r.UnwrapRevoked = false
	r.Until = now
	check(false)
	r.Until = now.Add(time.Minute)
	raw, _ := json.Marshal(r)
	sig := ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), raw...))
	raw[0] = ' '
	if _, e := authenticate(raw, sig, pub, now); e == nil {
		t.Fatal("tampered record accepted")
	}
	base, _ := json.Marshal(r)
	for _, malformed := range []string{
		strings.Replace(string(base), `"Revision":"v1"`, `"Revision":"v1","Revision":"v1"`, 1),
		strings.Replace(string(base), `"Revision":"v1"`, `"Revision":"v1","Extra":true`, 1),
		string(base) + `{}`,
	} {
		payload := []byte(malformed)
		signed := ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), payload...))
		if _, e := authenticate(payload, signed, pub, now); e == nil {
			t.Fatal("ambiguous signed authority record accepted")
		}
	}
}
