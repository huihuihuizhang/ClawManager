package systembackupkekadapter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestPreparedPermitCurrentOwnerMappingKeepsRevisionSemantics(t *testing.T) {
	original, issuer, key := ownerRecordFixture(t)
	defer clear(key)
	raw, sig := signOwner(original, key)
	owned, err := decodeOwnerRecord(raw, sig, issuer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := &PreparedProviderPermitIssue{
		issuer:  &ProviderPermitIssuer{cfg: ProviderPermitIssuerConfig{InstallationIssuer: bytes.Clone(issuer)}},
		mapping: owned, mappingRaw: bytes.Clone(raw), mappingSignature: bytes.Clone(sig), mappingIssuer: bytes.Clone(issuer), until: now.Add(30 * time.Second),
	}
	before, _ := json.Marshal(p.mapping)
	initialUntil := p.until
	initialRaw, initialSignature, initialIssuer := bytes.Clone(p.mappingRaw), bytes.Clone(p.mappingSignature), bytes.Clone(p.mappingIssuer)
	// This is the complete former per-read decision, retained as an independent
	// oracle for changed revisions. No SQL/current row is cached by this test.
	legacy := func(raw, sig []byte, at time.Time) bool {
		m, err := decodeOwnerRecord(raw, sig, p.issuer.cfg.InstallationIssuer)
		return err == nil && reflect.DeepEqual(m.Binding, p.mapping.Binding) && !m.GenerateRevoked && !at.Before(m.NotBefore) && at.Before(m.Until) && !m.Until.Before(p.until)
	}
	check := func(t *testing.T, raw, sig []byte, at time.Time, allowed bool) {
		t.Helper()
		if full := legacy(raw, sig, at); full != allowed {
			t.Fatalf("full current authentication allowed=%v want=%v", full, allowed)
		}
		if err := p.recheckMapping(raw, sig, at); (err == nil) != allowed {
			t.Fatalf("prepared current mapping allowed=%v: %v", allowed, err)
		}
		current, _ := json.Marshal(p.mapping)
		if !bytes.Equal(before, current) || !bytes.Equal(p.mappingRaw, initialRaw) || !bytes.Equal(p.mappingSignature, initialSignature) || !bytes.Equal(p.mappingIssuer, initialIssuer) || !p.until.Equal(initialUntil) {
			t.Fatal("current revision mutated prepared original data or lifetime")
		}
	}
	check(t, raw, sig, now, true)
	check(t, raw, sig, original.NotBefore, true)
	check(t, raw, sig, original.NotBefore.Add(-time.Nanosecond), false)
	check(t, raw, sig, original.Until, false)
	for _, tc := range []struct {
		name    string
		edit    func(*OriginalRecord)
		allowed bool
	}{
		{"new_revision", func(m *OriginalRecord) { m.Revision = "r2"; m.Source.RecordVersion = "r2" }, true},
		{"renewal", func(m *OriginalRecord) { m.Revision = "r2"; m.Until = m.Until.Add(time.Hour) }, true},
		{"same_minimum", func(m *OriginalRecord) { m.Until = p.until }, true},
		{"shortened_below_original_minimum", func(m *OriginalRecord) { m.Until = p.until.Add(-time.Microsecond) }, false},
		{"generate_revoked", func(m *OriginalRecord) { m.GenerateRevoked = true }, false},
		{"unwrap_only_revoked", func(m *OriginalRecord) { m.UnwrapRevoked = true }, true},
		{"future", func(m *OriginalRecord) { m.NotBefore = now.Add(time.Second) }, false},
		{"expired", func(m *OriginalRecord) { m.Until = now.Add(-time.Second) }, false},
		{"different_binding", func(m *OriginalRecord) {
			m.Binding.Key.ProviderVersion = "2"
			binding, _ := json.Marshal(m.Binding)
			h := sha256.Sum256(binding)
			m.Source.ContentSHA256 = hex.EncodeToString(h[:])
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := original
			tc.edit(&current)
			nextRaw, nextSig := signOwner(current, key)
			check(t, nextRaw, nextSig, now, tc.allowed)
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"oversize", bytes.Repeat([]byte("x"), 65537)}, {"malformed", []byte("{")},
		{"duplicate", append([]byte(`{"Revision":"duplicate",`), raw[1:]...)},
		{"unknown", append([]byte(`{"Unknown":true,`), raw[1:]...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), tc.raw...))
			check(t, tc.raw, signed, now, false)
		})
	}
	changedSignature := bytes.Clone(sig)
	changedSignature[0] ^= 1
	check(t, raw, changedSignature, now, false)
	check(t, raw, nil, now, false)
	// A byte change alone is not revocation for this owner table. Preserve the
	// former accepted signed JSON-whitespace change through full authentication.
	spaced := append(bytes.Clone(raw), '\n')
	spacedSig := ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), spaced...))
	check(t, spaced, spacedSig, now, true)
	otherIssuer, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(otherKey)
	p.issuer.cfg.InstallationIssuer = otherIssuer
	check(t, raw, sig, now, false)
	otherRaw, otherSig := signOwner(original, otherKey)
	check(t, otherRaw, otherSig, now, true)
	p.issuer.cfg.InstallationIssuer = bytes.Clone(issuer)
	check(t, raw, sig, now, true)
}
