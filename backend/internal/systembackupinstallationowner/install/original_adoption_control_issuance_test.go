package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// A correctly sized signature key is not source authority. Missing genuine
// sources must fail every entry without emitting even one partial record.
func TestOriginalAdoptionIssuerRejectsAbsentOriginalSources(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cases := map[string]*IssuedOriginalAdoptionControls{"nil": nil, "zero": {}, "self_without_sources": {ctx: ctx, until: time.Now().Add(time.Minute)}, "empty_coverage": {ctx: ctx, coverage: &PreparedOriginalAdoptionCoverage{}, until: time.Now().Add(time.Minute)}}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if b != nil {
				b.origin = b
			}
			signed, pin, e := b.signActualOriginalOwnerWitness(ctx, reg.RetainedArtifacts, "original_writer_fence", key)
			if e == nil || len(signed.Record) != 0 || pin.Source.RecordID != "" {
				t.Fatal("missing original source emitted witness")
			}
			signed, adoption, e := b.signActualOriginalAdoption(ctx, key)
			if e == nil || len(signed.Record) != 0 || adoption.Source.RecordID != "" {
				t.Fatal("missing original source emitted adoption")
			}
			if _, _, e = b.originalCommitInputs(ctx, nil, nil, nil); e == nil {
				t.Fatal("missing original source created KEK preparation")
			}
			if _, e = json.Marshal(b); b != nil && e == nil {
				t.Fatal("opaque batch serialized")
			}
		})
	}
}

func TestOriginalAdoptionIssuerRejectsMalformedSigningMaterial(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if !originalAdoptionSigningKey(key) {
		t.Fatal("canonical Ed25519 key rejected")
	}
	bad := append(ed25519.PrivateKey(nil), key...)
	defer clear(bad)
	bad[63] ^= 1
	for name, k := range map[string]ed25519.PrivateKey{"nil": nil, "seed_only": key[:32], "public_half_tampered": bad} {
		t.Run(name, func(t *testing.T) {
			if originalAdoptionSigningKey(k) {
				t.Fatal("malformed key accepted")
			}
		})
	}
}
