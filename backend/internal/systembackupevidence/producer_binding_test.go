package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupproducer"
)

func producerBindingFixture(t *testing.T) (Prepared, ProducerEvidenceChannel, Record, systembackupproducer.EvidenceBinding) {
	p, c, r, b, _ := producerBindingFixtureWithCiphertext(t)
	return p, c, r, b
}

func producerBindingFixtureWithCiphertext(t *testing.T) (Prepared, ProducerEvidenceChannel, Record, systembackupproducer.EvidenceBinding, []byte) {
	t.Helper()
	i, body, a, keys := smallSystemFixture(t)
	var dst bytes.Buffer
	p, err := PrepareSystemCapability(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), a, keys, &dst)
	if err != nil {
		t.Fatal(err)
	}
	c := ProducerEvidenceChannel{"evidence", KeyRef{strings.Repeat("a", 64), "v1"}, KeyRef{strings.Repeat("d", 64), "v2"}, strings.Repeat("e", 64)}
	b, err := p.PendingProducerBinding(c)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyFor(c.Root, i)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := Record{Manifest: p.Manifest(), Ref: Ref{c.Store.Identity, c.Store.Version, key, ""}, State: "pending", Failure: "none", RowVersion: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), OwnerDeadline: now.Add(time.Minute)}
	return p, c, r, b, append([]byte(nil), dst.Bytes()...)
}

func TestProducerBindingRoundTrip(t *testing.T) {
	p, c, r, b := producerBindingFixture(t)
	if b.ImmutableVersion != nil || string(b.ManifestHash) != hash(canonical(p.Manifest())) || string(b.RelativeKeyHash) != hash([]byte(r.Ref.RelativeKey)) {
		t.Fatal("incorrect pending binding")
	}
	// D's strict C1 decoder must accept the real A output, not only its vectors.
	var historical systembackupproducer.HistoricalBindingRecord
	if err := systembackupproducer.DecodeRecord(producerHistoricalVector(t), &historical); err != nil {
		t.Fatal(err)
	}
	historical.Scope.Installation = b.OwnerID
	historical.Evidence, historical.RelativeKey = b, systembackupproducer.RelativeKey(r.Ref.RelativeKey)
	var decoded systembackupproducer.HistoricalBindingRecord
	if err := systembackupproducer.DecodeRecord(canonical(historical), &decoded); err != nil || !reflect.DeepEqual(decoded.Evidence, b) {
		t.Fatal("C1 decoder rejected A output", err)
	}
	if err := MatchProducerBinding(r, c, decoded.Evidence); err != nil {
		t.Fatal(err)
	}
	copyManifest := p.Manifest()
	copyManifest.Chunks[0].CipherHash = strings.Repeat("f", 64)
	again, err := p.PendingProducerBinding(c)
	if err != nil || again != b {
		t.Fatal("manifest copy modified preparation")
	}
	r.State, r.Ref.ImmutableVersion = "ready", "Exact.V1"
	v := systembackupproducer.Text("Exact.V1")
	ready := b
	ready.ImmutableVersion = &v
	if err := MatchProducerBinding(r, c, ready); err != nil {
		t.Fatal("ready exact version", err)
	}
	if err := MatchProducerBinding(r, c, b); err != ErrIntegrity {
		t.Fatal("ready accepted historical pending version")
	}
	v = "exact.v1"
	if err := MatchProducerBinding(r, c, ready); err != ErrIntegrity {
		t.Fatal("version case folded")
	}
}

func producerHistoricalVector(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "producer-authority-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Records []struct {
			Definition string
			Value      json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, r := range vectors.Records {
		if r.Definition == "HistoricalBindingRecord" {
			return r.Value
		}
	}
	t.Fatal("missing historical vector")
	return nil
}

func TestProducerBindingRejectsEveryChangedField(t *testing.T) {
	_, c, r, b := producerBindingFixture(t)
	typ := reflect.TypeOf(b)
	for index := 0; index < typ.NumField(); index++ {
		t.Run(typ.Field(index).Name, func(t *testing.T) {
			changed := b
			field := reflect.ValueOf(&changed).Elem().Field(index)
			if field.Kind() == reflect.Pointer {
				v := systembackupproducer.Text("unexpected-version")
				changed.ImmutableVersion = &v
			} else {
				field.SetString(field.String() + "x")
			}
			if err := MatchProducerBinding(r, c, changed); err != ErrIntegrity {
				t.Fatal("mismatched field accepted", err)
			}
		})
	}
}

func TestProducerBindingRejectsUntrustedShapes(t *testing.T) {
	_, c, r, b := producerBindingFixture(t)
	if got, err := (Prepared{}).PendingProducerBinding(c); err != ErrIntegrity || got != (systembackupproducer.EvidenceBinding{}) {
		t.Fatal("zero preparation accepted")
	}
	for name, mutate := range map[string]func(*Record, *ProducerEvidenceChannel){
		"root":             func(_ *Record, c *ProducerEvidenceChannel) { c.Root = "other" },
		"traversal":        func(_ *Record, c *ProducerEvidenceChannel) { c.Root = "a/../b" },
		"channel_store":    func(_ *Record, c *ProducerEvidenceChannel) { c.Store.Version = "v3" },
		"channel_write":    func(_ *Record, c *ProducerEvidenceChannel) { c.Write.Version = "v3" },
		"recovery":         func(_ *Record, c *ProducerEvidenceChannel) { c.RecoveryProfileHash = strings.Repeat("f", 64) },
		"key":              func(r *Record, _ *ProducerEvidenceChannel) { r.Ref.RelativeKey += "other" },
		"manifest":         func(r *Record, _ *ProducerEvidenceChannel) { r.Manifest.ObjectHash = strings.Repeat("f", 64) },
		"empty_chunks":     func(r *Record, _ *ProducerEvidenceChannel) { r.Manifest.Chunks = nil },
		"inline":           func(r *Record, _ *ProducerEvidenceChannel) { r.State = "inline" },
		"deleted":          func(r *Record, _ *ProducerEvidenceChannel) { r.State = "deleted" },
		"pending_version":  func(r *Record, _ *ProducerEvidenceChannel) { r.Ref.ImmutableVersion = "v1" },
		"ready_no_version": func(r *Record, _ *ProducerEvidenceChannel) { r.State = "ready" },
		"ready_null":       func(r *Record, _ *ProducerEvidenceChannel) { r.State, r.Ref.ImmutableVersion = "ready", "null" },
		"ready_non_ascii":  func(r *Record, _ *ProducerEvidenceChannel) { r.State, r.Ref.ImmutableVersion = "ready", "版本" },
	} {
		t.Run(name, func(t *testing.T) {
			next, channel := r, c
			mutate(&next, &channel)
			if err := MatchProducerBinding(next, channel, b); err != ErrIntegrity {
				t.Fatal("bad record/channel accepted", err)
			}
		})
	}
}
