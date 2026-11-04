package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	pd "clawreef/internal/systembackupproducer"
)

func TestOriginalC1KeySourceRequiresActualNativeWrapAndPreservesCipherEnvelope(t *testing.T) {
	x := newSystemTransitFixture(t, "")
	var dst bytes.Buffer
	p, e := x.p.Prepare(context.Background(), x.i, source(x.body), &dst)
	if e != nil {
		t.Fatal("actual local TLS Transit Wrap protocol", e)
	}
	f, e := originalC1KeySource(p)
	if e != nil || f.Transit.Key != p.Manifest().Key || f.Transit.KeyName != x.c.Transit.KeyName || f.Transit.KeyVersion != x.c.Transit.KeyVersion || f.Transit.CASHA256 != x.c.Transit.CASHA256 || len(f.Transit.CAPEM) != 0 || f.ProfileSHA256 != SystemWrapProfileHash(x.c) {
		t.Fatal("original provider source association lost", e)
	}
	var env envelope
	if json.Unmarshal(f.EnvelopeHeader, &env) != nil || env.Wrapped == "" || env.Key != p.Manifest().Key || hash(f.EnvelopeHeader) != p.Manifest().EnvelopeHash {
		t.Fatal("actual original wrapped-DEK envelope lost")
	}
	f.EnvelopeHeader[0] ^= 1
	if _, e := originalC1KeySource(p); e != nil {
		t.Fatal("returned source bytes aliased original", e)
	}
	copy := p
	copy.header = append([]byte(nil), p.header...)
	copy.header[0] ^= 1
	if _, e := originalC1KeySource(copy); e == nil {
		t.Fatal("changed actual envelope accepted")
	}
	if _, e := originalC1KeySource(Prepared{manifest: p.Manifest()}); e == nil {
		t.Fatal("manifest DTO manufactured native source")
	}
	// A generic authority+real native Wrap remains insufficient to authenticate
	// D's original Execution/Handle. The tracked producer requires concrete D.
	if _, s, e := NewTrackedSystemResultEnvironment(nil, p, ProducerEvidenceChannel{}, pd.HistoricalBindingRecord{}, nil); e == nil || s != nil {
		t.Fatal("missing actual original producer accepted")
	}
}

func TestOriginalC1SourceRefusesUnmintedAndUncommittedData(t *testing.T) {
	for _, s := range []*OriginalC1EvidenceSource{nil, {}, {staged: true}} {
		if _, e := s.ReadCommitted(context.Background(), nil); e == nil {
			t.Fatal("missing original tx/source accepted")
		}
	}
	var s OriginalC1EvidenceSource
	if _, e := json.Marshal(&s); e == nil {
		t.Fatal("opaque source exported as JSON capability")
	}
}
