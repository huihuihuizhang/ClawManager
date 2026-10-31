package systembackupkekadapter

import (
	c "clawreef/internal/systembackupcontroller"
	"testing"
)

func TestPublisherVerifierHistoryPreservesExactSourceBytes(t *testing.T) {
	original := c.PublisherCaptureRecord{Input: c.HistoricalCaptureInput{SourceSnapshot: []byte(`{"source":1}`), SourceSHA256: "explicit source digest DATA"}}
	before := publisherVerifierHistoryHash(original)
	for _, replacement := range []string{`{ "source":1 }`, `{"source":2}`} {
		changed := original
		changed.Input.SourceSnapshot = []byte(replacement)
		if before == "" || publisherVerifierHistoryHash(changed) == before {
			t.Fatal("changed exact source bytes preserved verifier history hash")
		}
	}
}
