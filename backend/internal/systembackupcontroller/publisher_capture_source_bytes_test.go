package systembackupcontroller

import "testing"

// Inert DATA only: this does not manufacture a SQL receipt or authority.
// JSON compaction must not hide changes to exact authenticated source bytes.
func TestPublisherFrozenSourceExactBytes(t *testing.T) {
	original := PublisherCaptureRecord{Input: HistoricalCaptureInput{SourceSnapshot: []byte(`{"source":1}`), SourceSHA256: "explicit source digest DATA"}}
	before := publisherCaptureRecordHash(original)
	if before == "" {
		t.Fatal("empty record digest")
	}
	for _, replacement := range []string{`{ "source":1 }`, `{"source":2}`} {
		changed := original
		changed.Input.SourceSnapshot = []byte(replacement)
		if publisherCaptureRecordHash(changed) == before {
			t.Fatal("changed frozen source bytes preserved receipt hash")
		}
	}
	changed := original
	changed.Input.SourceSHA256 = "changed original source digest DATA"
	if publisherCaptureRecordHash(changed) == before {
		t.Fatal("changed frozen source digest preserved receipt hash")
	}
}
