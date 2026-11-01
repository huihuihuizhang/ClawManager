package systembackupexecution

import (
	"bytes"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Immutable byte/sequence comparison DATA only. No SQL registration, original
// upload authorization or C receipt is manufactured by this test.
func TestPostCOriginalResultSnapshotRejectsChangedOrReorderedData(t *testing.T) {
	for _, mode := range []string{"exact-first", "exact-last", "changed-fixed-version", "swapped-results", "changed-sequence", "whitespace", "missing-body", "missing-pin", "zero-sequence", "overflow-sequence", "typed-alias-with-updated-pin"} {
		t.Run(mode, func(t *testing.T) {
			observed := originalUploadPollFixtureData(t)
			var snapshot publicationPostCUploadSnapshot
			var raws [16][]byte
			for i, m := range observed.Messages {
				var err error
				raws[i], err = ce.Canonical(m)
				if err != nil {
					t.Fatal(err)
				}
				snapshot.resultsSHA256[i] = hash(raws[i])
			}
			sequence := uint64(1)
			raw := bytes.Clone(raws[0])
			switch mode {
			case "exact-last":
				sequence = 16
				raw = bytes.Clone(raws[15])
			case "changed-fixed-version":
				m := observed.Messages[0]
				m.Object.Version = "other-fixed-version"
				raw, _ = ce.Canonical(m)
			case "swapped-results":
				raw = bytes.Clone(raws[1])
			case "changed-sequence":
				m := observed.Messages[0]
				m.Sequence = 2
				raw, _ = ce.Canonical(m)
			case "whitespace":
				raw = append(raw, ' ')
			case "missing-body":
				raw = nil
			case "missing-pin":
				snapshot.resultsSHA256[0] = ""
			case "zero-sequence":
				sequence = 0
			case "overflow-sequence":
				sequence = 17
			case "typed-alias-with-updated-pin":
				raw = bytes.Replace(raw, []byte(`"Sequence"`), []byte(`"SEQUENCE"`), 1)
				snapshot.resultsSHA256[0] = hash(raw)
			}
			message, err := decodeOriginalPostCUploadResult(raw, sequence, snapshot)
			if mode == "exact-first" || mode == "exact-last" {
				if err != nil || message.Sequence != sequence {
					t.Fatal("original frozen result bytes rejected", err)
				}
				return
			}
			if err == nil {
				t.Fatal("changed/reordered original result accepted", mode)
			}
		})
	}
}
