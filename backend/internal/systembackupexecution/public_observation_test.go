package systembackupexecution

import "testing"

func TestObservationPreservesProgressAndTerminalResult(t *testing.T) {
	for _, test := range []struct {
		old, digest, next, nextDigest string
		sequence                      uint64
		change, reject                bool
	}{
		{"running", "heartbeat", "running", "heartbeat", 1, false, false},
		{"running", "ready", "running", "acquire", 1, true, false},
		{"running", "heartbeat", "sealed", "content", 2, true, false},
		{"sealed", "content", "running", "late-heartbeat", 3, false, false},
		{"sealed", "content", "sealed", "content", 3, false, false},
		{"sealed", "content", "sealed", "different-content", 3, false, true},
		{"running", "heartbeat", "sealed", "content", 0, false, true},
		{"running", "heartbeat", "sealed", "content", 1<<53 - 1, false, true},
	} {
		change, err := observationAdvance(test.old, test.digest, test.sequence, test.next, test.nextDigest)
		if change != test.change || (err != nil) != test.reject {
			t.Fatalf("transition %s -> %s: change=%v rejected=%v", test.old, test.next, change, err != nil)
		}
	}
}
