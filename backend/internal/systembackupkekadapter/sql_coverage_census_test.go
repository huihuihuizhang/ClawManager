package systembackupkekadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSQLCensusFramingPreservesNullEmptyAndBoundaries(t *testing.T) {
	digest := func(values ...[]byte) string {
		h := sha256.New()
		for _, v := range values {
			censusFrame(h, v)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	seen := map[string]bool{}
	for _, values := range [][][]byte{{nil}, {[]byte{}}, {[]byte("ab"), []byte("c")}, {[]byte("a"), []byte("bc")}, {[]byte("a"), nil}, {[]byte("a"), []byte{}}} {
		h := digest(values...)
		if seen[h] {
			t.Fatal("ambiguous source-row frame")
		}
		seen[h] = true
	}
}
