package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"testing"
)

func TestLegacy177ExternalHashSortMatchesOriginalDigest(t *testing.T) {
	for _, count := range []int{0, 1, 2, 31, 257, 4097} {
		t.Run(originalLegacy177TestNumber(count), func(t *testing.T) {
			s, e := newLegacy177HashSort(context.Background(), 7, 3, 16<<20)
			if e != nil {
				t.Fatal(e)
			}
			dir := s.dir
			var reference []string
			for n := 0; n < count; n++ {
				hash := sha256.Sum256([]byte{byte((count - n) % 17)})
				reference = append(reference, hex.EncodeToString(hash[:]))
				if e = s.add(hash); e != nil {
					t.Fatal(e)
				}
			}
			sort.Strings(reference)
			actual, e := s.digest(int64(count))
			if e != nil || actual != importDigest(reference) {
				t.Fatal("original multiset/null/duplicate JSON digest differs", e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(dir); !os.IsNotExist(e) {
				t.Fatal("owned hash scratch not removed")
			}
		})
	}
}
func originalLegacy177TestNumber(n int) string {
	if n == 0 {
		return "empty"
	}
	var b [32]byte
	p := len(b)
	for n > 0 {
		p--
		b[p] = byte('0' + n%10)
		n /= 10
	}
	return string(b[p:])
}

func TestLegacy177ExternalHashSortRejectsPartialOrUnboundedWork(t *testing.T) {
	t.Run("disk_ceiling", func(t *testing.T) {
		s, e := newLegacy177HashSort(context.Background(), 1, 2, 32)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		h := sha256.Sum256([]byte("same"))
		if e = s.add(h); e != nil {
			t.Fatal(e)
		}
		if e = s.add(h); !errors.Is(e, errLegacy177Scratch) {
			t.Fatal("scratch limit bypass", e)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s, e := newLegacy177HashSort(ctx, 1, 2, 1024)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		cancel()
		if e = s.add([32]byte{}); !errors.Is(e, context.Canceled) {
			t.Fatal("cancelled scan accepted", e)
		}
	})
	t.Run("wrong_count", func(t *testing.T) {
		s, e := newLegacy177HashSort(context.Background(), 2, 2, 1024)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		if e = s.add([32]byte{}); e != nil {
			t.Fatal(e)
		}
		if _, e = s.digest(2); e == nil {
			t.Fatal("partial scan accepted")
		}
	})
	t.Run("truncated_run", func(t *testing.T) {
		s, e := newLegacy177HashSort(context.Background(), 1, 2, 1024)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		if e = s.add([32]byte{}); e != nil {
			t.Fatal(e)
		}
		if e = os.Truncate(s.levels[0][0], 31); e != nil {
			t.Fatal(e)
		}
		if _, e = s.digest(1); e == nil {
			t.Fatal("partial hash accepted")
		}
	})
}

// Cross the actual old 1,000,000-row cutoff using a real private disk sort.
// Expected JSON digest is generated independently from three multiplicities,
// without retaining a million-element reference or omitting duplicate rows.
func TestLegacy177ExternalHashSortBeyondOldRowCeiling(t *testing.T) {
	const count = 1_000_003
	s, e := newLegacy177HashSort(context.Background(), 65536, 32, 256<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	keys := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b")), sha256.Sum256([]byte("c"))}
	counts := map[string]int{}
	for n := 0; n < count; n++ {
		h := keys[n%3]
		counts[hex.EncodeToString(h[:])]++
		if e = s.add(h); e != nil {
			t.Fatal(e)
		}
	}
	ordered := []string{}
	for key := range counts {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	expected := sha256.New()
	expected.Write([]byte("["))
	first := true
	for _, key := range ordered {
		for n := 0; n < counts[key]; n++ {
			if !first {
				expected.Write([]byte(","))
			}
			first = false
			expected.Write([]byte("\"" + key + "\""))
		}
	}
	expected.Write([]byte("]"))
	actual, e := s.digest(count)
	if e != nil || actual != hex.EncodeToString(expected.Sum(nil)) {
		t.Fatal("complete million-row proof differs", e)
	}
}
