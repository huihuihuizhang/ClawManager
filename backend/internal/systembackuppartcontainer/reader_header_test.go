package systembackuppartcontainer

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// A reader can change between observations even when callers supply a fixed
// object-version DTO. Header facts must be authenticated by the SAME whole
// byte hash, rather than by a later independent read of the header region.
func TestContainerReaderBindsParsedHeaderToWholeHashData(t *testing.T) {
	scope, source, inputs, checkpoints, _ := containerData(t)
	var output bytes.Buffer
	facts, err := Write(context.Background(), &output, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(output.Bytes())
	changed := reframeData(t, original, func(h *Header) {
		p := []byte(h.Members[0].CipherPath)
		p[len(p)-1] = 'X'
		h.Members[0].CipherPath = string(p)
	}, func(payload []byte) []byte { return payload })
	if len(original) != len(changed) {
		t.Fatal("probe must preserve exact header size")
	}
	sourceReader := &changingHeaderDataReader{original: original, initial: changed, header: int(binary.BigEndian.Uint32(changed[8:12]))}
	got, err := Inspect(context.Background(), FixedObject{Reader: sourceReader, Version: "named-fixed-version-DATA", SHA256: facts.SHA256, Size: facts.Size}, scope, checkpoints, MaxBytes, MaxIndexBytes)
	if err == nil {
		t.Fatalf("parsed header escaped whole-object hash: returned %q, actual authenticated object has %q", got.Header.Members[0].CipherPath, facts.Header.Members[0].CipherPath)
	}
	if got.SHA256 != "" || got.Size != 0 {
		t.Fatal("rejected changed-header source returned complete facts")
	}
}

type changingHeaderDataReader struct {
	original, initial []byte
	header            int
}

func (r *changingHeaderDataReader) ReadAt(p []byte, off int64) (int, error) {
	raw := r.original
	if off == 0 && len(p) == prefixBytes || off == prefixBytes && len(p) == r.header {
		raw = r.initial
	}
	return bytes.NewReader(raw).ReadAt(p, off)
}
