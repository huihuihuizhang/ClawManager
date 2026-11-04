package install

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const originalRuntimeMetadataLimit = 8 << 20

// Exact original wire, with a bounded larger envelope for full genuine C1
// records/chunks. The general plan/request/grant decoder limits stay unchanged.
func decodeOriginalRuntimeMetadata(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > originalRuntimeMetadataLimit || !utf8.Valid(raw) {
		return ErrInstall
	}
	c, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(c, raw) {
		return ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	roundtrip, e := canonical(out)
	if e != nil || !bytes.Equal(roundtrip, raw) {
		return ErrInstall
	}
	return nil
}
