package systembackuppartcontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// A custom writer and parser agreeing is insufficient evidence for the public
// canonical JSON promise. Check the actual framed bytes with independent JSON
// and JCS implementations. The encrypted members remain named local test DATA.
func TestContainerPhysicalHeaderCanonicalJCSData(t *testing.T) {
	scope, source, inputs, checkpoints, _ := containerData(t)
	var output bytes.Buffer
	facts, err := Write(context.Background(), &output, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes)
	if err != nil {
		t.Fatal(err)
	}
	raw := output.Bytes()[prefixBytes : prefixBytes+facts.HeaderBytes]
	if !json.Valid(raw) {
		t.Fatal("physical header is not JSON")
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		t.Fatal("physical header is not canonical JCS", err)
	}
}
