package install

import (
	"strings"
	"testing"
)

func TestOriginalRuntimeMetadataLargerClosedWireDoesNotRelaxGrantDecoder(t *testing.T) {
	var value struct{ Payload string }
	value.Payload = strings.Repeat("x", 300000)
	raw, e := canonical(value)
	if e != nil {
		t.Fatal(e)
	}
	var actual struct{ Payload string }
	if decodeOriginalRuntimeMetadata(raw, &actual) != nil || actual != value {
		t.Fatal("bounded full-source metadata rejected")
	}
	if decodeExact(raw, &actual) == nil {
		t.Fatal("general grant/request limit was relaxed")
	}
	for _, bad := range [][]byte{
		[]byte(`{"Passed":true,"Payload":"source"}`),
		[]byte(`{"payload":"source"}`),
		append(append([]byte(nil), raw...), []byte("{}")...),
		[]byte(`{"Payload":"a","Payload":"b"}`),
		[]byte(strings.Repeat("x", originalRuntimeMetadataLimit+1)),
	} {
		if decodeOriginalRuntimeMetadata(bad, &actual) == nil {
			t.Fatal("noncanonical/unknown/oversize source accepted")
		}
	}
}
