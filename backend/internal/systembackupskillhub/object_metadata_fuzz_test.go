package systembackupskillhub

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Check fidelity using an independent JSON decoder, including strings that
// encoding/json would normally HTML-escape and invalid UTF-8 inputs.
func FuzzCanonicalObjectMetadata(f *testing.F) {
	for _, value := range []string{"", "text/plain", "中文<>&\u2028\u2029", "quote\"slash\\tab\t", "\x00", "\xff"} {
		f.Add(value, "owner")
	}
	f.Fuzz(func(t *testing.T, value, owner string) {
		m := ObjectMetadata{ContentType: value, UserMetadata: map[string]string{"owner": owner, "second": value}}
		encoded, err := CanonicalObjectMetadata(context.Background(), m)
		if err != nil {
			if encoded != nil {
				t.Fatal("returned partial canonical bytes on failure")
			}
			return
		}
		if len(encoded) > MaxObjectMetadataBytes || !json.Valid(encoded) {
			t.Fatal("invalid or unbounded JSON")
		}
		var decoded struct {
			ContentType string            `json:"content_type"`
			User        map[string]string `json:"user_metadata_allowlist"`
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ContentType != value || decoded.User["owner"] != owner || decoded.User["second"] != value || len(decoded.User) != 2 {
			t.Fatal("canonical JSON changed metadata values")
		}
		m.UserMetadata = map[string]string{}
		m.UserMetadata["second"] = value
		m.UserMetadata["owner"] = owner
		again, err := CanonicalObjectMetadata(context.Background(), m)
		if err != nil || !bytes.Equal(encoded, again) {
			t.Fatal("encoding depends on map iteration order")
		}
	})
}
