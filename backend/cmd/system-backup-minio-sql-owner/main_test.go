package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
)

func TestOriginalMinIOSQLOwnerCLIRefusesImplicitOrForeignFlows(t *testing.T) {
	for _, args := range [][]string{nil, {"install"}, {"issue-install"}, {"prepare-input"}, {"import-qualified"}, {"import-revocation"}, {"resolve"}, {"export-terminal"}, {"issue-revocation"}, {"resolve", "--passed=true"}, {"prepare-input", "--task=generated-task"}, {"export-terminal", "--publisher-verifier-dsn=foreign"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out); code != 2 || out.Len() != 0 {
			t.Fatalf("unsupported/incomplete flow returned code=%d data=%q", code, out.String())
		}
	}
}

func TestOriginalMinIOSQLOwnerCLIPinRequiresExactPrivateCanonicalBytes(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "original-pin.json")
	pin := ma.SQLTrustPin{AuthorityID: "original-authority"}
	raw, e := ce.Canonical(pin)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var decoded ma.SQLTrustPin
	if e = pinnedJSON(path, digest(raw), &decoded); e != nil || decoded.AuthorityID != pin.AuthorityID {
		t.Fatal("exact metadata pin decoding", e)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), byte('\n')), bytes.Replace(raw, []byte(`"AuthorityID":"original-authority"`), []byte(`"AuthorityID":"original-authority","AuthorityID":"foreign"`), 1), bytes.Replace(raw, []byte(`"AuthorityID"`), []byte(`"authorityid"`), 1)} {
		if bytes.Equal(bad, raw) {
			t.Fatal("invalid pin case did not mutate original bytes")
		}
		if e = os.WriteFile(path, bad, 0600); e != nil {
			t.Fatal(e)
		}
		if pinnedJSON(path, digest(bad), &decoded) == nil {
			t.Fatal("noncanonical/duplicate/alias pin accepted")
		}
	}
}
