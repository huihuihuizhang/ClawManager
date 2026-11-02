package systembackupinstallationowner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrollmentCandidateNeverEstablishesTrust(t *testing.T) {
	dir := t.TempDir()
	c, e := GenerateEnrollmentCandidate(dir)
	if e != nil {
		t.Fatal(e)
	}
	if c.Status != "untrusted_candidate_requires_user_enrollment" {
		t.Fatal("candidate claimed enrollment")
	}
	pub, e := os.ReadFile(filepath.Join(dir, "owner-issuer.public"))
	if e != nil || len(pub) != 32 || digest(pub) != c.PublicKeySHA256 {
		t.Fatal("public pin")
	}
	key, e := os.ReadFile(filepath.Join(dir, "owner-issuer.private"))
	defer clear(key)
	if e != nil || len(key) != 64 {
		t.Fatal("private key")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatal("extra trust/ledger artifacts")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "enrollment-candidate.json"))
	var out EnrollmentCandidate
	if decodeCanonical(raw, &out) != nil || out != c {
		t.Fatal("candidate codec")
	}
	before := bytes.Clone(pub)
	if _, e := GenerateEnrollmentCandidate(dir); e == nil {
		t.Fatal("overwrote candidate")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "owner-issuer.public"))
	if !bytes.Equal(before, after) {
		t.Fatal("existing material changed")
	}
	if b, _ := json.Marshal(c); bytes.Contains(b, []byte("private")) {
		t.Fatal("private bytes/locator exposed")
	}
	if _, e := GenerateEnrollmentCandidate("relative"); e == nil {
		t.Fatal("relative output accepted")
	}
}
