package systembackupreferenceprobe

import (
	"encoding/json"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferencePolicyRejectsBroaderAndUnversionedPermissions(t *testing.T) {
	want := []minioPermissionRule{{[]string{"s3:GetObjectVersion"}, []string{"arn:aws:s3:::evidence/root/install/*"}}}
	valid := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObjectVersion"],"Resource":["arn:aws:s3:::evidence/root/install/*"]}]}`)
	canonical, e := jsoncanonicalizer.Transform(valid)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := minioPermissionNormalizedPolicyV2(valid, hash(canonical), want); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(valid), "s3:GetObjectVersion", "s3:GetObject", 1)),
		[]byte(strings.Replace(string(valid), "root/install/*", "root/*", 1)),
		[]byte(strings.Replace(string(valid), `"Effect":"Allow"`, `"Effect":"Allow","Condition":{}`, 1)),
		[]byte(strings.Replace(string(valid), `"Effect":"Allow"`, `"Effect":"Allow","Effect":"Allow"`, 1)),
	} {
		canonical, e := jsoncanonicalizer.Transform(raw)
		if e != nil {
			canonical = raw
		}
		if _, e := minioPermissionNormalizedPolicyV2(raw, hash(canonical), want); e == nil {
			t.Fatal("broader/ambiguous policy accepted")
		}
	}
}
func TestReferencePinnedCredentialReplacementRejects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential.json")
	raw := []byte("original")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	pin := FilePin{path, hash(raw)}
	got, e := ReadPinned(pin, 128)
	if e != nil || string(got) != "original" {
		t.Fatal("original pin")
	}
	if e := os.WriteFile(path, []byte("replaced"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPinned(pin, 128); e == nil {
		t.Fatal("changed pin accepted")
	}
	if _, e := json.Marshal(&S3Observation{}); e == nil {
		t.Fatal("observation transport accepted")
	}
}
