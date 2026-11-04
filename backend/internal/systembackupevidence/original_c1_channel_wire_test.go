package systembackupevidence

import (
	"crypto/tls"
	"github.com/minio/minio-go/v7/pkg/signer"
	"net/http"
	"testing"
	"time"
)

// Model/source tests only. These cross-check the wire verifier against the
// real SDK signer; they do not stand in for native MinIO/Kube/MySQL tests.
func TestOriginalC1PresignWireBindsMethodKeyTokenAndExpiry(t *testing.T) {
	const access = "actual-signer-model-access"
	secret := []byte("actual-signer-model-secret-32-bytes")
	now := time.Now().UTC()
	until := now.Add(30 * time.Second)
	r, err := http.NewRequest(http.MethodHead, "https://127.0.0.1:19000/bucket/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Amz-Content-Sha256", hash(nil))
	r = signer.PreSignV4(*r, access, string(secret), "model-session-token", "us-east-1", 20)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
	if !c1VerifyPresign(r, access, secret, "model-session-token", "us-east-1", until, now) {
		t.Fatal("real SDK signature refused")
	}
	for _, name := range []string{"method", "key", "token", "expiry", "no-tls", "duplicate-query"} {
		t.Run(name, func(t *testing.T) {
			copy := r.Clone(r.Context())
			u := *r.URL
			copy.URL = &u
			when := now
			switch name {
			case "method":
				copy.Method = http.MethodGet
			case "key":
				copy.URL.Path += ".foreign"
			case "token":
				q := copy.URL.Query()
				q.Set("X-Amz-Security-Token", "foreign")
				copy.URL.RawQuery = q.Encode()
			case "expiry":
				when = until
			case "no-tls":
				copy.TLS = nil
			case "duplicate-query":
				copy.URL.RawQuery += "&X-Amz-Date=20000101T000000Z"
			}
			if c1VerifyPresign(copy, access, secret, "model-session-token", "us-east-1", until, when) {
				t.Fatal("mutated request accepted")
			}
		})
	}
}

func TestOriginalC1VersionsXMLRejectsDuplicateAbsenceControls(t *testing.T) {
	for _, raw := range []string{
		`<ListVersionsResult><IsTruncated>true</IsTruncated><IsTruncated>false</IsTruncated></ListVersionsResult>`,
		`<ListVersionsResult><Version><Key>a</Key><Key>b</Key></Version></ListVersionsResult>`,
		`<ListVersionsResult><DeleteMarker><VersionId>a</VersionId><VersionId>b</VersionId></DeleteMarker></ListVersionsResult>`,
		`<!DOCTYPE x><ListVersionsResult/>`,
		`<ListVersionsResult/><ListVersionsResult/>`,
	} {
		if c1UnambiguousVersionsXML([]byte(raw)) {
			t.Fatal("ambiguous XML accepted")
		}
	}
	if !c1UnambiguousVersionsXML([]byte(`<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>a</Key><VersionId>1</VersionId></Version><Version><Key>b</Key><VersionId>2</VersionId></Version></ListVersionsResult>`)) {
		t.Fatal("unambiguous repeated version entries refused")
	}
}
