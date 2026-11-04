package systembackupinstallationowner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Real TLS/HTTP wire status fixture; no Vault, original credentials, token
// issuance or current installation availability is claimed by these tests.
func TestInstalledMetadataPolicyWriteUsesNative204(t *testing.T) {
	for _, test := range []struct {
		name           string
		status         int
		body, encoding string
		want           bool
	}{
		{"native-empty204", 204, "", "", true},
		{"json200", 200, `{"data":{}}`, "", true},
		{"denied", 403, `{"errors":["denied"]}`, "", false},
		{"missing", 404, `{"errors":[]}`, "", false},
		{"busy", 503, `{"errors":[]}`, "", false},
		{"empty200", 200, "", "", false},
		{"encoded", 200, `{"data":{}}`, "gzip", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/sys/policies/acl/fixture" || r.Header.Get("X-Vault-Token") != "fixture-non-authority" {
					t.Error("unexpected mutation request")
				}
				w.Header().Set("Content-Encoding", test.encoding)
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			o := &InstalledVaultDependencyObserver{cfg: InstalledVaultDependencyConfig{Endpoint: server.URL}, transport: &CaptureSigningObserver{client: server.Client()}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, e := o.metadataIdentityWrite(ctx, "/v1/sys/policies/acl/fixture", []byte("fixture-non-authority"), []byte(`{"policy":"metadata fixture"}`))
			if (e == nil) != test.want {
				t.Fatal("native policy-write result misclassified")
			}
		})
	}
}
