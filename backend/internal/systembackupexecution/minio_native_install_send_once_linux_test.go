package systembackupexecution

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Authenticated TLS-protocol component, not real MinIO/owner qualification.
func TestMinIONativeInstallerLostReplyQueriesOriginalOperation(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown-still-absent", true: "accepted-and-visible"}[committed], func(t *testing.T) {
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::business"]}]}`)
			file := filepath.Join(dir, "policy.json")
			if e := os.WriteFile(file, policy, 0600); e != nil {
				t.Fatal(e)
			}
			var writes atomic.Int32
			var visible atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" && r.URL.Path == "/minio/admin/v3/add-canned-policy" {
					writes.Add(1)
					_, _ = io.Copy(io.Discard, r.Body)
					visible.Store(committed)
					c, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						_ = c.Close()
					}
					return
				}
				if r.Method != "GET" || r.URL.Path != "/minio/admin/v3/info-canned-policy" {
					w.WriteHeader(500)
					return
				}
				if visible.Load() {
					_ = json.NewEncoder(w).Encode(struct {
						PolicyName string
						Policy     json.RawMessage
					}{"original-policy", policy})
					return
				}
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(map[string]string{"Code": "XMinioAdminNoSuchPolicy", "Message": "not found", "Resource": r.URL.Path, "RequestId": "fixture-request", "HostId": "fixture-host"})
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			caFile := filepath.Join(dir, "ca.crt")
			if e := os.WriteFile(caFile, ca, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			n, e := newMinioPermissionHTTP(minioPermissionProvider{Endpoint: server.URL, Region: "us-east-1", CAFile: caFile, CASHA256: hash(ca), SPKISHA256: hash(server.Certificate().RawSubjectPublicKeyInfo)}, nativePublicationCredential{AccessKey: "original", SecretKey: "fixture-secret", NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)})
			if e != nil {
				t.Fatal(e)
			}
			defer n.close()
			for call := 0; call < 2; call++ {
				e = nativeInstallWriteOnce(ctx, dir, n, nil, "admin", "policy", "create", "native", "original-policy", file)
				if committed && e != nil || !committed && e != install.ErrCommitUnknown {
					t.Fatalf("original outcome mismatch: %v", e)
				}
				if writes.Load() != 1 {
					t.Fatal("retry sent another native mutation")
				}
			}
		})
	}
}
