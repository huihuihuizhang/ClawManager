package systembackupinstallationowner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInstalledVaultDependencyOpaqueRequiresActualNativeObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var zero ObservedInstalledVaultDependency
	if zero.Recheck(ctx, time.Now()) == nil {
		t.Fatal("zero observation accepted")
	}
	if _, _, e := zero.Data(ctx); e == nil {
		t.Fatal("zero observation produced authoritative source data")
	}
	if _, e := NewInstalledVaultDependencyObserver(InstalledVaultDependencyConfig{}, nil, "", ""); e == nil {
		t.Fatal("missing actual installation identity accepted")
	}
}

// Actual TLS/HTTP status model; not Vault execution, Kube, JWT, key metadata,
// an original admin or a successful dependency/source hold.
func TestInstalledVaultRoleListSeparatesDeniedMissingAndEmpty(t *testing.T) {
	for _, test := range []struct {
		name           string
		status         int
		body           string
		allowed, empty bool
	}{
		{"empty-existing-mount", 404, `{"errors":[]}`, true, true},
		{"denied-list", 403, `{"errors":["permission denied"]}`, false, true},
		{"wrong-path", 404, `{"errors":["unsupported path"]}`, false, true},
		{"missing-keys", 404, `{"errors":[]}`, false, false},
		{"explicit-empty", 200, `{"data":{"keys":[]}}`, true, true},
		{"unknown-list", 200, `{"data":{}}`, false, true},
		{"null-list", 200, `{"data":{"keys":null}}`, false, true},
		{"duplicate-roles", 200, `{"data":{"keys":["same","same"]}}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "LIST" {
					t.Error("unexpected method")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			o := &InstalledVaultDependencyObserver{cfg: InstalledVaultDependencyConfig{Endpoint: server.URL}, transport: &CaptureSigningObserver{client: server.Client()}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			names, e := o.listMetadata(ctx, "/v1/auth/actual-installed-mount/role", []byte("fixture-token-not-authority"), test.empty)
			if (e == nil) != test.allowed || e == nil && len(names) != 0 {
				t.Fatal("empty/denied native census conflated")
			}
		})
	}
}
