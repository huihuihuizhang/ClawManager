package profile

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
)

func TestWriterCoverageBindsProofToInventoryProcessAndDeadline(t *testing.T) {
	for _, failure := range []string{"", "nonce", "inventory", "expiry", "partial", "ungated", "remote", "legacy"} {
		t.Run(failure, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-ClawManager-Control-Token") != "fixture-token" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				var request WriterProofRequest
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Process == nil || request.Process.ID != "original-process" || len(request.Permits) != 1 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				nonce, digest, expiry := request.Nonce, kube.ContentHash(request), request.RequiredUntil
				switch failure {
				case "nonce":
					nonce = "old-response"
				case "inventory":
					digest = strings.Repeat("0", 64)
				case "expiry":
					expiry = expiry.Add(-time.Second)
				}
				json.NewEncoder(w).Encode(map[string]any{"Version": request.Version, "Nonce": nonce, "RequestSHA256": digest, "Complete": failure != "partial", "GateEnforced": failure != "ungated", "RemoteEffectsStopped": failure != "remote", "LegacyIdentityConfirmed": failure != "legacy", "ValidUntil": expiry})
			}))
			defer server.Close()
			client, err := NewCapabilityClient(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), "fixture-token")
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			r := WriterProofRequest{Task: "fixture", Mode: "resolve-legacy", Database: "fixture", ServerUUID: "uuid", InventorySHA256: strings.Repeat("a", 64), RequiredUntil: time.Now().Add(time.Minute), Process: &control.AppProcess{ID: "original-process"}, Permits: []control.MutationPermit{{Token: "old-token", Participant: "api"}}}
			err = client.WriterCoverage(context.Background(), server.URL, r)
			if (err == nil) != (failure == "") {
				t.Fatalf("proof acceptance mismatch: %v", err)
			}
		})
	}
}
