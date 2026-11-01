package worker

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"
	k "clawreef/internal/systembackupkms"
)

// Real local TLS transport/status rejection only; the server grants no key or
// source authority. Production ControlClient.send keeps its original result.
func TestDescriptionControlHTTPDiagnosticPreservesDeniedStatus(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			i, _, _ := formalInvocationFixture(t)
			seed := cd.Seed{Version: cd.SeedVersion, Members: []cd.Selection{{Part: "business_sql", Operation: "capture-database", PartIndex: 3}}}
			seed.MaxPlaintextBytes, _ = cd.Budget(1)
			i.Request.Operation, i.Request.Binding.Path, i.Request.Binding.PartIndex = cd.Operation, cd.Part, 0
			i.Request.ArtifactName, i.Request.CaptureDescription = cd.LogicalCipherName, &seed
			i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = seed.MaxPlaintextBytes, seed.MaxPlaintextBytes
			i.Request.MaxFiles, i.Request.MaxFileBytes, i.WorkspacePath = 0, 0, ""
			i.ProviderKey.Request.Context.Part, i.ProviderKey.Request.Context.PartIndex = cd.Part, "0"
			i.FormalCapture.MaxFrames = 64
			i.FormalCapture.SourceConfigSHA256 = strings.Repeat("e", 64)
			i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}
			sha, _ := i.Hash()
			request := ControlRequest{Invocation: i, InvocationSHA256: sha, Action: "key-check", Point: strings.Repeat("c", 32)}
			if !ValidateControl(request) {
				t.Fatal("invalid named local description request DATA")
			}
			secret := "PRIVATE_RESPONSE_SQL_SOURCE_TOKEN_BODY"
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				_, _ = w.Write([]byte(secret))
			}))
			defer server.Close()
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(previous)
			client := &ControlClient{endpoint: server.URL, http: server.Client()}
			defer client.Close()
			_, err := client.send(context.Background(), request)
			want := ErrExecution
			if status == http.StatusServiceUnavailable {
				want = ErrNotReady
			}
			if !errors.Is(err, want) || calls != 1 || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=worker-control-http action=key-check") {
				t.Fatal("diagnostic changed denied transport or logged body", err, calls)
			}
		})
	}
}
