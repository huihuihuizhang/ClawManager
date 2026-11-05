package systembackupreferenceprobe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
)

type referenceSeptemberContractTransport func(*http.Request) (*http.Response, error)

func (f referenceSeptemberContractTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Response-contract unit coverage only; this fixture does not establish native
// TLS/Kubernetes/owner authorization or an actual account installation result.
func TestReferenceSeptemberExactOnlineServerContract(t *testing.T) {
	profile, _ := ma.NativeProfile(ma.SeptemberPermissionProfile)
	for _, tc := range []struct {
		name  string
		state string
		edit  func(map[string]any, map[string]any)
		pass  bool
	}{
		{name: "exact_september_online", state: "online", pass: true},
		{name: "old_ok_rejected", state: "ok"},
		{name: "offline_rejected", state: "offline"},
		{name: "empty_rejected", state: ""},
		{name: "uppercase_rejected", state: "ONLINE"},
		{name: "whitespace_rejected", state: "online "},
		{name: "wrong_release", state: "online", edit: func(_ map[string]any, server map[string]any) { server["version"] = "2025-04-22T22:12:26Z" }},
		{name: "wrong_commit", state: "online", edit: func(_ map[string]any, server map[string]any) { server["commitID"] = "wrong-commit" }},
		{name: "wrong_deployment", state: "online", edit: func(doc map[string]any, _ map[string]any) { doc["deploymentID"] = "another-deployment" }},
		{name: "wrong_region", state: "online", edit: func(doc map[string]any, _ map[string]any) { doc["region"] = "another-region" }},
		{name: "no_server", state: "online", edit: func(doc map[string]any, _ map[string]any) { doc["servers"] = []any{} }},
		{name: "multiple_servers", state: "online", edit: func(doc map[string]any, server map[string]any) { doc["servers"] = []any{server, server} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := map[string]any{"state": tc.state, "version": profile.ServerVersion, "commitID": profile.ServerCommit}
			doc := map[string]any{"deploymentID": "original-deployment", "region": "us-east-1", "servers": []any{server}}
			if tc.edit != nil {
				tc.edit(doc, server)
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			r := &minioPermissionHTTP{
				provider:   MinIOProvider{Endpoint: "https://original.invalid", Region: "us-east-1", DeploymentID: "original-deployment"},
				credential: nativePublicationCredential{AccessKey: "unit-contract-account", SecretKey: "unit-contract-secret", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)},
				client: &http.Client{Transport: referenceSeptemberContractTransport(func(request *http.Request) (*http.Response, error) {
					if request.Method != http.MethodGet || request.URL.Path != "/minio/admin/v3/info" || request.URL.RawQuery != "metrics=false" {
						t.Fatal("server contract must use the original bounded info request")
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), ContentLength: int64(len(raw)), Request: request}, nil
				})},
			}
			stamp, err := r.serverSeptember(context.Background())
			if tc.pass {
				if err != nil || !digest.MatchString(stamp) {
					t.Fatalf("exact native response contract rejected: %v", err)
				}
			} else if err == nil || stamp != "" {
				t.Fatal("nonmatching state or original identity accepted")
			}
		})
	}
}
