package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadReadinessUsesRunningJournalWithoutSQL(t *testing.T) {
	c, base, model, path := downloadDeploymentFixture(t)
	raw, _ := json.Marshal(c)
	pin := writeDownloadFixtureFile(t, path, raw)
	d, err := loadDownloadDeployment(context.Background(), base, model.db, path, pin, c.RegistrationRuntimeSHA256, c.DatabaseUser)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	h, err := mountDownloadHTTP(base.API, d)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	response, err := server.Client().Get(server.URL + downloadReadinessPath)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusNoContent || response.Header.Get(downloadReadinessHeader) != pin || response.Header.Get("Cache-Control") != "no-store" || len(body) != 0 {
		t.Fatal("readiness did not bind the running configuration", err)
	}
	for _, test := range []struct{ method, suffix string }{{"POST", ""}, {"GET", "?x=1"}, {"GET", "?"}} {
		req, err := http.NewRequest(test.method, server.URL+downloadReadinessPath+test.suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode < 400 || res.Header.Get(downloadReadinessHeader) != "" {
			t.Fatal("invalid probe succeeded")
		}
	}
	d.application.Runtime.Close()
	res, err := server.Client().Get(server.URL + downloadReadinessPath)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get(downloadReadinessHeader) != "" || model.queries != 2 || model.base.queries != 0 || model.connections != 1 || model.base.connections != 0 {
		t.Fatal("readiness reopened state, touched SQL or ignored journal closure")
	}
}

func TestDownloadLiveReadinessRequiresTLSIdentityAndExactDigest(t *testing.T) {
	for _, mode := range []string{"ready", "hostname", "missing_ca", "invalid_ca", "unhealthy", "wrong_digest", "duplicate_digest", "redirect", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			pin := strings.Repeat("a", 64)
			calls := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.TLS == nil || r.URL.Path != downloadReadinessPath {
					t.Error("probe lost TLS or path binding")
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/redirect-target", http.StatusFound)
					return
				}
				if mode == "unhealthy" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				value := pin
				if mode == "wrong_digest" {
					value = strings.Repeat("b", 64)
				}
				w.Header().Set(downloadReadinessHeader, value)
				if mode == "duplicate_digest" {
					w.Header().Add(downloadReadinessHeader, pin)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			cert := server.Certificate()
			serverName := cert.DNSNames[0]
			caFile := filepath.Join(t.TempDir(), "server.pem")
			writeDownloadFixtureFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "hostname":
				serverName = "wrong.invalid"
			case "missing_ca":
				caFile += ".missing"
			case "invalid_ca":
				writeDownloadFixtureFile(t, caFile, []byte("PRIVATE-invalid-certificate"))
			case "canceled":
				cancel()
			}
			err := checkLiveDownloadReadiness(ctx, server.URL+downloadReadinessPath, serverName, caFile, pin)
			if (err == nil) != (mode == "ready") || err != nil && err != errDownloadDeployment {
				t.Fatal("probe TLS/status/digest decision", mode, err)
			}
			if mode == "redirect" && calls != 1 || (mode == "missing_ca" || mode == "invalid_ca" || mode == "canceled" || mode == "hostname") && calls != 0 {
				t.Fatal("invalid probe made an unauthorized HTTP request", calls)
			}
		})
	}
}

func TestDownloadModeAndLoopbackBoundary(t *testing.T) {
	base := downloadMode{runtime: "/base.json", deployment: "/download.json", digest: strings.Repeat("a", 64), dsn: "/download-dsn"}
	probe := base
	probe.deployment, probe.liveURL, probe.serverName, probe.check = "", "https://127.0.0.1:9443"+downloadReadinessPath, "registration.backup.svc", true
	for _, mode := range []downloadMode{{}, base, probe} {
		if validateDownloadMode(mode) != nil {
			t.Fatal("valid mode rejected")
		}
	}
	for _, mutate := range []func(*downloadMode){
		func(m *downloadMode) { m.runtime = "" }, func(m *downloadMode) { m.deployment = "" }, func(m *downloadMode) { m.digest = "" }, func(m *downloadMode) { m.dsn = "" }, func(m *downloadMode) { m.capacity = true }, func(m *downloadMode) { m.bootstrap = true }, func(m *downloadMode) { m.serverName = "unexpected" },
	} {
		m := base
		mutate(&m)
		if validateDownloadMode(m) == nil {
			t.Fatal("invalid runtime mode accepted")
		}
	}
	for _, mutate := range []func(*downloadMode){func(m *downloadMode) { m.check = false }, func(m *downloadMode) { m.serverName = "" }, func(m *downloadMode) { m.deployment = "/download.json" }, func(m *downloadMode) { m.dsn = "" }, func(m *downloadMode) { m.digest = "" }, func(m *downloadMode) { m.serverName = "bad name" }} {
		m := probe
		mutate(&m)
		if validateDownloadMode(m) == nil {
			t.Fatal("probe reopened a deployment or bypassed mode requirements")
		}
	}
	for _, raw := range []string{"http://127.0.0.1:9443" + downloadReadinessPath, "https://example.invalid:9443" + downloadReadinessPath, "https://localhost:9443" + downloadReadinessPath, "https://127.0.0.1" + downloadReadinessPath, "https://127.0.0.1:0" + downloadReadinessPath, "https://u:p@127.0.0.1:9443" + downloadReadinessPath, probe.liveURL + "?", probe.liveURL + "#", "https://127.0.0.1:9443/other"} {
		if _, err := downloadReadinessURL(raw); err == nil {
			t.Fatal("nonlocal or ambiguous probe URL accepted", raw)
		}
	}
}
