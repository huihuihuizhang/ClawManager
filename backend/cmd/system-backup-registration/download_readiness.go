package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const downloadReadinessPath = "/internal/system-backup-download/ready"
const downloadReadinessHeader = "X-System-Backup-Download-Runtime-SHA256"

type downloadMode struct {
	runtime, deployment, liveURL, serverName, digest, dsn string
	capacity, bootstrap, check                            bool
}

func validateDownloadMode(m downloadMode) error {
	if m.liveURL != "" {
		if !m.check || m.runtime == "" || m.deployment != "" || m.capacity || m.bootstrap || m.serverName == "" || len(m.serverName) > 253 || strings.ContainsAny(m.serverName, " \t\r\n/\\") || !downloadDigest.MatchString(m.digest) || m.dsn == "" {
			return errDownloadDeployment
		}
		_, err := downloadReadinessURL(m.liveURL)
		return err
	}
	if m.serverName != "" || m.deployment != "" && (m.runtime == "" || m.capacity || m.bootstrap || !downloadDigest.MatchString(m.digest) || m.dsn == "") || m.deployment == "" && (m.digest != "" || m.dsn != "") {
		return errDownloadDeployment
	}
	return nil
}

func downloadReadinessURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path != downloadReadinessPath || u.RawPath != "" || strings.ContainsAny(raw, "?#") || u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, errDownloadDeployment
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errDownloadDeployment
	}
	return u, nil
}

// The exec probe first checks registration's actual configuration/SQL scope,
// then contacts this process over loopback. Trust the mounted server certificate
// chain with normal hostname/expiry verification; never skip TLS verification.
// It does not load download configuration, credentials, authority or journal.
func checkLiveDownloadReadiness(ctx context.Context, rawURL, serverName, certificateFile, digest string) error {
	u, err := downloadReadinessURL(rawURL)
	if err != nil || ctx == nil || ctx.Err() != nil || serverName == "" || !downloadDigest.MatchString(digest) {
		return errDownloadDeployment
	}
	certificates, err := deploymentBytes(certificateFile, 262144)
	if err != nil {
		return errDownloadDeployment
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificates) {
		return errDownloadDeployment
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12},
		DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
		TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: time.Second,
		DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errDownloadDeployment }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return errDownloadDeployment
	}
	response, err := client.Do(req)
	if err != nil {
		return errDownloadDeployment
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1))
	if err != nil || len(body) != 0 || response.StatusCode != http.StatusNoContent || len(response.Header.Values(downloadReadinessHeader)) != 1 || response.Header.Get(downloadReadinessHeader) != digest {
		return errDownloadDeployment
	}
	return nil
}
