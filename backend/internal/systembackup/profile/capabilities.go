package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CapabilityClient uses the runtime control token and verified TLS. A 404, stale
// Pod identity or partial implementation is not evidence of backup capability.
type CapabilityClient struct {
	HTTP  *http.Client
	Token string
}

func NewCapabilityClient(ca []byte, token string) (*CapabilityClient, error) {
	roots := x509.NewCertPool()
	if token == "" || strings.ContainsAny(token, "\r\n") || !roots.AppendCertsFromPEM(ca) {
		return nil, ErrProfile
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	return &CapabilityClient{HTTP: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Token: token}, nil
}
func (c *CapabilityClient) Close() {
	if c != nil && c.HTTP != nil {
		c.HTTP.CloseIdleConnections()
	}
}
func (c *CapabilityClient) exchange(ctx context.Context, endpoint string, body any, out any) error {
	u, e := url.Parse(endpoint)
	if c == nil || c.HTTP == nil || c.Token == "" || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return ErrProfile
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return ErrProfile
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if e != nil {
		return ErrProfile
	}
	req.Header.Set("X-ClawManager-Control-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	response, e := c.HTTP.Do(req)
	if e != nil {
		return ErrProfile
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrProfile
	}
	raw, e = io.ReadAll(io.LimitReader(response.Body, 32<<10+1))
	if e != nil || len(raw) > 32<<10 {
		return ErrProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrProfile
	}
	return nil
}
func nonce() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (c *CapabilityClient) Agent(ctx context.Context, endpoint, podUID string) error {
	n, e := nonce()
	if e != nil || podUID == "" {
		return ErrProfile
	}
	request := struct{ Version, PodUID, Nonce string }{"gateway-backup.v1", podUID, n}
	var response struct {
		Version, PodUID, Nonce                                           string
		GenerationFence, ProcessTreeStop, IdempotentCreate, UIDIsolation bool
	}
	if e = c.exchange(ctx, strings.TrimRight(endpoint, "/")+"/v1/backup/capabilities", request, &response); e != nil {
		return e
	}
	if response.Version != request.Version || response.PodUID != podUID || response.Nonce != n || !response.GenerationFence || !response.ProcessTreeStop || !response.IdempotentCreate || !response.UIDIsolation {
		return ErrProfile
	}
	return nil
}
func (c *CapabilityClient) NFS(ctx context.Context, endpoint, volumeHash string) error {
	n, e := nonce()
	if e != nil || len(volumeHash) != 64 {
		return ErrProfile
	}
	// A proof must cover the maximum task lifetime, not just this HTTP call.
	request := struct {
		Version, VolumeSHA256, Nonce string
		RequiredUntil                time.Time
	}{"nfs-writer-fence.v1", volumeHash, n, time.Now().Add(2 * time.Hour)}
	var response struct {
		Version, VolumeSHA256, Nonce string
		ExternalWritersFenced        bool
		ValidUntil                   time.Time
	}
	if e = c.exchange(ctx, endpoint, request, &response); e != nil {
		return e
	}
	if response.Version != request.Version || response.VolumeSHA256 != volumeHash || response.Nonce != n || !response.ExternalWritersFenced || response.ValidUntil.Before(request.RequiredUntil) {
		return ErrProfile
	}
	return nil
}
