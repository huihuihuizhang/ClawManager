package worker

import (
	"bytes"
	"clawreef/internal/systembackup/staging"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Invocation contains no credentials. The immutable hash binds paths and policy
// to the task-authorized worker, not just its public backup ID.
type Invocation struct {
	Request       Request `json:"request"`
	WorkspacePath string  `json:"workspace_path"`
	StagingPath   string  `json:"staging_path"`
	EvidencePath  string  `json:"evidence_path,omitempty"`
}

func (i Invocation) Hash() (string, error) {
	b, e := json.Marshal(i)
	if e != nil {
		return "", ErrRequest
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

type ControlRequest struct {
	Invocation       Invocation `json:"invocation"`
	InvocationSHA256 string     `json:"invocation_sha256"`
	Action           string     `json:"action"`
	Point            string     `json:"point,omitempty"`
	Result           *Result    `json:"result,omitempty"`
}
type Lease struct {
	InvocationSHA256 string              `json:"invocation_sha256"`
	ExpiresAt        time.Time           `json:"expires_at"`
	DEK              []byte              `json:"dek,omitempty"`
	Database         *DatabaseCredential `json:"database,omitempty"`
}

// Clear releases mutable credential buffers. Driver password strings cannot be
// guaranteed zeroized in Go; the short-lived worker must exit after its task.
func (l *Lease) Clear() {
	clear(l.DEK)
	if l.Database != nil {
		clear(l.Database.Password)
	}
}
func validLeasePayload(l Lease, r ControlRequest) bool {
	if !validLease(l, r) {
		return false
	}
	if r.Action != "acquire" {
		return len(l.DEK) == 0 && l.Database == nil
	}
	if len(l.DEK) != 32 {
		return false
	}
	if !databaseOperation(r.Invocation.Request.Operation) {
		return l.Database == nil
	}
	return l.Database != nil && l.Database.Username != "" && len(l.Database.Username) <= 128 && len(l.Database.Password) > 0 && len(l.Database.Password) <= 4096
}

// Authorizer must consult the shared task/resource journals, certificate identity,
// cancellation, capture barrier/fence and observed isolation. Acquire calls the
// shared key provider; it must bind the envelope and never give an unwrap grant
// to a capture identity. No permissive default Authorizer is supplied.
type Authorizer interface {
	Authorize(context.Context, string, ControlRequest) (Lease, error)
}
type ControlHandler struct{ Authorizer Authorizer }

func (h ControlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.Authorizer == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "spiffe" || cert.URIs[0].Host == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req ControlRequest
	if decodeBounded(r.Body, &req, 1<<20) != nil || !validControl(req) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	lease, e := h.Authorizer.Authorize(r.Context(), cert.URIs[0].String(), req)
	defer lease.Clear()
	if e != nil {
		if e == ErrNotReady {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}
	if !validLeasePayload(lease, req) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lease)
}
func validControl(r ControlRequest) bool {
	q := r.Invocation.Request
	if !validWorkBuddyIdentityRequest(q) {
		return false
	}
	if databaseOperation(q.Operation) {
		if !validDatabaseRequest(q) || r.Invocation.WorkspacePath != "" || r.Invocation.StagingPath == "" || (q.Operation == "restore-database" && r.Invocation.EvidencePath == "") || (q.Operation != "restore-database" && r.Invocation.EvidencePath != "") {
			return false
		}
	} else if assetOperation(q.Operation) {
		if !validAssetRequest(q) || r.Invocation.WorkspacePath == "" || r.Invocation.StagingPath == "" || r.Invocation.EvidencePath != "" {
			return false
		}
	} else if q.Database != nil || r.Invocation.EvidencePath != "" || q.Version != Version || (q.Operation != "capture-workspace" && q.Operation != "restore-workspace") || q.MaxFiles <= 0 || q.MaxFiles > 1_000_000 || q.MaxFileBytes <= 0 || q.MaxArchiveBytes < q.MaxFileBytes || q.MaxArchiveBytes > 1<<50 || q.MaxCompressedBytes <= 0 || q.MaxCompressedBytes > 1<<50 {
		return false
	}
	h, e := r.Invocation.Hash()
	if e != nil || h != r.InvocationSHA256 || !time.Now().Before(r.Invocation.Request.Deadline) {
		return false
	}
	switch r.Action {
	case "ready", "acquire":
		return r.Point == "" && r.Result == nil
	case "check":
		return r.Result == nil && validCheckpoint(q.Operation, r.Point)
	case "complete":
		return r.Point == "" && validResult(q, r.Result)
	}
	return false
}

func ValidateControl(r ControlRequest) bool { return validControl(r) }

// ValidateRecordedInvocation validates durable recovery data after its deadline.
// This MUST NOT authorize execution; live requests still use ValidateControl.
func ValidateRecordedInvocation(i Invocation) bool {
	if i.Request.Deadline.IsZero() {
		return false
	}
	i.Request.Deadline = time.Now().Add(time.Minute)
	hash, e := i.Hash()
	return e == nil && validControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "ready"})
}

// ValidateResult also works after the worker deadline for durable reconciliation.
// It does not authorize a worker or establish that a Kubernetes Job completed.
func ValidateResult(r Request, result *Result) bool { return validResult(r, result) }
func validReceipt(receipt staging.Receipt) bool {
	if receipt.Name == "" || receipt.Size <= 0 || len(receipt.SHA256) != 64 {
		return false
	}
	_, e := hex.DecodeString(receipt.SHA256)
	return e == nil
}
func validResult(r Request, result *Result) bool {
	if result == nil || result.Files < 0 || result.Bytes < 0 || result.Rows < 0 || result.Tables < 0 || result.NormalizedFiles < 0 {
		return false
	}
	if !validReceipt(result.Receipt) {
		return false
	}
	switch r.Operation {
	case "capture-workspace", "capture-database":
		return !result.Quarantined && !result.Verified && result.Receipt.Name == r.ArtifactName
	case "restore-workspace", "restore-assets":
		return result.Quarantined && !result.Verified && result.Receipt == r.Receipt
	case "restore-database":
		return result.Quarantined && !result.Verified && result.Receipt == r.Receipt && r.Database != nil && result.Evidence.Name == r.Database.EvidenceName && validReceipt(result.Evidence)
	case "verify-database", "verify-assets":
		return result.Quarantined && result.Verified && result.Receipt == r.Receipt
	}
	return false
}
func validCheckpoint(operation, point string) bool {
	if point == "prepare" {
		return true
	}
	switch operation {
	case "capture-workspace", "capture-database":
		return point == "before-capture" || point == "before-seal" || point == "sealed"
	case "restore-workspace", "restore-assets":
		return point == "before-restore" || point == "before-normalize" || point == "restored-quarantine"
	case "restore-database":
		return point == "before-restore" || point == "database-isolation" || point == "before-evidence" || point == "before-database-commit" || point == "restored-quarantine"
	case "verify-database", "verify-assets":
		return point == "before-verify" || point == "database-isolation" || point == "verified-quarantine"
	}
	return false
}
func validLease(l Lease, r ControlRequest) bool {
	return l.InvocationSHA256 == r.InvocationSHA256 && time.Now().Before(l.ExpiresAt) && !l.ExpiresAt.After(r.Invocation.Request.Deadline)
}

type ControlClient struct {
	endpoint string
	http     *http.Client
}

// NewControlClient enables mutual TLS with an explicit CA and no redirects or
// environment proxy. Task-issued certificates are mounted by the coordinator;
// no service-account token or in-cluster API access is needed by the worker.
func NewControlClient(endpoint, caFile, certFile, keyFile string) (*ControlClient, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrRequest
	}
	ca, e := os.ReadFile(caFile)
	if e != nil {
		return nil, ErrNotReady
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrNotReady
	}
	certificate, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, ErrNotReady
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxConnsPerHost: 2}
	return &ControlClient{endpoint: endpoint, http: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *ControlClient) Close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *ControlClient) call(ctx context.Context, i Invocation, action, point string) (Lease, error) {
	if c == nil || c.http == nil {
		return Lease{}, ErrNotReady
	}
	hash, e := i.Hash()
	if e != nil {
		return Lease{}, e
	}
	request := ControlRequest{Invocation: i, InvocationSHA256: hash, Action: action, Point: point}
	return c.send(ctx, request)
}
func (c *ControlClient) send(ctx context.Context, request ControlRequest) (Lease, error) {
	if c == nil || c.http == nil {
		return Lease{}, ErrNotReady
	}
	if !validControl(request) {
		return Lease{}, ErrRequest
	}
	b, e := json.Marshal(request)
	if e != nil {
		return Lease{}, ErrRequest
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(b))
	if e != nil {
		return Lease{}, ErrRequest
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(r)
	if e != nil {
		return Lease{}, ErrNotReady
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusServiceUnavailable {
		return Lease{}, ErrNotReady
	}
	if response.StatusCode != http.StatusOK {
		return Lease{}, ErrExecution
	}
	var lease Lease
	if decodeBounded(response.Body, &lease, 64<<10) != nil || !validLeasePayload(lease, request) {
		lease.Clear()
		return Lease{}, ErrExecution
	}
	return lease, nil
}
func (c *ControlClient) Ready(ctx context.Context, i Invocation) error {
	_, e := c.call(ctx, i, "ready", "")
	return e
}
func (c *ControlClient) Acquire(ctx context.Context, i Invocation) (Lease, error) {
	return c.call(ctx, i, "acquire", "")
}
func (c *ControlClient) Check(ctx context.Context, i Invocation, point string) error {
	_, e := c.call(ctx, i, "check", point)
	return e
}
func (c *ControlClient) Complete(ctx context.Context, i Invocation, result Result) error {
	hash, e := i.Hash()
	if e != nil {
		return e
	}
	_, e = c.send(ctx, ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "complete", Result: &result})
	return e
}
func decodeBounded(r io.Reader, dst any, limit int64) error {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(b)) > limit {
		return ErrRequest
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrRequest
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrRequest
	}
	return nil
}
func ReadInvocation(r io.Reader) (Invocation, error) {
	var i Invocation
	if decodeBounded(r, &i, 1<<20) != nil || (!databaseOperation(i.Request.Operation) && i.WorkspacePath == "") || i.StagingPath == "" || strings.ContainsAny(i.WorkspacePath+i.StagingPath+i.EvidencePath, "\x00\r\n") {
		return Invocation{}, ErrRequest
	}
	return i, nil
}
