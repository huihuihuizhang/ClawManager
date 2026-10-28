package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"
)

const maxS3EvidenceObject = MaxContent + MaxHeader + 12 + 28*(MaxContent/ChunkSize)

type S3Operation string

const (
	S3Stat   S3Operation = "evidence_stat"
	S3Range  S3Operation = "evidence_range"
	S3Put    S3Operation = "evidence_create"
	S3Delete S3Operation = "evidence_delete_version"
)

// S3Scope comes from the registered intent, never directly from an Admin body.
// Resolve must verify current task/claim, owner deadline, immutable configuration
// and revocation before issuing operation-specific, exact-object credentials.
type S3Scope struct {
	Ref            Ref
	Operation      S3Operation
	Object         ObjectInfo
	Offset, Length int64
	Deadline       time.Time
}

type S3Credential struct {
	Scope                              S3Scope
	AccessKey, SecretKey, SessionToken []byte
	ExpiresAt                          time.Time
}

type S3Credentials interface {
	Resolve(context.Context, S3Scope) (S3Credential, error)
}

type S3AbsenceRequest struct {
	Ref       Ref
	Challenge string
}

type S3AbsenceProof struct {
	Request               S3AbsenceRequest
	ObservedAt, ExpiresAt time.Time
}

// S3AbsenceVerifier must authenticate a fresh C-owned provider proof, including
// issuer, endpoint/bucket/root/CA identity, exact key/version, permission and
// consistency-window semantics. For an unversioned pending intent it must prove
// exact-key absence, not merely absence of a current version behind a marker.
// A 404, DELETE acknowledgement or caller-supplied boolean is NOT such a proof.
// Successful return asserts verification; the store also checks freshness and
// challenge binding. There is deliberately no permissive default implementation.
type S3AbsenceVerifier interface {
	VerifyAbsent(context.Context, S3AbsenceRequest) (S3AbsenceProof, error)
}

// S3Config is a trusted immutable registry mapping, not a capability approval.
// This profile uses path-style, versioned S3, single PUT and native SHA256.
type S3Config struct {
	Endpoint, Region, Bucket, Root, Installation string
	Identity, Version                            string
	CAPEM                                        []byte
	CASHA256                                     string
}

type S3Store struct {
	config      S3Config
	client      *http.Client
	credentials S3Credentials
	absence     S3AbsenceVerifier
}

var _ Store = (*S3Store)(nil)

func NewS3Store(c S3Config, credentials S3Credentials, absence S3AbsenceVerifier) (*S3Store, error) {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.Opaque != "" ||
		strings.ContainsAny(c.Endpoint, "?#\r\n") || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(c.Region) ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") ||
		!safeKey(c.Root) || !installationPattern.MatchString(c.Installation) || !digestPattern.MatchString(c.Identity) || !versionPattern.MatchString(c.Version) ||
		len(c.CAPEM) > 65536 || !digestPattern.MatchString(c.CASHA256) || hash(c.CAPEM) != c.CASHA256 || credentials == nil || absence == nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) {
		return nil, ErrInvalid
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 16384, DisableCompression: true, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c.CAPEM = nil // The immutable parsed roots are owned by the transport.
	return &S3Store{config: c, client: client, credentials: credentials, absence: absence}, nil
}

func (s *S3Store) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}

func s3Version(v string) bool { return len(v) <= 256 && v != "null" && s3Token([]byte(v), 1, 256) }

func (s *S3Store) validRef(r Ref, published bool) bool {
	return s != nil && r.valid(published) && r.Identity == s.config.Identity && r.Version == s.config.Version &&
		strings.HasPrefix(r.RelativeKey, s.config.Root+"/"+s.config.Installation+"/") &&
		(r.ImmutableVersion == "" || s3Version(r.ImmutableVersion))
}

func s3Token(b []byte, lo, hi int) bool {
	if len(b) < lo || len(b) > hi {
		return false
	}
	for _, v := range b {
		if v < 33 || v > 126 {
			return false
		}
	}
	return true
}

func s3Header(h http.Header, name string) string {
	v := h.Values(name)
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

func s3Checksum(h http.Header) (string, bool) {
	encoded := s3Header(h, "X-Amz-Checksum-Sha256")
	decoded, e := base64.StdEncoding.Strict().DecodeString(encoded)
	kind := h.Values("X-Amz-Checksum-Type")
	validKind := len(kind) == 0 || len(kind) == 1 && kind[0] == "FULL_OBJECT"
	return hex.EncodeToString(decoded), e == nil && len(decoded) == 32 && base64.StdEncoding.EncodeToString(decoded) == encoded && validKind
}

// do signs all operation constraints, including a server-visible expiry. The
// signed URL never leaves this client. The live resolver must return actual STS
// credentials; local declarations alone cannot establish provider-side scope.
func (s *S3Store) do(ctx context.Context, scope S3Scope, method string, body io.Reader, headers http.Header) (*http.Response, context.CancelFunc, error) {
	if ctx.Err() != nil || s.client == nil || s.credentials == nil {
		return nil, nil, ErrUnavailable
	}
	grant, e := s.credentials.Resolve(ctx, scope)
	defer wipe(grant.AccessKey)
	defer wipe(grant.SecretKey)
	defer wipe(grant.SessionToken)
	if e != nil || grant.Scope != scope || !s3Token(grant.AccessKey, 3, 256) || !s3Token(grant.SecretKey, 16, 4096) || !s3Token(grant.SessionToken, 16, 16384) {
		return nil, nil, ErrDenied
	}
	deadline := time.Now().Add(60 * time.Second)
	if grant.ExpiresAt.Before(deadline) {
		deadline = grant.ExpiresAt
	}
	if !scope.Deadline.IsZero() && scope.Deadline.Before(deadline) {
		deadline = scope.Deadline
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	expires := int64(time.Until(deadline) / time.Second)
	if expires < 1 {
		return nil, nil, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	u, _ := url.Parse(s.config.Endpoint)
	u.Path = "/" + s.config.Bucket + "/" + scope.Ref.RelativeKey
	if scope.Ref.ImmutableVersion != "" {
		u.RawQuery = url.Values{"versionId": {scope.Ref.ImmutableVersion}}.Encode()
	}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), body)
	if e != nil {
		cancel()
		return nil, nil, ErrUnavailable
	}
	req.Header = headers
	if method == http.MethodPut {
		req.ContentLength = scope.Object.Size
		req.Header.Set("Content-Length", strconv.FormatInt(scope.Object.Size, 10))
	}
	// Prevent transport replay of a write body even if its reader is seekable.
	req.GetBody = nil
	req = signer.PreSignV4(*req, string(grant.AccessKey), string(grant.SecretKey), string(grant.SessionToken), s.config.Region, expires)
	// Let a provider reject a conditional upload before streaming a large body.
	// Expect is transport negotiation, not an authorization constraint; the body
	// digest and length remain signed independently.
	if method == http.MethodPut {
		req.Header.Set("Expect", "100-continue")
	}
	signedAt, e := time.Parse("20060102T150405Z", req.URL.Query().Get("X-Amz-Date"))
	if e != nil || signedAt.Add(time.Duration(expires)*time.Second).After(deadline) {
		cancel()
		return nil, nil, ErrDenied
	}
	res, e := s.client.Do(req)
	if e != nil {
		cancel()
		return nil, nil, ErrUnavailable
	}
	marker := res.Header.Values("X-Amz-Delete-Marker")
	validMarker := len(marker) == 0 || len(marker) == 1 && marker[0] == "false"
	if ctx.Err() != nil || !time.Now().Before(deadline) || len(res.Header.Values("Content-Encoding")) != 0 || !validMarker {
		res.Body.Close()
		cancel()
		return nil, nil, ErrUnavailable
	}
	return res, cancel, nil
}

func s3ReadHeaders() http.Header {
	return http.Header{"X-Amz-Content-Sha256": {hash(nil)}, "X-Amz-Checksum-Mode": {"ENABLED"}}
}

func (s *S3Store) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	if !s.validRef(ref, false) {
		return ObjectInfo{}, ErrInvalid
	}
	res, cancel, e := s.do(ctx, S3Scope{Ref: ref, Operation: S3Stat}, http.MethodHead, nil, s3ReadHeaders())
	if e != nil {
		return ObjectInfo{}, e
	}
	defer cancel()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ObjectInfo{}, ErrUnavailable
	}
	version := s3Header(res.Header, "X-Amz-Version-Id")
	checksum, valid := s3Checksum(res.Header)
	if !s3Version(version) || ref.ImmutableVersion != "" && ref.ImmutableVersion != version || !valid || res.ContentLength < 1 || res.ContentLength > maxS3EvidenceObject {
		return ObjectInfo{}, ErrIntegrity
	}
	return ObjectInfo{Version: version, SHA256: checksum, Size: res.ContentLength}, nil
}

func (s *S3Store) Range(ctx context.Context, ref Ref, offset, length int64) (io.ReadCloser, error) {
	if !s.validRef(ref, true) {
		return nil, ErrInvalid
	}
	if offset < 0 || length < 1 || length > ChunkSize+28 || offset > maxS3EvidenceObject-length {
		return nil, ErrRange
	}
	headers := s3ReadHeaders()
	headers.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-"+strconv.FormatInt(offset+length-1, 10))
	res, cancel, e := s.do(ctx, S3Scope{Ref: ref, Operation: S3Range, Offset: offset, Length: length}, http.MethodGet, nil, headers)
	if e != nil {
		return nil, e
	}
	defer cancel()
	defer res.Body.Close()
	if res.StatusCode != http.StatusPartialContent {
		return nil, ErrUnavailable
	}
	prefix := "bytes " + strconv.FormatInt(offset, 10) + "-" + strconv.FormatInt(offset+length-1, 10) + "/"
	contentRange := s3Header(res.Header, "Content-Range")
	if !strings.HasPrefix(contentRange, prefix) || s3Header(res.Header, "X-Amz-Version-Id") != ref.ImmutableVersion || res.ContentLength != length {
		return nil, ErrIntegrity
	}
	total, e := strconv.ParseInt(strings.TrimPrefix(contentRange, prefix), 10, 64)
	if e != nil || total < offset+length || total > maxS3EvidenceObject || contentRange != prefix+strconv.FormatInt(total, 10) {
		return nil, ErrIntegrity
	}
	data, e := io.ReadAll(io.LimitReader(res.Body, length+1))
	if e != nil || int64(len(data)) != length || res.Request.Context().Err() != nil {
		return nil, ErrUnavailable
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *S3Store) Put(ctx context.Context, ref Ref, src io.Reader, info ObjectInfo, deadline time.Time) error {
	if !s.validRef(ref, false) || ref.ImmutableVersion != "" || src == nil || info.Version != "" || !digestPattern.MatchString(info.SHA256) || info.Size < 1 || info.Size > maxS3EvidenceObject || !time.Now().Before(deadline) {
		return ErrInvalid
	}
	checksum, _ := hex.DecodeString(info.SHA256)
	headers := http.Header{"X-Amz-Content-Sha256": {info.SHA256}, "X-Amz-Checksum-Sha256": {base64.StdEncoding.EncodeToString(checksum)}, "If-None-Match": {"*"}, "Content-Type": {"application/octet-stream"}}
	res, cancel, e := s.do(ctx, S3Scope{Ref: ref, Operation: S3Put, Object: info, Deadline: deadline}, http.MethodPut, src, headers)
	if e != nil {
		return e
	}
	defer cancel()
	defer res.Body.Close()
	if res.StatusCode == http.StatusPreconditionFailed || res.StatusCode == http.StatusConflict {
		return ErrConflict
	}
	if res.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	got, valid := s3Checksum(res.Header)
	if !s3Version(s3Header(res.Header, "X-Amz-Version-Id")) || !valid || got != info.SHA256 {
		return ErrIntegrity
	}
	return nil
}

func (s *S3Store) Delete(ctx context.Context, ref Ref, info ObjectInfo) error {
	if !s.validRef(ref, true) || info.Version != ref.ImmutableVersion || !digestPattern.MatchString(info.SHA256) || info.Size < 1 || info.Size > maxS3EvidenceObject {
		return ErrInvalid
	}
	current, e := s.Stat(ctx, ref)
	if e != nil {
		return e
	}
	if current != info {
		return ErrIntegrity
	}
	res, cancel, e := s.do(ctx, S3Scope{Ref: ref, Operation: S3Delete, Object: info}, http.MethodDelete, nil, http.Header{"X-Amz-Content-Sha256": {hash(nil)}})
	if e != nil {
		return e
	}
	defer cancel()
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}
	if s3Header(res.Header, "X-Amz-Version-Id") != ref.ImmutableVersion {
		return ErrIntegrity
	}
	return nil // Acknowledgement only; GC still requires Absent.
}

func (s *S3Store) Absent(ctx context.Context, ref Ref) (Absence, error) {
	if !s.validRef(ref, false) || s.absence == nil || ctx.Err() != nil {
		return Absence{}, ErrUnavailable
	}
	challenge := make([]byte, 32)
	if _, e := rand.Read(challenge); e != nil {
		return Absence{}, ErrUnavailable
	}
	request := S3AbsenceRequest{Ref: ref, Challenge: hex.EncodeToString(challenge)}
	started := time.Now().UTC().Truncate(time.Second)
	proof, e := s.absence.VerifyAbsent(ctx, request)
	now := time.Now()
	if e != nil || ctx.Err() != nil || proof.Request != request || proof.ObservedAt.Before(started) || proof.ObservedAt.After(now) || !now.Before(proof.ExpiresAt) || proof.ExpiresAt.After(proof.ObservedAt.Add(30*time.Second)) {
		return Absence{}, ErrUnavailable
	}
	return Absence{Authoritative: true, Version: ref.ImmutableVersion}, nil
}
