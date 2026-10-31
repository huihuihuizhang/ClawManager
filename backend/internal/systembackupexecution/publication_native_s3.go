package systembackupexecution

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/minio/minio-go/v7/pkg/signer"
)

var errPublicationUnavailable = errors.New("native publication outcome unavailable")
var errPublicationConflict = errors.New("native publication immutable object conflict")

// Lookup coordinates in independently pinned deployment material. This is a
// transport mapping, not task/claim/append authorization or a readiness proof.
// The production publication pass supplies the original journal's exact scope.
type PublicationTargetMaterials struct {
	Version               string `json:"schema_version"`
	InstallationID        string `json:"installation_id"`
	Endpoint              string `json:"endpoint"`
	Region                string `json:"region"`
	Bucket                string `json:"bucket"`
	Root                  string `json:"root"`
	ReadIdentityHash      string `json:"read_identity_hash"`
	ReadRefVersion        string `json:"read_ref_version"`
	WriteIdentityHash     string `json:"write_identity_hash"`
	WriteRefVersion       string `json:"write_ref_version"`
	CAIdentityHash        string `json:"ca_identity_hash"`
	CARefVersion          string `json:"ca_ref_version"`
	CAFile                string `json:"ca_file"`
	CASHA256              string `json:"ca_sha256"`
	ReadCredentialFile    string `json:"read_credential_file"`
	ReadCredentialSHA256  string `json:"read_credential_sha256"`
	WriteCredentialFile   string `json:"write_credential_file"`
	WriteCredentialSHA256 string `json:"write_credential_sha256"`
}

const publicationTargetVersion = "system-backup-native-publication-s3.v1"

type nativePublicationCredential struct {
	AccessKey    string    `json:"access_key"`
	SecretKey    string    `json:"secret_key"`
	SessionToken string    `json:"session_token"`
	NotBefore    time.Time `json:"not_before"`
	Until        time.Time `json:"until"`
}

type nativePublicationObject struct {
	Key, Version, SHA256 string
	Size                 int64
	receipt              *publicationObjectReceipt
	payloadRead          *publicationPayloadReadReceipt
}
type nativePublicationS3 struct {
	config PublicationTargetMaterials
	client *http.Client
}

func (p PublicationTargetMaterials) validate() error {
	u, err := url.Parse(p.Endpoint)
	if p.Version != publicationTargetVersion || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(p.Endpoint, "?#\r\n") || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(p.Region) || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(p.Bucket) || strings.Contains(p.Bucket, "..") || p.InstallationID == "" || !strings.HasSuffix(p.Root, "/") || !safePublicationKey(strings.TrimSuffix(p.Root, "/")) || p.ReadIdentityHash == p.WriteIdentityHash {
		return errPublicationUnavailable
	}
	for _, digest := range []string{p.ReadIdentityHash, p.WriteIdentityHash, p.CAIdentityHash, p.CASHA256, p.ReadCredentialSHA256, p.WriteCredentialSHA256} {
		if !formalCandidateDigest(digest) {
			return errPublicationUnavailable
		}
	}
	for _, version := range []string{p.ReadRefVersion, p.WriteRefVersion, p.CARefVersion} {
		if version == "" || version == "latest" || version == "current" || len(version) > 128 {
			return errPublicationUnavailable
		}
	}
	for _, path := range []string{p.CAFile, p.ReadCredentialFile, p.WriteCredentialFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errPublicationUnavailable
		}
	}
	if p.ReadCredentialFile == p.WriteCredentialFile {
		return errPublicationUnavailable
	}
	return nil
}

func newNativePublicationS3(p PublicationTargetMaterials) (*nativePublicationS3, error) {
	if p.validate() != nil {
		return nil, errPublicationUnavailable
	}
	ca, err := pinnedDeploymentFile(p.CAFile, p.CASHA256, 65536)
	if err != nil {
		return nil, errPublicationUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errPublicationUnavailable
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	return &nativePublicationS3{config: p, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (s *nativePublicationS3) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func safePublicationKey(key string) bool {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00\r\n\t") {
		return false
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (s *nativePublicationS3) credential(write bool) (nativePublicationCredential, error) {
	if s == nil || s.config.validate() != nil {
		return nativePublicationCredential{}, errPublicationUnavailable
	}
	path, pin := s.config.ReadCredentialFile, s.config.ReadCredentialSHA256
	if write {
		path, pin = s.config.WriteCredentialFile, s.config.WriteCredentialSHA256
	}
	raw, err := pinnedDeploymentFile(path, pin, 16384)
	if err != nil {
		return nativePublicationCredential{}, errPublicationUnavailable
	}
	defer clear(raw)
	// Credential files use the same private-file rules as actual projected JWTs.
	private, err := readPrivate(path, 16384)
	if err != nil {
		return nativePublicationCredential{}, errPublicationUnavailable
	}
	defer clear(private)
	sum := sha256.Sum256(private)
	if hex.EncodeToString(sum[:]) != pin {
		return nativePublicationCredential{}, errPublicationUnavailable
	}
	var credential nativePublicationCredential
	now := time.Now()
	if decodeProviderDeploymentJSON(raw, &credential) != nil || len(credential.AccessKey) < 3 || len(credential.AccessKey) > 256 || len(credential.SecretKey) < 16 || len(credential.SecretKey) > 4096 || len(credential.SessionToken) > 16384 || strings.ContainsAny(credential.AccessKey, "\r\n") || credential.NotBefore.IsZero() || !credential.Until.After(credential.NotBefore) || now.Before(credential.NotBefore) || !now.Before(credential.Until) {
		return nativePublicationCredential{}, errPublicationUnavailable
	}
	return credential, nil
}

func (s *nativePublicationS3) request(ctx context.Context, method, key, version string, body io.Reader, size int64, checksum string, deadline time.Time, write bool, contentType string) (*http.Response, error) {
	if s == nil || s.client == nil || ctx == nil || ctx.Err() != nil || !safePublicationKey(key) || !strings.HasPrefix(key, s.config.Root) || len(version) > 256 || version == "null" || version == "latest" || write && (method != "PUT" || version != "" || size < 1 || size > 8<<30 || !formalCandidateDigest(checksum) || body == nil) || !write && method != "GET" && method != "HEAD" {
		return nil, errPublicationUnavailable
	}
	credential, err := s.credential(write)
	if err != nil {
		return nil, err
	}
	if deadline.IsZero() {
		return nil, errPublicationUnavailable
	}
	if credential.Until.Before(deadline) {
		deadline = credential.Until
	}
	if !time.Now().Before(deadline) || time.Until(deadline) > 24*time.Hour {
		return nil, errPublicationUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	// The response body owns cancellation for a successful streaming GET.
	failed := true
	defer func() {
		if failed {
			cancel()
		}
	}()
	u, _ := url.Parse(s.config.Endpoint)
	u.Path = "/" + s.config.Bucket + "/" + key
	query := u.Query()
	if version != "" {
		query.Set("versionId", version)
	}
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errPublicationUnavailable
	}
	if write {
		if contentType != "application/json" && contentType != "application/octet-stream" {
			return nil, errPublicationUnavailable
		}
		request.ContentLength = size
		request.Header.Set("Content-Length", strconvFormatPublicationSize(size))
		request.Header.Set("Content-Type", contentType)
		request.Header.Set("If-None-Match", "*")
		request.Header.Set("X-Amz-Content-Sha256", checksum)
		digest, _ := hex.DecodeString(checksum)
		request.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
		// Native S3 checks expiration on THIS exact presigned request. No general
		// overwrite credential is sent; key/body hash/length/condition are signed.
		seconds := int64(time.Until(deadline) / time.Second)
		if seconds < 1 {
			return nil, errPublicationUnavailable
		}
		request = signer.PreSignV4(*request, credential.AccessKey, credential.SecretKey, credential.SessionToken, s.config.Region, seconds)
		signed := request.URL.Query().Get("X-Amz-SignedHeaders")
		for _, header := range []string{"content-length", "content-type", "if-none-match", "x-amz-content-sha256", "x-amz-checksum-sha256"} {
			found := false
			for _, field := range strings.Split(signed, ";") {
				if field == header {
					found = true
				}
			}
			if !found {
				return nil, errPublicationUnavailable
			}
		}
	} else {
		request.Header.Set("X-Amz-Content-Sha256", hash(nil))
		request = signer.SignV4(*request, credential.AccessKey, credential.SecretKey, credential.SessionToken, s.config.Region)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, errPublicationUnavailable
	}
	response.Body = &publicationCancelBody{ReadCloser: response.Body, cancel: cancel}
	failed = false
	return response, nil
}

func strconvFormatPublicationSize(size int64) string { return strconv.FormatInt(size, 10) }

type publicationCancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *publicationCancelBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

// create is transport only. Its caller MUST have committed the same v2
// external-action request_sent/send_attempt BEFORE calling it, and must query
// with the independent read principal afterwards even when this returns nil.
func (s *nativePublicationS3) create(ctx context.Context, key string, body io.Reader, size int64, checksum string, deadline time.Time) (nativePublicationObject, error) {
	return s.createContent(ctx, key, body, size, checksum, deadline, "application/octet-stream")
}

func (s *nativePublicationS3) createJSON(ctx context.Context, key string, body io.Reader, size int64, checksum string, deadline time.Time) (nativePublicationObject, error) {
	return s.createContent(ctx, key, body, size, checksum, deadline, "application/json")
}
func (s *nativePublicationS3) createContent(ctx context.Context, key string, body io.Reader, size int64, checksum string, deadline time.Time, contentType string) (nativePublicationObject, error) {
	response, err := s.request(ctx, "PUT", key, "", body, size, checksum, deadline, true, contentType)
	if err != nil {
		return nativePublicationObject{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusConflict {
		return nativePublicationObject{}, errPublicationConflict
	}
	version := response.Header.Get("x-amz-version-id")
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated || version == "" || version == "null" || len(version) > 256 || response.Header.Get("Content-Encoding") != "" {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	return nativePublicationObject{Key: key, Version: version, SHA256: checksum, Size: size}, nil
}

func (s *nativePublicationS3) stat(ctx context.Context, key, version string, deadline time.Time) (nativePublicationObject, error) {
	response, err := s.request(ctx, "HEAD", key, version, nil, 0, "", deadline, false, "")
	if err != nil {
		return nativePublicationObject{}, err
	}
	defer response.Body.Close()
	observed := response.Header.Get("x-amz-version-id")
	if response.StatusCode != 200 || observed == "" || observed == "null" || len(observed) > 256 || version != "" && observed != version || response.ContentLength < 1 || response.ContentLength > 8<<30 || response.Header.Get("x-amz-delete-marker") == "true" || response.Header.Get("Content-Encoding") != "" {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	return nativePublicationObject{Key: key, Version: observed, Size: response.ContentLength}, nil
}

func (s *nativePublicationS3) open(ctx context.Context, object nativePublicationObject, deadline time.Time) (io.ReadCloser, error) {
	if object.Version == "" || object.Size < 1 {
		return nil, errPublicationUnavailable
	}
	response, err := s.request(ctx, "GET", object.Key, object.Version, nil, 0, "", deadline, false, "")
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 || response.Header.Get("x-amz-version-id") != object.Version || response.ContentLength != object.Size || response.Header.Get("x-amz-delete-marker") == "true" || response.Header.Get("Content-Encoding") != "" {
		response.Body.Close()
		return nil, errPublicationUnavailable
	}
	return response.Body, nil
}
