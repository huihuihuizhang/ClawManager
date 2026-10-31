package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	reg "clawreef/internal/systembackupkekregistry"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var ErrS3CoverageCensus = errors.New("original external backup inventory incomplete or unavailable")

// These are ORIGINAL deployment-owned read/discovery scope pins, never HTTP
// request inputs. ContentSHA256 names JSON(Scope). They authorize no key use,
// destruction, release or complete adoption. Physical IAM must still be narrow.
type S3CoverageScope struct {
	Endpoint, Region, Bucket, Prefix, CASHA256, CredentialSHA256 string
}
type S3CoverageCensusConfig struct {
	Source          reg.SourceRecord
	Scope           S3CoverageScope
	CAPEM           []byte
	CredentialsFile string
}
type S3CoverageCensus struct{ cfg S3CoverageCensusConfig }

type S3CoverageMember struct {
	Kind, Key, VersionID, UploadID, ETag string
	Size                                 int64
	ModifiedAt                           time.Time
	Latest                               bool
	RetentionMode, LegalHold             string
	RetainUntil                          time.Time
}
type S3CoveragePage struct {
	Kind, KeyMarker, TokenMarker, NextKeyMarker, NextTokenMarker, PayloadSHA256 string
	Truncated                                                                   bool
	Entries                                                                     uint64
}
type S3CoverageCensusFacts struct {
	Source        reg.SourceRecord
	Scope         S3CoverageScope
	ObservedAt    time.Time
	Members       []S3CoverageMember
	Pages         []S3CoveragePage
	MembersSHA256 string
}

// This live native census is intentionally UNADMITTED: complete live LIST EOF
// does not create an immutable provider snapshot, authenticate envelopes, prove
// old writer participation or replace original SQL/adoption maintenance locks.
type UnadmittedS3CoverageCensus struct{ facts S3CoverageCensusFacts }

func (p *UnadmittedS3CoverageCensus) Facts() S3CoverageCensusFacts {
	if p == nil {
		return S3CoverageCensusFacts{}
	}
	f := p.facts
	f.Members = append([]S3CoverageMember(nil), f.Members...)
	f.Pages = append([]S3CoveragePage(nil), f.Pages...)
	return f
}

func NewS3CoverageCensus(cfg S3CoverageCensusConfig) (*S3CoverageCensus, error) {
	u, err := url.Parse(cfg.Scope.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || cfg.Scope.Region == "" || cfg.Scope.Bucket == "" || cfg.Scope.Prefix == "" || cfg.Scope.Prefix == "." || cfg.Scope.Prefix == ".." || strings.HasPrefix(cfg.Scope.Prefix, "../") || path.Clean(cfg.Scope.Prefix) != cfg.Scope.Prefix || strings.HasPrefix(cfg.Scope.Prefix, "/") || strings.ContainsAny(cfg.Scope.Prefix, "\\\x00\r\n") || !filepath.IsAbs(cfg.CredentialsFile) || !authorityHash.MatchString(cfg.Scope.CASHA256) || !authorityHash.MatchString(cfg.Scope.CredentialSHA256) || !authoritySource(cfg.Source) || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 {
		return nil, ErrS3CoverageCensus
	}
	h := sha256.Sum256(cfg.CAPEM)
	raw, _ := json.Marshal(cfg.Scope)
	scopeHash := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != cfg.Scope.CASHA256 || hex.EncodeToString(scopeHash[:]) != cfg.Source.ContentSHA256 {
		return nil, ErrS3CoverageCensus
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	return &S3CoverageCensus{cfg: cfg}, nil
}

type s3CensusCredential struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token"`
}

func (s3CensusCredential) String() string               { return "OriginalS3InventoryCredential" }
func (s3CensusCredential) GoString() string             { return "OriginalS3InventoryCredential" }
func (s3CensusCredential) MarshalJSON() ([]byte, error) { return nil, ErrS3CoverageCensus }
func (s *S3CoverageCensus) credential() (s3CensusCredential, error) {
	f, err := os.Open(s.cfg.CredentialsFile)
	if err != nil {
		return s3CensusCredential{}, ErrS3CoverageCensus
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16384 || (runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return s3CensusCredential{}, ErrS3CoverageCensus
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	defer clear(raw)
	h := sha256.Sum256(raw)
	var c s3CensusCredential
	if err != nil || len(raw) == 0 || len(raw) > 16384 || hex.EncodeToString(h[:]) != s.cfg.Scope.CredentialSHA256 || strictPermitIssuerJSON(raw, &c) != nil || c.AccessKey == "" || len(c.AccessKey) > 256 || c.SecretKey == "" || len(c.SecretKey) > 4096 || len(c.SessionToken) > 8192 {
		return s3CensusCredential{}, ErrS3CoverageCensus
	}
	return c, nil
}

func (s *S3CoverageCensus) Observe(ctx context.Context) (*UnadmittedS3CoverageCensus, error) {
	bad := func() (*UnadmittedS3CoverageCensus, error) { return nil, ErrS3CoverageCensus }
	if s == nil || ctx == nil || ctx.Err() != nil {
		return bad()
	}
	if _, ok := ctx.Deadline(); !ok {
		return bad()
	}
	c, err := s.credential()
	if err != nil {
		return bad()
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(s.cfg.CAPEM) {
		return bad()
	}
	base := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	defer base.CloseIdleConnections()
	endpoint, _ := url.Parse(s.cfg.Scope.Endpoint)
	transport := &s3CensusTransport{base: base, host: endpoint.Host, bucket: s.cfg.Scope.Bucket, prefix: s.cfg.Scope.Prefix + "/", next: map[string][2]string{}, done: map[string]bool{}}
	client, err := minio.New(endpoint.Host, &minio.Options{Secure: true, Region: s.cfg.Scope.Region, BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4(c.AccessKey, c.SecretKey, c.SessionToken), Transport: transport, MaxRetries: 1})
	c = s3CensusCredential{}
	if err != nil {
		return bad()
	}
	versioning, err := client.GetBucketVersioning(ctx, s.cfg.Scope.Bucket)
	if err != nil || versioning.Status != "Enabled" {
		return bad()
	}
	lock, _, _, _, err := client.GetObjectLockConfig(ctx, s.cfg.Scope.Bucket)
	if err != nil {
		transport.mu.Lock()
		absent := transport.objectLockAbsent
		transport.mu.Unlock()
		if !absent {
			return bad()
		}
		lock = ""
	} else if lock != "Enabled" {
		return bad()
	}
	facts := S3CoverageCensusFacts{Source: s.cfg.Source, Scope: s.cfg.Scope, ObservedAt: time.Now().UTC(), Members: []S3CoverageMember{}}
	seen := map[string]bool{}
	var previous string
	var metadataBytes uint64
	add := func(member S3CoverageMember) bool {
		if len(facts.Members) >= 100000 || !strings.HasPrefix(member.Key, transport.prefix) || len(member.Key) > 1024 || !utf8.ValidString(member.Key) || strings.ContainsAny(member.Key, "\x00\r\n") || member.ModifiedAt.IsZero() || member.Size < 0 {
			return false
		}
		identityKind := "version"
		if member.Kind == "multipart_unknown" {
			identityKind = "multipart"
		}
		identityRaw, _ := json.Marshal([]string{identityKind, member.Key, member.VersionID, member.UploadID})
		identity := string(identityRaw)
		if seen[identity] {
			return false
		}
		seen[identity] = true
		encoded, _ := json.Marshal(member)
		metadataBytes += uint64(len(encoded))
		if metadataBytes > 64<<20 {
			return false
		}
		facts.Members = append(facts.Members, member)
		return true
	}
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for object := range client.ListObjects(listCtx, s.cfg.Scope.Bucket, minio.ListObjectsOptions{Prefix: transport.prefix, Recursive: true, WithVersions: true, MaxKeys: 1000}) {
		if object.Err != nil || ctx.Err() != nil || object.Key < previous || object.VersionID == "" || len(object.VersionID) > 1024 || strings.ContainsAny(object.VersionID, "\x00\r\n") {
			return bad()
		}
		if object.Key != previous {
			if !object.IsLatest {
				return bad()
			}
		} else if object.IsLatest {
			return bad()
		}
		previous = object.Key
		member := S3CoverageMember{Kind: "version", Key: object.Key, VersionID: object.VersionID, ETag: object.ETag, Size: object.Size, ModifiedAt: object.LastModified.UTC(), Latest: object.IsLatest}
		if object.IsDeleteMarker {
			member.Kind = "delete_marker"
		} else if object.VersionID == "null" {
			member.Kind = "legacy_unversioned"
		}
		if lock == "Enabled" && !object.IsDeleteMarker {
			mode, until, err := client.GetObjectRetention(ctx, s.cfg.Scope.Bucket, object.Key, object.VersionID)
			if err != nil {
				return bad()
			}
			if mode != nil {
				member.RetentionMode = string(*mode)
			}
			if member.RetentionMode != "" && member.RetentionMode != "GOVERNANCE" && member.RetentionMode != "COMPLIANCE" {
				return bad()
			}
			if until != nil {
				member.RetainUntil = until.UTC()
			}
			if (member.RetentionMode != "") != (!member.RetainUntil.IsZero()) {
				return bad()
			}
			hold, err := client.GetObjectLegalHold(ctx, s.cfg.Scope.Bucket, object.Key, minio.GetObjectLegalHoldOptions{VersionID: object.VersionID})
			if err != nil || hold == nil || (*hold != minio.LegalHoldEnabled && *hold != minio.LegalHoldDisabled) {
				return bad()
			}
			member.LegalHold = string(*hold)
		}
		if !add(member) {
			return bad()
		}
	}
	if ctx.Err() != nil {
		return bad()
	}
	versionCount := uint64(len(facts.Members))
	core := minio.Core{Client: client}
	keyMarker, uploadMarker := "", ""
	for pageNo := 0; pageNo < 100001; pageNo++ {
		page, err := core.ListMultipartUploads(ctx, s.cfg.Scope.Bucket, transport.prefix, keyMarker, uploadMarker, "", 1000)
		if err != nil || ctx.Err() != nil || page.Prefix != transport.prefix || page.KeyMarker != keyMarker || page.UploadIDMarker != uploadMarker || len(page.CommonPrefixes) != 0 {
			return bad()
		}
		for _, upload := range page.Uploads {
			if upload.UploadID == "" || len(upload.UploadID) > 1024 || strings.ContainsAny(upload.UploadID, "\x00\r\n") || !add(S3CoverageMember{Kind: "multipart_unknown", Key: upload.Key, UploadID: upload.UploadID, Size: upload.Size, ModifiedAt: upload.Initiated.UTC()}) {
				return bad()
			}
		}
		if !page.IsTruncated {
			break
		}
		if pageNo == 100000 || len(page.Uploads) == 0 || page.NextKeyMarker == "" || (page.NextKeyMarker == keyMarker && page.NextUploadIDMarker == uploadMarker) {
			return bad()
		}
		keyMarker, uploadMarker = page.NextKeyMarker, page.NextUploadIDMarker
	}
	transport.mu.Lock()
	complete := transport.done["versions"] && transport.done["uploads"]
	facts.Pages = append([]S3CoveragePage(nil), transport.pages...)
	transport.mu.Unlock()
	if !complete {
		return bad()
	}
	if _, err = s.credential(); err != nil {
		return bad()
	}
	var listedVersions, listedUploads uint64
	for _, page := range facts.Pages {
		if page.Kind == "versions" {
			listedVersions += page.Entries
		} else {
			listedUploads += page.Entries
		}
	}
	if listedVersions != versionCount || listedUploads != uint64(len(facts.Members))-versionCount {
		return bad()
	}
	raw, _ := json.Marshal(facts.Members)
	h := sha256.Sum256(raw)
	facts.MembersSHA256 = hex.EncodeToString(h[:])
	return &UnadmittedS3CoverageCensus{facts: facts}, nil
}

type s3CensusTransport struct {
	base                 http.RoundTripper
	host, bucket, prefix string
	mu                   sync.Mutex
	next                 map[string][2]string
	done                 map[string]bool
	pages                []S3CoveragePage
	proofBytes           uint64
	seen                 map[string]map[[2]string]bool
	objectLockAbsent     bool
}

func (t *s3CensusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	q := req.URL.Query()
	kind := ""
	bucketPath := req.URL.Path == "/"+t.bucket || req.URL.Path == "/"+t.bucket+"/"
	if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != t.host || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, ErrS3CoverageCensus
	}
	if q.Has("versions") {
		kind = "versions"
	}
	if q.Has("uploads") {
		if kind != "" {
			return nil, ErrS3CoverageCensus
		}
		kind = "uploads"
	}
	if kind != "" {
		if !bucketPath || q.Get("prefix") != t.prefix || q.Get("delimiter") != "" {
			return nil, ErrS3CoverageCensus
		}
	} else if bucketPath {
		if !q.Has("versioning") && !q.Has("object-lock") {
			return nil, ErrS3CoverageCensus
		}
	} else if !strings.HasPrefix(req.URL.Path, "/"+t.bucket+"/"+t.prefix) || (!q.Has("retention") && !q.Has("legal-hold")) || q.Get("versionId") == "" {
		return nil, ErrS3CoverageCensus
	}
	response, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, ErrS3CoverageCensus
	}
	if response.Header.Get("Content-Encoding") != "" {
		response.Body.Close()
		return nil, ErrS3CoverageCensus
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	response.Body.Close()
	if err != nil || len(raw) > 4<<20 {
		return nil, ErrS3CoverageCensus
	}
	if kind == "" {
		op := ""
		for _, candidate := range []string{"versioning", "object-lock", "retention", "legal-hold"} {
			if q.Has(candidate) {
				if op != "" {
					return nil, ErrS3CoverageCensus
				}
				op = candidate
			}
		}
		absent, err := validateNativeS3Protection(raw, op, response.StatusCode)
		if err != nil {
			return nil, err
		}
		if absent {
			t.mu.Lock()
			t.objectLockAbsent = true
			t.mu.Unlock()
		}
	}
	if kind != "" && response.StatusCode == http.StatusOK {
		page, err := validateNativeS3CensusPage(raw, kind, t.bucket, t.prefix, q)
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		want := t.next[kind]
		if t.seen == nil {
			t.seen = map[string]map[[2]string]bool{}
		}
		if t.seen[kind] == nil {
			t.seen[kind] = map[[2]string]bool{}
		}
		cursor := [2]string{page.KeyMarker, page.TokenMarker}
		next := [2]string{page.NextKeyMarker, page.NextTokenMarker}
		encoded, _ := json.Marshal(page)
		t.proofBytes += uint64(len(encoded))
		if t.done[kind] || want != cursor || t.seen[kind][cursor] || page.Truncated && t.seen[kind][next] || len(t.pages) >= 10000 || t.proofBytes > 32<<20 {
			return nil, ErrS3CoverageCensus
		}
		t.seen[kind][cursor] = true
		t.pages = append(t.pages, page)
		t.next[kind] = [2]string{page.NextKeyMarker, page.NextTokenMarker}
		if !page.Truncated {
			t.done[kind] = true
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}

func validateNativeS3CensusPage(raw []byte, kind, bucket, prefix string, q url.Values) (S3CoveragePage, error) {
	bad := func() (S3CoveragePage, error) { return S3CoveragePage{}, ErrS3CoverageCensus }
	d := xml.NewDecoder(bytes.NewReader(raw))
	fields := map[string]string{}
	seen := map[string]bool{}
	depth := 0
	var root string
	var entries uint64
	allowed := map[string]bool{}
	for _, name := range strings.Fields("Name Bucket Prefix KeyMarker VersionIdMarker NextKeyMarker NextVersionIdMarker MaxKeys IsTruncated EncodingType Delimiter UploadIdMarker NextUploadIdMarker MaxUploads") {
		allowed[name] = true
	}
	var entryFields map[string]bool
	var entryValues map[string]string
	entryScalarName := ""
	var entryScalar strings.Builder
	entryName := ""
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bad()
		}
		switch token := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				if root != "" {
					return bad()
				}
				root = token.Name.Local
			}
			if depth == 2 {
				name := token.Name.Local
				if name == "Version" || name == "DeleteMarker" || name == "Upload" {
					if (kind == "uploads") != (name == "Upload") {
						return bad()
					}
					entryName = name
					entryFields = map[string]bool{}
					entryValues = map[string]string{}
					entries++
					if entries > 1000 {
						return bad()
					}
				} else if name == "CommonPrefixes" {
					return bad()
				} else {
					if seen[name] || !allowed[name] {
						return bad()
					}
					seen[name] = true
					var text string
					if d.DecodeElement(&text, &token) != nil {
						return bad()
					}
					fields[name] = text
					depth--
				}
			} else if depth == 3 && entryFields != nil {
				if entryFields[token.Name.Local] {
					return bad()
				}
				entryFields[token.Name.Local] = true
				switch token.Name.Local {
				case "Key", "VersionId", "IsLatest", "LastModified", "Size", "ETag", "UploadId", "Initiated":
					entryScalarName = token.Name.Local
					entryScalar.Reset()
				}
			} else if depth > 3 && entryScalarName != "" {
				return bad()
			}
		case xml.EndElement:
			if depth == 3 && entryScalarName != "" {
				entryValues[entryScalarName] = strings.TrimSpace(entryScalar.String())
				entryScalarName = ""
			}
			if depth == 2 && entryFields != nil {
				for _, name := range []string{"Key"} {
					if !entryFields[name] {
						return bad()
					}
				}
				if entryName == "Upload" {
					if !entryFields["UploadId"] || !entryFields["Initiated"] {
						return bad()
					}
				} else if !entryFields["VersionId"] || !entryFields["IsLatest"] || !entryFields["LastModified"] {
					return bad()
				}
				if entryName == "Version" && (!entryFields["Size"] || !entryFields["ETag"]) {
					return bad()
				}
				if entryValues["Key"] == "" {
					return bad()
				}
				dateField := "LastModified"
				if entryName == "Upload" {
					dateField = "Initiated"
					if entryValues["UploadId"] == "" {
						return bad()
					}
				} else if entryValues["VersionId"] == "" || (entryValues["IsLatest"] != "true" && entryValues["IsLatest"] != "false") {
					return bad()
				}
				date, err := time.Parse(time.RFC3339Nano, entryValues[dateField])
				if err != nil || date.IsZero() {
					return bad()
				}
				if entryName == "Version" {
					if _, err := strconv.ParseUint(entryValues["Size"], 10, 63); err != nil || entryValues["ETag"] == "" {
						return bad()
					}
				}
				entryFields = nil
				entryName = ""
			}
			depth--
			if depth < 0 {
				return bad()
			}
		case xml.CharData:
			if depth == 3 && entryScalarName != "" {
				if entryScalar.Len()+len(token) > 8192 {
					return bad()
				}
				entryScalar.Write(token)
			}
			if depth == 0 && strings.TrimSpace(string(token)) != "" {
				return bad()
			}
		}
	}
	if depth != 0 || (kind == "versions" && root != "ListVersionsResult") || (kind == "uploads" && root != "ListMultipartUploadsResult") || !seen["IsTruncated"] || (fields["IsTruncated"] != "true" && fields["IsTruncated"] != "false") {
		return bad()
	}
	if fields["EncodingType"] == "url" {
		for _, name := range []string{"Prefix", "KeyMarker", "NextKeyMarker"} {
			value, err := url.PathUnescape(fields[name])
			if err != nil {
				return bad()
			}
			fields[name] = value
		}
	} else if fields["EncodingType"] != "" {
		return bad()
	}
	name := fields["Name"]
	tokenName, nextTokenName := "VersionIdMarker", "NextVersionIdMarker"
	if kind == "uploads" {
		name = fields["Bucket"]
		tokenName, nextTokenName = "UploadIdMarker", "NextUploadIdMarker"
	}
	requestToken := q.Get("version-id-marker")
	if kind == "uploads" {
		requestToken = q.Get("upload-id-marker")
	}
	page := S3CoveragePage{Kind: kind, KeyMarker: fields["KeyMarker"], TokenMarker: fields[tokenName], NextKeyMarker: fields["NextKeyMarker"], NextTokenMarker: fields[nextTokenName], Truncated: fields["IsTruncated"] == "true", Entries: entries}
	for _, value := range []string{page.KeyMarker, page.NextKeyMarker, page.TokenMarker, page.NextTokenMarker} {
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return bad()
		}
	}
	if name != bucket || fields["Prefix"] != prefix || fields["Delimiter"] != "" || page.KeyMarker != q.Get("key-marker") || page.TokenMarker != requestToken {
		return bad()
	}
	if page.Truncated && (entries == 0 || page.NextKeyMarker == "" || !strings.HasPrefix(page.NextKeyMarker, prefix) || (page.NextKeyMarker == page.KeyMarker && page.NextTokenMarker == page.TokenMarker)) {
		return bad()
	}
	if !page.Truncated && (page.NextKeyMarker != "" || page.NextTokenMarker != "") {
		return bad()
	}
	h := sha256.Sum256(raw)
	page.PayloadSHA256 = hex.EncodeToString(h[:])
	return page, nil
}

// Native success metadata must have one unambiguous interpretation BEFORE
// the SDK decoder. In particular missing/duplicate Enabled can never disable
// per-version protection checks. Only an exact native 404 proves no bucket
// Object Lock configuration; AccessDenied/200-empty is not such a proof.
func validateNativeS3Protection(raw []byte, operation string, status int) (bool, error) {
	bad := func() (bool, error) { return false, ErrS3CoverageCensus }
	d := xml.NewDecoder(bytes.NewReader(raw))
	seen := map[string]bool{}
	values := map[string]string{}
	var stack []string
	var text []*strings.Builder
	root := ""
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return bad()
		}
		switch token := token.(type) {
		case xml.StartElement:
			if len(stack) >= 16 {
				return bad()
			}
			if len(stack) == 0 {
				if root != "" {
					return bad()
				}
				root = token.Name.Local
			}
			stack = append(stack, token.Name.Local)
			key := strings.Join(stack, "/")
			if seen[key] || len(seen) >= 1000 {
				return bad()
			}
			seen[key] = true
			text = append(text, new(strings.Builder))
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(token)) != "" {
					return bad()
				}
			} else {
				if text[len(text)-1].Len()+len(token) > 16384 {
					return bad()
				}
				text[len(text)-1].Write(token)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return bad()
			}
			key := strings.Join(stack, "/")
			values[key] = strings.TrimSpace(text[len(text)-1].String())
			stack = stack[:len(stack)-1]
			text = text[:len(text)-1]
		}
	}
	if len(stack) != 0 || root == "" {
		return bad()
	}
	for key := range seen {
		for _, leaf := range []string{"Error/Code", "VersioningConfiguration/Status", "ObjectLockConfiguration/ObjectLockEnabled", "Retention/Mode", "Retention/RetainUntilDate", "LegalHold/Status"} {
			if strings.HasPrefix(key, leaf+"/") {
				return bad()
			}
		}
	}
	if status != http.StatusOK {
		if operation == "object-lock" && status == http.StatusNotFound && root == "Error" && values["Error/Code"] == "ObjectLockConfigurationNotFoundError" {
			return true, nil
		}
		return bad()
	}
	switch operation {
	case "versioning":
		if root != "VersioningConfiguration" || values["VersioningConfiguration/Status"] != "Enabled" {
			return bad()
		}
	case "object-lock":
		if root != "ObjectLockConfiguration" || values["ObjectLockConfiguration/ObjectLockEnabled"] != "Enabled" {
			return bad()
		}
	case "retention":
		if root != "Retention" {
			return bad()
		}
		mode, hasMode := values["Retention/Mode"]
		date, hasDate := values["Retention/RetainUntilDate"]
		if hasMode != hasDate {
			return bad()
		}
		if hasMode {
			if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
				return bad()
			}
			parsed, err := time.Parse(time.RFC3339Nano, date)
			if err != nil || parsed.IsZero() {
				return bad()
			}
		}
	case "legal-hold":
		if root != "LegalHold" || (values["LegalHold/Status"] != "ON" && values["LegalHold/Status"] != "OFF") {
			return bad()
		}
	default:
		return bad()
	}
	return false, nil
}
