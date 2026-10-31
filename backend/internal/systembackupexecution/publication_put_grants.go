package systembackupexecution

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const publicationPutGrantVersion = "system-backup-presigned-put-set.v1"
const publicationPutGrantMaxBytes = 32 << 20

// These are finite bearer capabilities for exact PUTs, never a principal's
// access/secret key pair. Keep their bytes out of SQL, public evidence and logs.
// Current publisher authorization must wrap construction before Job dispatch.
type publicationPutGrantSet struct {
	Version, ScopeSHA256 string
	Grants               []publicationPutGrant
}
type publicationPutGrant struct {
	Key, URL, SHA256 string
	Bytes            int64
	Headers          map[string]string
}

func (publicationPutGrantSet) String() string   { return "publication PUT grant set" }
func (publicationPutGrantSet) GoString() string { return "publication PUT grant set" }
func (publicationPutGrant) String() string      { return "publication PUT grant" }
func (publicationPutGrant) GoString() string    { return "publication PUT grant" }

func publicationPutScope(p PublicationUploadRequest) string {
	p.CredentialHash = ""
	raw, _ := json.Marshal(p)
	return hash(raw)
}

// No HTTP is sent here. Signing uses the same fixed-header native S3 request
// builder as the original upload primitive; only the restricted resulting
// requests may enter a Job. The issuing key pair stays in the controller.
func makePublicationPutGrantSet(ctx context.Context, p PublicationUploadRequest, issuer nativePublicationCredential) ([]byte, error) {
	manifest, candidate, err := p.validate()
	if err != nil || p.Version != publicationPresignedUploadVersion || !formalCandidateDigest(p.CandidateOwnerHMAC) {
		return nil, errPublicationUnavailable
	}
	if time.Now().Before(issuer.NotBefore) || !time.Now().Before(issuer.Until) || len(issuer.AccessKey) < 3 || len(issuer.SecretKey) < 16 {
		return nil, errPublicationUnavailable
	}
	set := publicationPutGrantSet{Version: publicationPutGrantVersion, ScopeSHA256: publicationPutScope(p), Grants: []publicationPutGrant{}}
	prefix := p.ArtifactRoot + p.Backup + "/" + strconv.FormatUint(p.Attempt, 10) + "/"
	inputs := append([]PublicationUploadInput(nil), p.Objects...)
	inputs = append(inputs, PublicationUploadInput{Path: candidate, SHA256: hash(manifest), Bytes: int64(len(manifest))})
	for i, object := range inputs {
		key := prefix + object.Path
		if i == len(inputs)-1 {
			key = candidate
		}
		r, e := newPublicationUploadSignedPut(ctx, p, issuer, key, object.SHA256, object.Bytes, nil)
		if e != nil {
			return nil, e
		}
		headers := map[string]string{}
		for name, values := range r.Header {
			if len(values) != 1 {
				return nil, errPublicationUnavailable
			}
			headers[strings.ToLower(name)] = values[0]
		}
		set.Grants = append(set.Grants, publicationPutGrant{Key: key, URL: r.URL.String(), SHA256: object.SHA256, Bytes: object.Bytes, Headers: headers})
	}
	raw, err := json.Marshal(set)
	if err != nil || len(raw) > publicationPutGrantMaxBytes {
		return nil, errPublicationUnavailable
	}
	// Validate the exact exported bytes independently of the generator before
	// an original current-authority caller can freeze the request/file hash.
	if _, _, err = parsePublicationPutGrantSet(p, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func parsePublicationPutGrantSet(p PublicationUploadRequest, raw []byte) (map[string]publicationPutGrant, time.Time, error) {
	bad := func() (map[string]publicationPutGrant, time.Time, error) {
		return nil, time.Time{}, errPublicationUnavailable
	}
	if p.Version != publicationPresignedUploadVersion || len(raw) < 2 || len(raw) > publicationPutGrantMaxBytes {
		return bad()
	}
	manifest, candidate, err := p.validate()
	if err != nil {
		return bad()
	}
	var set publicationPutGrantSet
	if decodeProviderDeploymentJSON(raw, &set) != nil || set.Version != publicationPutGrantVersion || set.ScopeSHA256 != publicationPutScope(p) || len(set.Grants) != len(p.Objects)+1 {
		return bad()
	}
	expected := map[string]PublicationUploadInput{}
	prefix := p.ArtifactRoot + p.Backup + "/" + strconv.FormatUint(p.Attempt, 10) + "/"
	for _, entry := range p.Objects {
		expected[prefix+entry.Path] = entry
	}
	expected[candidate] = PublicationUploadInput{SHA256: hash(manifest), Bytes: int64(len(manifest))}
	grants := map[string]publicationPutGrant{}
	until := p.Deadline
	base, e := url.Parse(p.Endpoint)
	if e != nil {
		return bad()
	}
	for _, grant := range set.Grants {
		want, ok := expected[grant.Key]
		if !ok || grants[grant.Key].URL != "" || grant.SHA256 != want.SHA256 || grant.Bytes != want.Bytes {
			return bad()
		}
		u, e := url.Parse(grant.URL)
		if e != nil || u.Scheme != "https" || u.Host != base.Host || u.User != nil || u.Fragment != "" || u.Path != "/"+p.Bucket+"/"+grant.Key || u.Opaque != "" {
			return bad()
		}
		q := u.Query()
		allowed := map[string]bool{"X-Amz-Algorithm": true, "X-Amz-Credential": true, "X-Amz-Date": true, "X-Amz-Expires": true, "X-Amz-SignedHeaders": true, "X-Amz-Signature": true, "X-Amz-Security-Token": true}
		for name, values := range q {
			if !allowed[name] || len(values) != 1 || values[0] == "" {
				return bad()
			}
		}
		if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || !formalCandidateDigest(q.Get("X-Amz-Signature")) {
			return bad()
		}
		credential := strings.Split(q.Get("X-Amz-Credential"), "/")
		if len(credential) != 5 || credential[0] == "" || credential[2] != p.Region || credential[3] != "s3" || credential[4] != "aws4_request" {
			return bad()
		}
		issued, e := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
		if e != nil || issued.Format("20060102") != credential[1] || issued.After(time.Now().Add(time.Second)) {
			return bad()
		}
		seconds, e := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
		if e != nil || seconds < 1 || seconds > 86400 {
			return bad()
		}
		expires := issued.Add(time.Duration(seconds) * time.Second)
		if !time.Now().Before(expires) || expires.After(p.Deadline) {
			return bad()
		}
		if expires.Before(until) {
			until = expires
		}
		contentType := "application/octet-stream"
		if strings.HasSuffix(grant.Key, ".json") {
			contentType = "application/json"
		}
		digest, _ := hex.DecodeString(want.SHA256)
		headers := map[string]string{"content-length": strconv.FormatInt(want.Bytes, 10), "content-type": contentType, "if-none-match": "*", "x-amz-content-sha256": want.SHA256, "x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(digest)}
		if grant.Key == candidate {
			if !formalCandidateDigest(p.CandidateOwnerHMAC) {
				return bad()
			}
			headers["x-amz-meta-system-backup-owner"] = p.CandidateOwnerHMAC
		}
		if len(headers) != len(grant.Headers) {
			return bad()
		}
		signed := []string{"host"}
		for name, value := range headers {
			if grant.Headers[name] != value {
				return bad()
			}
			signed = append(signed, name)
		}
		sort.Strings(signed)
		if q.Get("X-Amz-SignedHeaders") != strings.Join(signed, ";") {
			return bad()
		}
		grants[grant.Key] = grant
	}
	if len(grants) != len(expected) {
		return bad()
	}
	return grants, until, nil
}

func usePublicationPutGrant(ctx context.Context, client *http.Client, grant publicationPutGrant, body io.Reader) (PublicationUploadObservation, error) {
	var zero PublicationUploadObservation
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, grant.URL, body)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	request.ContentLength = grant.Bytes
	for name, value := range grant.Headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return zero, ErrJobUncertain
	}
	defer response.Body.Close()
	count, err := io.Copy(io.Discard, io.LimitReader(response.Body, 8193))
	digest, _ := hex.DecodeString(grant.SHA256)
	version := response.Header.Get("X-Amz-Version-Id")
	if err != nil || count > 8192 || response.StatusCode != http.StatusOK || version == "" || version == "null" || version == "latest" || len(version) > 256 || response.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest) {
		return zero, ErrJobUncertain
	}
	return PublicationUploadObservation{Key: grant.Key, Version: version, SHA256: grant.SHA256, Bytes: grant.Bytes}, nil
}
