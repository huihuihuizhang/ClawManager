package systembackupexecution

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"
)

// Independent disaster-side READ material. There is deliberately no original
// controller, DB, staging root, capture claim, write credential or KMS key.
// The caller separately authenticates its installation/signing trust input.
type ArtifactReadMaterials struct {
	InstallationID, Endpoint, Region, Bucket, Root string
	ReadIdentityHash, ReadRefVersion               string
	CAIdentityHash, CARefVersion, CAFile, CASHA256 string
	ReadCredentialFile, ReadCredentialSHA256       string
}

func artifactReadMaterials(p PublicationTargetMaterials) ArtifactReadMaterials {
	return ArtifactReadMaterials{p.InstallationID, p.Endpoint, p.Region, p.Bucket, p.Root, p.ReadIdentityHash, p.ReadRefVersion, p.CAIdentityHash, p.CARefVersion, p.CAFile, p.CASHA256, p.ReadCredentialFile, p.ReadCredentialSHA256}
}
func (p ArtifactReadMaterials) validate() error {
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || p.InstallationID == "" || !strings.HasSuffix(p.Root, "/") || !safePublicationKey(strings.TrimSuffix(p.Root, "/")) || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(p.Region) || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(p.Bucket) || strings.Contains(p.Bucket, "..") {
		return errPublicationUnavailable
	}
	for _, digest := range []string{p.ReadIdentityHash, p.CAIdentityHash, p.CASHA256, p.ReadCredentialSHA256} {
		if !formalCandidateDigest(digest) {
			return errPublicationUnavailable
		}
	}
	for _, version := range []string{p.ReadRefVersion, p.CARefVersion} {
		if version == "" || version == "latest" || version == "current" || len(version) > 128 {
			return errPublicationUnavailable
		}
	}
	for _, path := range []string{p.CAFile, p.ReadCredentialFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errPublicationUnavailable
		}
	}
	return nil
}

type ArtifactReadObject struct {
	Key, Version, SHA256 string
	Size                 int64
}
type ArtifactVersionSearchBudget struct {
	MaxVersions, MaxPages int
	MaxReadBytes          int64
}
type ArtifactReadOnlyS3 struct{ store *nativePublicationS3 }

func NewArtifactReadOnlyS3(p ArtifactReadMaterials) (*ArtifactReadOnlyS3, error) {
	if p.validate() != nil {
		return nil, errPublicationUnavailable
	}
	target := PublicationTargetMaterials{Version: publicationTargetVersion, InstallationID: p.InstallationID, Endpoint: p.Endpoint, Region: p.Region, Bucket: p.Bucket, Root: p.Root, ReadIdentityHash: p.ReadIdentityHash, ReadRefVersion: p.ReadRefVersion, CAIdentityHash: p.CAIdentityHash, CARefVersion: p.CARefVersion, CAFile: p.CAFile, CASHA256: p.CASHA256, ReadCredentialFile: p.ReadCredentialFile, ReadCredentialSHA256: p.ReadCredentialSHA256}
	store, err := newPublicationS3Transport(target)
	if err != nil {
		return nil, err
	}
	store.readOnly = true
	if _, err = store.credential(false); err != nil {
		store.Close()
		return nil, err
	}
	return &ArtifactReadOnlyS3{store}, nil
}
func (r *ArtifactReadOnlyS3) Close() {
	if r != nil && r.store != nil {
		r.store.Close()
	}
}

type artifactNativeVersion struct {
	Key      string    `xml:"Key"`
	Version  string    `xml:"VersionId"`
	Size     int64     `xml:"Size"`
	Modified time.Time `xml:"LastModified"`
}
type artifactVersionPage struct {
	XMLName                                xml.Name
	Name, Prefix, KeyMarker, NextKeyMarker string
	VersionIDMarker                        string                            `xml:"VersionIdMarker"`
	NextVersionIDMarker                    string                            `xml:"NextVersionIdMarker"`
	Truncated                              bool                              `xml:"IsTruncated"`
	Versions                               []artifactNativeVersion           `xml:"Version"`
	Deletes                                []struct{ Key, VersionID string } `xml:"DeleteMarker"`
}

func (r *ArtifactReadOnlyS3) versionPage(ctx context.Context, key, keyMarker, versionMarker string, limit int, until time.Time) (artifactVersionPage, error) {
	var zero artifactVersionPage
	if r == nil || r.store == nil || ctx == nil || ctx.Err() != nil || !safePublicationKey(key) || !strings.HasPrefix(key, r.store.config.Root) || limit < 1 || limit > 1000 || len(versionMarker) > 256 || keyMarker != "" && (!safePublicationKey(keyMarker) || !strings.HasPrefix(keyMarker, key)) {
		return zero, errPublicationUnavailable
	}
	s := r.store
	credential, err := s.credential(false)
	if err != nil {
		return zero, err
	}
	if credential.Until.Before(until) {
		until = credential.Until
	}
	if until.IsZero() || !time.Now().Before(until) || time.Until(until) > 24*time.Hour {
		return zero, errPublicationUnavailable
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	u, _ := url.Parse(s.config.Endpoint)
	u.Path = "/" + s.config.Bucket + "/"
	q := url.Values{"versions": {""}, "prefix": {key}, "max-keys": {strconv.Itoa(limit)}}
	if keyMarker != "" {
		q.Set("key-marker", keyMarker)
	}
	if versionMarker != "" {
		q.Set("version-id-marker", versionMarker)
	}
	u.RawQuery = q.Encode()
	request, err := http.NewRequestWithContext(bounded, http.MethodGet, u.String(), nil)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	request.Header.Set("X-Amz-Content-Sha256", hash(nil))
	request = signer.SignV4(*request, credential.AccessKey, credential.SecretKey, credential.SessionToken, s.config.Region)
	response, err := s.client.Do(request)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return zero, errPublicationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return zero, errPublicationUnavailable
	}
	var page artifactVersionPage
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	if decoder.Decode(&page) != nil || decoder.Decode(new(any)) != io.EOF || page.XMLName.Local != "ListVersionsResult" || page.Name != s.config.Bucket || page.Prefix != key || page.KeyMarker != keyMarker || page.VersionIDMarker != versionMarker || len(page.Versions)+len(page.Deletes) > limit {
		return zero, errPublicationUnavailable
	}
	if _, err = s.credential(false); err != nil {
		return zero, err
	}
	return page, nil
}

// ResolveIndexedObject uses the AUTHENTICATED index's size/hash to find native
// immutable versions. It never HEADs/GETs latest, consults original SQL or treats
// an ETag/HEAD hash as content proof. Missing ListBucketVersions permission,
// missing retained versions, read failures and exhausted budgets fail closed.
// This preserves the existing v12 index wire schema (no ad-hoc version field).
func (r *ArtifactReadOnlyS3) ResolveIndexedObject(ctx context.Context, key, sha string, size int64, budget ArtifactVersionSearchBudget, until time.Time) (ArtifactReadObject, error) {
	if size < 1 {
		return ArtifactReadObject{}, errPublicationUnavailable
	}
	return r.resolveHashedVersion(ctx, key, sha, size, size, budget, until)
}

// Metadata objects such as v12's index are hash-bound by their parent without
// a size field. A caller-provided byte budget bounds version discovery/reads.
func (r *ArtifactReadOnlyS3) ResolveHashedObject(ctx context.Context, key, sha string, maxBytes int64, budget ArtifactVersionSearchBudget, until time.Time) (ArtifactReadObject, error) {
	return r.resolveHashedVersion(ctx, key, sha, 0, maxBytes, budget, until)
}

func (r *ArtifactReadOnlyS3) resolveHashedVersion(ctx context.Context, key, sha string, size, maxBytes int64, budget ArtifactVersionSearchBudget, until time.Time) (ArtifactReadObject, error) {
	var zero ArtifactReadObject
	if r == nil || r.store == nil || !formalCandidateDigest(sha) || size < 0 || maxBytes < 1 || maxBytes > 8<<30 || size > maxBytes || budget.MaxVersions < 1 || budget.MaxVersions > 10000 || budget.MaxPages < 1 || budget.MaxPages > 1000 || budget.MaxReadBytes < maxBytes || budget.MaxReadBytes > 900<<30 {
		return zero, errPublicationUnavailable
	}
	versions := []artifactNativeVersion{}
	seen := map[string]bool{}
	markers := map[string]bool{}
	keyMarker, versionMarker := "", ""
	count := 0
	pages := 0
	for {
		pages++
		if pages > budget.MaxPages {
			return zero, errPublicationUnavailable
		}
		remaining := budget.MaxVersions - count
		if remaining < 1 {
			return zero, errPublicationUnavailable
		}
		limit := remaining
		if limit > 1000 {
			limit = 1000
		}
		page, err := r.versionPage(ctx, key, keyMarker, versionMarker, limit, until)
		if err != nil {
			return zero, err
		}
		count += len(page.Versions) + len(page.Deletes)
		for _, version := range page.Versions {
			if version.Key != key {
				if !strings.HasPrefix(version.Key, key) {
					return zero, errPublicationUnavailable
				}
				continue
			}
			if version.Version == "" || version.Version == "null" || version.Version == "latest" || len(version.Version) > 256 || version.Size < 1 || version.Size > 8<<30 || version.Modified.IsZero() || seen[version.Version] {
				return zero, errPublicationUnavailable
			}
			seen[version.Version] = true
			if version.Size <= maxBytes && (size == 0 || version.Size == size) {
				versions = append(versions, version)
			}
		}
		if !page.Truncated {
			break
		}
		keyMarker, versionMarker = page.NextKeyMarker, page.NextVersionIDMarker
		marker := keyMarker + "\x00" + versionMarker
		if keyMarker == "" || markers[marker] {
			return zero, errPublicationUnavailable
		}
		markers[marker] = true
	}
	sort.Slice(versions, func(i, j int) bool {
		if !versions[i].Modified.Equal(versions[j].Modified) {
			return versions[i].Modified.Before(versions[j].Modified)
		}
		return versions[i].Version < versions[j].Version
	})
	remaining := budget.MaxReadBytes
	for _, version := range versions {
		if version.Size > remaining {
			return zero, errPublicationUnavailable
		}
		remaining -= version.Size
		intent := publicationPayloadIntent{Key: key, SHA256: sha, Size: version.Size}
		object, err := readPublicationPayload(ctx, r.store, intent, version.Version, until)
		if err == errPublicationConflict {
			continue
		}
		if err != nil {
			return zero, err
		}
		if _, err = r.store.credential(false); err != nil {
			return zero, err
		}
		return ArtifactReadObject{Key: object.Key, Version: object.Version, SHA256: object.SHA256, Size: object.Size}, nil
	}
	return zero, errPublicationConflict
}
