package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/staging"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// This local worker protocol carries encrypted/public input DATA only. It has
// no SQL, source, capture execution grant, private signing key or KMS material.
// The controller authenticates the exact request and its separate upload
// identity before CreatePublishJob; worker success is never artifact acceptance.
type PublicationUploadRequest struct {
	Version                                                   string `json:"schema_version"`
	Installation, Backup                                      string
	Attempt                                                   uint64
	Endpoint, Region, Bucket, ArtifactRoot, RemoteStagingRoot string
	CAHash, CredentialHash                                    string
	CandidateOwnerHMAC                                        string
	Deadline                                                  time.Time
	Objects                                                   []PublicationUploadInput
	ManifestInput                                             json.RawMessage
}
type PublicationUploadInput struct {
	Path, SHA256 string
	Bytes        int64
}
type PublicationUploadObservation struct {
	Key, Version, SHA256 string
	Bytes                int64
}
type PublicationUploadResult struct {
	Version, Installation, Backup string
	Attempt                       uint64
	RequestSHA256                 string
	Objects                       []PublicationUploadObservation
	Candidate                     PublicationUploadObservation
}

const publicationUploadVersion = "system-backup-upload-only.v1"

func (p PublicationUploadRequest) validate() ([]byte, string, error) {
	if p.CandidateOwnerHMAC != "" && !formalCandidateDigest(p.CandidateOwnerHMAC) {
		return nil, "", errPublicationUnavailable
	}
	if p.Version != publicationUploadVersion || !strings.HasPrefix(p.Installation, "installation_") || len(p.Installation) > 128 || !strings.HasPrefix(p.Backup, "sbk_") || len(p.Backup) != 40 || p.Attempt < 1 || len(p.Objects) < 2 || len(p.Objects) > 20001 || p.Deadline.IsZero() || !formalCandidateDigest(p.CAHash) || !formalCandidateDigest(p.CredentialHash) {
		return nil, "", errPublicationUnavailable
	}
	if _, e := uuid.Parse(strings.TrimPrefix(p.Backup, "sbk_")); e != nil {
		return nil, "", errPublicationUnavailable
	}
	u, e := url.Parse(p.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || p.Region == "" || p.Bucket == "" || strings.ContainsAny(p.Bucket, "/\\\x00\r\n") {
		return nil, "", errPublicationUnavailable
	}
	for _, root := range []string{p.ArtifactRoot, p.RemoteStagingRoot} {
		if !safePublicationKey(strings.TrimSuffix(root, "/")) || !strings.HasSuffix(root, "/") {
			return nil, "", errPublicationUnavailable
		}
	}
	if strings.HasPrefix(p.ArtifactRoot, p.RemoteStagingRoot) || strings.HasPrefix(p.RemoteStagingRoot, p.ArtifactRoot) {
		return nil, "", errPublicationUnavailable
	}
	seen := map[string]bool{}
	index := false
	indexSHA := ""
	for _, object := range p.Objects {
		if !safePublicationKey(object.Path) || path.Clean(object.Path) != object.Path || seen[object.Path] || !formalCandidateDigest(object.SHA256) || object.Bytes < 1 || object.Bytes > 8<<30 {
			return nil, "", errPublicationUnavailable
		}
		base := path.Base(object.Path)
		if object.Path == "artifact-index.json" {
			index = true
			indexSHA = object.SHA256
		} else if !strings.HasPrefix(object.Path, "parts/") && !strings.HasPrefix(object.Path, "control/") {
			return nil, "", errPublicationUnavailable
		} else if !strings.HasSuffix(base, ".enc") && !strings.HasSuffix(base, ".envelope.json") {
			return nil, "", errPublicationUnavailable
		}
		if base == "manifest.json" || strings.HasPrefix(base, "_") || strings.Contains(strings.ToLower(base), "catalog") {
			return nil, "", errPublicationUnavailable
		}
		seen[object.Path] = true
	}
	if !index || len(p.ManifestInput) < 2 || len(p.ManifestInput) > 262144 {
		return nil, "", errPublicationUnavailable
	}
	manifest, e := jsoncanonicalizer.Transform(p.ManifestInput)
	if e != nil || len(manifest) > 262144 {
		return nil, "", errPublicationUnavailable
	}
	var binding struct {
		Schema       string                          `json:"schema_version"`
		Installation string                          `json:"origin_installation_id"`
		Backup       string                          `json:"backup_public_id"`
		Attempt      uint64                          `json:"attempt_no"`
		Index        struct{ Path, Checksum string } `json:"artifact_index"`
	}
	if json.Unmarshal(manifest, &binding) != nil || binding.Schema != "system-backup.v1" || binding.Installation != p.Installation || binding.Backup != p.Backup || binding.Attempt != p.Attempt || binding.Index.Path != "artifact-index.json" || binding.Index.Checksum != indexSHA {
		return nil, "", errPublicationUnavailable
	}
	// Full v12 schema/business/certificate verification belongs to the current
	// controller before finalization. Candidate bytes alone convey no permission.
	key := p.RemoteStagingRoot + p.Backup + "/" + strconv.FormatUint(p.Attempt, 10) + "/manifest-candidate.json"
	if !safePublicationKey(key) {
		return nil, "", errPublicationUnavailable
	}
	return manifest, key, nil
}

type publicationUploadReader struct {
	ctx context.Context
	r   io.Reader
}

func (r publicationUploadReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}

// RunPublicationUploadOnly sends each explicit non-final object and the unique
// remote candidate at most once. Backoff/restart are disabled in PublishJob.
// An exclusive local start witness refuses manual re-entry too; it is DATA in
// the original Job's output, not task authority or a second control state store.
// Ambiguous PUT outcomes always require controller-side immutable readback.
func RunPublicationUploadOnly(ctx context.Context, request []byte, caFile, credentialFile string, input, output *os.Root) (PublicationUploadResult, error) {
	var zero PublicationUploadResult
	if ctx == nil || ctx.Err() != nil || input == nil || output == nil || len(request) < 2 || len(request) > 8<<20 {
		return zero, errPublicationUnavailable
	}
	var p PublicationUploadRequest
	if decodeProviderDeploymentJSON(request, &p) != nil {
		return zero, errPublicationUnavailable
	}
	manifest, candidateKey, err := p.validate()
	if err != nil {
		return zero, err
	}
	if !formalCandidateDigest(p.CandidateOwnerHMAC) {
		return zero, errPublicationUnavailable
	}
	if !time.Now().Before(p.Deadline) || time.Until(p.Deadline) > 24*time.Hour {
		return zero, errPublicationUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	ca, err := pinnedDeploymentFile(caFile, p.CAHash, 1<<20)
	if err != nil || len(ca) == 0 {
		return zero, errPublicationUnavailable
	}
	private, err := readPrivate(credentialFile, 65536)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	defer clear(private)
	if hash(private) != p.CredentialHash {
		return zero, errPublicationUnavailable
	}
	var credential nativePublicationCredential
	if decodeProviderDeploymentJSON(private, &credential) != nil || len(credential.AccessKey) < 3 || len(credential.AccessKey) > 256 || strings.ContainsAny(credential.AccessKey, "\r\n") || len(credential.SecretKey) < 16 || len(credential.SecretKey) > 4096 || len(credential.SessionToken) > 16384 || credential.NotBefore.IsZero() || time.Now().Before(credential.NotBefore) || !time.Now().Before(credential.Until) || !credential.Until.After(credential.NotBefore) {
		return zero, errPublicationUnavailable
	}
	if credential.Until.Before(p.Deadline) {
		ctx, cancel = context.WithDeadline(ctx, credential.Until)
		defer cancel()
	}
	transport, err := newPublicationS3Transport(PublicationTargetMaterials{Endpoint: p.Endpoint, Region: p.Region, Bucket: p.Bucket, CAFile: caFile, CASHA256: p.CAHash})
	if err != nil {
		return zero, err
	}
	defer transport.Close()
	// This private file must be exclusive even after an interrupted/unknown
	// send. No retry path accepts or overwrites an earlier start witness.
	if err = writeStageExclusive(output, "upload-started.json", []byte(`{"request_sha256":"`+hash(request)+`"}`)); err != nil {
		return zero, ErrJobUncertain
	}
	result := PublicationUploadResult{Version: publicationUploadVersion, Installation: p.Installation, Backup: p.Backup, Attempt: p.Attempt, RequestSHA256: hash(request), Objects: []PublicationUploadObservation{}}
	prefix := p.ArtifactRoot + p.Backup + "/" + strconv.FormatUint(p.Attempt, 10) + "/"
	currentCredential := func() error {
		if _, e := pinnedDeploymentFile(caFile, p.CAHash, 65536); e != nil {
			return errPublicationUnavailable
		}
		raw, e := readPrivate(credentialFile, 65536)
		if e != nil {
			return errPublicationUnavailable
		}
		defer clear(raw)
		if hash(raw) != p.CredentialHash || ctx.Err() != nil || !time.Now().Before(credential.Until) {
			return errPublicationUnavailable
		}
		return nil
	}
	for _, object := range p.Objects {
		file, err := input.Open(object.Path)
		if err != nil {
			return zero, errPublicationUnavailable
		}
		info, err := file.Stat()
		expected, e := input.Lstat(object.Path)
		if err != nil || e != nil || !info.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, expected) || info.Size() != object.Bytes {
			file.Close()
			return zero, errPublicationUnavailable
		}
		digest := sha256.New()
		n, err := io.Copy(digest, publicationUploadReader{ctx: ctx, r: file})
		if err != nil || n != object.Bytes || hex.EncodeToString(digest.Sum(nil)) != object.SHA256 {
			file.Close()
			return zero, errPublicationConflict
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return zero, errPublicationUnavailable
		}
		if err = currentCredential(); err != nil {
			file.Close()
			return zero, err
		}
		observation, err := publicationUploadPut(ctx, transport.client, p, credential, prefix+object.Path, object.SHA256, object.Bytes, publicationUploadReader{ctx: ctx, r: file})
		file.Close()
		if err != nil {
			return zero, err
		}
		if err = currentCredential(); err != nil {
			return zero, err
		}
		result.Objects = append(result.Objects, observation)
	}
	result.Candidate, err = publicationUploadPut(ctx, transport.client, p, credential, candidateKey, hash(manifest), int64(len(manifest)), bytes.NewReader(manifest))
	if err != nil {
		return zero, err
	}
	if err = currentCredential(); err != nil {
		return zero, err
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 8<<20 {
		return zero, errPublicationUnavailable
	}
	if _, err = staging.WriteUnpublishedFile(ctx, output, "publication-result.json", func(w io.Writer) error { _, e := w.Write(raw); return e }); err != nil {
		return zero, err
	}
	return result, nil
}

func publicationUploadPut(ctx context.Context, client *http.Client, p PublicationUploadRequest, credential nativePublicationCredential, key, digest string, size int64, body io.Reader) (PublicationUploadObservation, error) {
	var zero PublicationUploadObservation
	if ctx.Err() != nil || !safePublicationKey(key) || !formalCandidateDigest(digest) || size < 1 || size > 8<<30 {
		return zero, errPublicationUnavailable
	}
	u, _ := url.Parse(p.Endpoint)
	u.Path = "/" + p.Bucket + "/" + key
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return zero, errPublicationUnavailable
	}
	r.ContentLength = size
	r.Header.Set("Content-Length", strconv.FormatInt(size, 10))
	contentType := "application/octet-stream"
	if strings.HasSuffix(key, ".json") {
		contentType = "application/json"
	}
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("If-None-Match", "*")
	r.Header.Set("X-Amz-Content-Sha256", digest)
	sum, _ := hex.DecodeString(digest)
	r.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum))
	ownerHeader := ""
	if key == p.RemoteStagingRoot+p.Backup+"/"+strconv.FormatUint(p.Attempt, 10)+"/manifest-candidate.json" {
		if !formalCandidateDigest(p.CandidateOwnerHMAC) {
			return zero, errPublicationUnavailable
		}
		ownerHeader = "x-amz-meta-system-backup-owner"
		r.Header.Set(ownerHeader, p.CandidateOwnerHMAC)
	}
	until := p.Deadline
	if credential.Until.Before(until) {
		until = credential.Until
	}
	seconds := int64(time.Until(until) / time.Second)
	if seconds < 1 {
		return zero, errPublicationUnavailable
	}
	r = signer.PreSignV4(*r, credential.AccessKey, credential.SecretKey, credential.SessionToken, p.Region, seconds)
	for _, required := range []string{"content-length", "content-type", "if-none-match", "x-amz-content-sha256", "x-amz-checksum-sha256"} {
		found := false
		for _, name := range strings.Split(r.URL.Query().Get("X-Amz-SignedHeaders"), ";") {
			if name == required {
				found = true
			}
		}
		if !found {
			return zero, errPublicationUnavailable
		}
	}
	if ownerHeader != "" {
		found := false
		for _, name := range strings.Split(r.URL.Query().Get("X-Amz-SignedHeaders"), ";") {
			if name == ownerHeader {
				found = true
			}
		}
		if !found {
			return zero, errPublicationUnavailable
		}
	}
	response, err := client.Do(r)
	if err != nil {
		return zero, ErrJobUncertain
	}
	defer response.Body.Close()
	responseBytes, err := io.Copy(io.Discard, io.LimitReader(response.Body, 8193))
	if err != nil || responseBytes > 8192 {
		return zero, ErrJobUncertain
	}
	version := response.Header.Get("X-Amz-Version-Id")
	if response.StatusCode != 200 || version == "" || version == "null" || version == "latest" || len(version) > 256 || response.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum) {
		return zero, ErrJobUncertain
	}
	return PublicationUploadObservation{Key: key, Version: version, SHA256: digest, Bytes: size}, nil
}
