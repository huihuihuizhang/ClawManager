package systembackupreferenceprobe

import (
	"bytes"
	ce "clawreef/internal/systembackupcontrolevidence"
	"context"
	"github.com/minio/minio-go/v7/pkg/signer"
	"io"
	"k8s.io/client-go/kubernetes"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Exact previously installed immutable checkpoint, not a catalog scan DTO.
func ObserveOriginalCatalogCheckpoint(ctx context.Context, kube kubernetes.Interface, p OriginalFiveProfile, bucket, key, version string, envelope []byte) (*S3Observation, error) {
	if bucket == "" || key == "" || !strings.HasPrefix(key, p.Installation+"/catalog/initial-inventory/") || strings.ContainsAny(key, "\\\x00\r\n") || strings.Contains(key, "../") || version == "" || version == "null" || len(version) > 1024 || strings.ContainsAny(version, "\x00\r\n") || len(envelope) == 0 || len(envelope) > 4096 {
		return nil, ErrObservation
	}
	native, err := ObserveOriginalFive(ctx, kube, p)
	if err != nil {
		return nil, err
	}
	active, cancel := context.WithDeadline(ctx, native.until)
	defer cancel()
	var principal *OriginalFivePrincipal
	for j := range p.Principals {
		candidate := &p.Principals[j]
		if candidate.Principal.Purpose == "catalog_read" {
			if principal != nil || candidate.Bucket != bucket {
				return nil, ErrObservation
			}
			principal = candidate
		}
	}
	if principal == nil {
		return nil, ErrObservation
	}
	c, err := credential(principal.Principal.Credential)
	if err != nil {
		return nil, err
	}
	reader, err := newMinioPermissionHTTP(p.Provider, c)
	c = nativePublicationCredential{}
	if err != nil {
		return nil, err
	}
	defer reader.close()
	for _, fixed := range []string{"", version, ""} {
		// Native get checks complete body EOF/size and TLS/SPKI; the response's
		// exact native version header is independently checked below.
		if err = originalCatalogExactGET(active, reader, bucket, key, fixed, version, envelope); err != nil {
			return nil, err
		}
	}
	if active.Err() != nil || RecheckOriginalFiveFiles(p) != nil {
		return nil, ErrObservation
	}
	raw, _ := ce.Canonical([]string{native.identity, bucket, key, version, hash(envelope)})
	out := &S3Observation{identity: hash(raw), started: native.started, until: native.until}
	out.origin = out
	return out, nil
}
func originalCatalogExactGET(ctx context.Context, r *minioPermissionHTTP, bucket, key, fixed, want string, envelope []byte) error {
	q := url.Values{}
	if fixed != "" {
		q.Set("versionId", fixed)
	}
	// This fixed profile adds exact immutable/current GET, never PUT/DELETE or
	// unbounded source enumeration; signed owner install pins supply key/version.
	u, err := url.Parse(r.provider.Endpoint)
	if err != nil {
		return ErrObservation
	}
	u.Path = "/" + bucket + "/" + key
	u.RawQuery = q.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ErrObservation
	}
	return r.originalCatalogSignedGET(ctx, request, want, envelope)
}

func (r *minioPermissionHTTP) originalCatalogSignedGET(ctx context.Context, request *http.Request, version string, envelope []byte) error {
	if ctx.Err() != nil || time.Now().Before(r.credential.NotBefore) || !time.Now().Before(r.credential.Until) {
		return ErrObservation
	}
	request.Header.Set("X-Amz-Content-Sha256", hash(nil))
	request = signer.SignV4(*request, r.credential.AccessKey, r.credential.SecretKey, "", r.provider.Region)
	response, err := r.client.Do(request)
	if err != nil {
		return ErrObservation
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(response.Header.Values("X-Amz-Version-Id")) != 1 || response.Header.Get("X-Amz-Version-Id") != version || response.Header.Get("Content-Range") != "" || response.Header.Get("Content-Encoding") != "" || len(body) > 4096 || !bytes.Equal(body, envelope) || response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		return ErrObservation
	}
	return nil
}
