package systembackupreferenceprobe

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"k8s.io/client-go/kubernetes"
)

// OriginalS3OwnerCredential is the existing MinIOGateCredential wire shape.
// It is credential DATA, never an approval. The native server must authenticate
// it and permit the actual admin operation before installation can mutate IAM.
type OriginalS3OwnerCredential struct {
	AccessKey        string
	SecretKey        []byte
	Version          string
	NotBefore, Until time.Time
}

// ObserveOriginalS3OwnerTarget performs paired real Kubernetes/server reads and
// an authenticated root discriminator. No caller supplied Passed/hash is used.
func ObserveOriginalS3OwnerTarget(ctx context.Context, kube kubernetes.Interface, namespace, namespaceUID string, p MinIOProvider, root FilePin) error {
	if ctx == nil || ctx.Err() != nil || kube == nil {
		return ErrObservation
	}
	raw, err := ReadPinned(root, 16384)
	if err != nil {
		return ErrObservation
	}
	defer clear(raw)
	var c OriginalS3OwnerCredential
	if minioPermissionDecode(raw, &c) != nil || c.Version == "" || len(c.AccessKey) < 3 || len(c.SecretKey) < 8 || time.Now().Before(c.NotBefore) || !time.Now().Before(c.Until) {
		return ErrObservation
	}
	defer clear(c.SecretKey)
	ctx, cancel := context.WithDeadline(ctx, c.Until)
	defer cancel()
	chain, err := minioPermissionKubernetes(ctx, kube, minioPermissionConfiguration{namespace, namespaceUID}, p)
	if err != nil {
		return ErrObservation
	}
	r, err := newMinioPermissionHTTP(p, nativePublicationCredential{AccessKey: c.AccessKey, SecretKey: string(c.SecretKey), NotBefore: c.NotBefore, Until: c.Until})
	if err != nil {
		return ErrObservation
	}
	defer r.close()
	a, err := r.serverSeptember(ctx)
	if err != nil {
		return ErrObservation
	}
	_, status, err := r.get(ctx, minioEffectiveOwnerGuardPath, url.Values{"subSys": {"policy_plugin"}, "key": {""}})
	if err != nil || status != http.StatusOK {
		return ErrObservation
	}
	b, err := r.serverSeptember(ctx)
	if err != nil || a != b {
		return ErrObservation
	}
	tail, err := minioPermissionKubernetes(ctx, kube, minioPermissionConfiguration{namespace, namespaceUID}, p)
	if err != nil || chain != tail || ctx.Err() != nil {
		return ErrObservation
	}
	return nil
}
