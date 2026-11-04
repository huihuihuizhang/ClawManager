package systembackup

import (
	"context"
	"time"
)

// A real MinIO builtin IAM user/root credential has no native lease/TTL.
// This object records fixed identity bytes only. It carries NO authority,
// observation timestamp, future expiry, task, operation or Passed field.
type MinIOBuiltinIdentity struct {
	Kind      string
	AccessKey string
	SecretKey []byte
	Version   string
}

func resolveMinIOBuiltinIdentity(ctx context.Context, identity MinIOBuiltinIdentity, check TeamSourceCheck) (MinIOGateCredential, error) {
	var zero MinIOGateCredential
	if ctx == nil || ctx.Err() != nil || check == nil || check(ctx) != nil || identity.Kind != "minio-builtin-static-identity.v1" || identity.AccessKey == "" || identity.Version == "" || identity.Version == "latest" || identity.Version == "current" || len(identity.SecretKey) < 8 {
		return zero, ErrMinIOReadGate
	}
	deadline, bounded := ctx.Deadline()
	now := time.Now().UTC()
	if !bounded || !now.Before(deadline) {
		return zero, ErrMinIOReadGate
	}
	// These are CALL-LOCAL native transport bounds from the current genuinely
	// checked authority, never a change to a stored key expiry or installation
	// grant. Every native request still invokes that same concrete owner check.
	credential := MinIOGateCredential{AccessKey: identity.AccessKey, SecretKey: append([]byte(nil), identity.SecretKey...), Version: identity.Version, NotBefore: now, Until: deadline}
	if !minioGateCredentialValid(credential, now) || check(ctx) != nil {
		clear(credential.SecretKey)
		return zero, ErrMinIOReadGate
	}
	return credential, nil
}
