package systembackupminioauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"

	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
)

// Authenticates consent for exact SQL PROFILE comparison only. Returned data
// is not a VerifiedRuntimeMetadataRead and cannot authorize metadata reads.
// Actual reads still require fresh native workload + same-view original source.
func VerifyRuntimeMetadataProfileConsent(ctx context.Context, view reg.SQLReadView, d MinIORecoveryDescriptor, descriptorSHA Digest, source RuntimeMetadataConsentSource, current *c.PinnedExecutionIdentity) (RuntimeMetadataConsent, error) {
	var zero RuntimeMetadataConsent
	raw, e := runtimeMetadataFile(source.File, source.SHA256)
	if e != nil {
		return zero, ErrRecord
	}
	r, e := DecodeRuntimeMetadataConsent(raw, d, descriptorSHA)
	if e != nil || source.OriginalForwardSHA256 != string(r.OriginalForwardSHA256) {
		return zero, ErrRecord
	}
	account, server, database, now, e := sampleSQL(ctx, view)
	if e != nil || account != r.RuntimeDatabaseAccount || server != d.Pin.Target.ServerUUID || database != d.Pin.Target.Database || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return zero, ErrRecord
	}
	original, e := runtimeMetadataFile(source.OriginalForwardFile, source.OriginalForwardSHA256)
	if e != nil {
		return zero, ErrRecord
	}
	var envelope struct {
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}
	exact := func(raw []byte, out any) bool {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		return decoder.Decode(out) == nil && decoder.Decode(new(any)) == io.EOF
	}
	if !exact(original, &envelope) {
		return zero, ErrRecord
	}
	body, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	signature, se := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	var old c.ExecutionGrant
	if e != nil || se != nil || !ed25519.Verify(r.ForwardIssuer, body, signature) || !exact(body, &old) || old.Version != "system-backup-execution-grant.v1" || old.ConfigVersion != 1 || old.ConfigSHA256 != string(r.OriginalConfigSHA256) || old.InstallationID != d.Pin.Target.InstallationID || old.ServerUUID != server || old.Database != database || old.DatabaseAccount != account || old.ControllerOwner != r.Workload.ControllerOwner || now.Before(old.NotBefore) || !now.Before(old.ExpiresAt) || r.NotBefore.Before(old.NotBefore) || r.Until.After(old.ExpiresAt) {
		return zero, ErrRecord
	}
	if current != nil {
		if current.CheckDeploymentInViewWithIssuer(ctx, view, r.ForwardIssuer) != nil {
			return zero, ErrRecord
		}
		if current.GrantSHA256() != source.OriginalForwardSHA256 {
			prior, e := current.OpenOriginalEnabledOnlyPredecessor(source.OriginalForwardFile, source.OriginalForwardSHA256)
			if e != nil || current.CheckOriginalEnabledOnlyPredecessorInView(ctx, view, prior) != nil {
				return zero, ErrRecord
			}
		}
	}
	return r, nil
}
