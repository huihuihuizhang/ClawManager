package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"regexp"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// InspectInstallationHead authenticates comparison data for the offline
// writer, including a revoked/expired head. It does not grant consumption;
// existing verifyHead/readOwnerLedger still require current active authority.
func InspectInstallationHead(raw, signature []byte, issuer ed25519.PublicKey) (Head, error) {
	var h Head
	if len(raw) == 0 || len(raw) > 262144 || len(issuer) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return Head{}, ErrOwner
	}
	raw, signature, issuer = bytes.Clone(raw), bytes.Clone(signature), bytes.Clone(issuer)
	if !ed25519.Verify(issuer, append([]byte(HeadDomain), raw...), signature) || decodeCanonical(raw, &h) != nil || h.SchemaVersion != HeadVersion || !regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(h.InstallationID) || !safeName.MatchString(h.EnrollmentID) || !safeName.MatchString(h.IssuerID) || !validText(h.OwnerSubject) || h.EnrollmentRevision == 0 || h.Revision == 0 || !safeName.MatchString(h.GrantID) || h.GrantRevision == 0 || !hashPattern.MatchString(h.RecordSHA256) || (h.State != "active" && h.State != "revoked") || !validWindow(h.NotBefore, h.Until) {
		return Head{}, ErrOwner
	}
	return h, nil
}

// VerifyInstallationRequest preserves the original codec and complete
// grant/config/reference-set comparison. The installer supplies an issuer pin
// authenticated independently through its original enrollment, never a record.
func VerifyInstallationRequest(raw, signature []byte, pin TrustPin, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) error {
	a, e := VerifyRecord(raw, signature, pin)
	if e != nil || !matchConfig(a, grant, config) {
		return ErrOwner
	}
	return nil
}

// CheckInstallationDraft is only a pre-signing shape/pin comparison. It
// creates and returns no AuthenticatedRecord, observation or approval.
func CheckInstallationDraft(raw []byte, pin TrustPin) error {
	var r Record
	if len(raw) == 0 || len(raw) > 262144 || digest(raw) != pin.RecordSHA256 || decodeCanonical(raw, &r) != nil || !validRecord(r, pin) {
		return ErrOwner
	}
	return nil
}

// InstallationCaptureObservation can only originate in the existing concrete
// observer. It is not serializable, an authorization DTO or a callback result.
type InstallationCaptureObservation struct {
	observation *signingObservation
	ctx         context.Context
}

func (*InstallationCaptureObservation) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (o *InstallationCaptureObservation) ValidUntil() time.Time {
	if o == nil || o.observation == nil {
		return time.Time{}
	}
	return o.observation.until
}
func (o *InstallationCaptureObservation) Check(ctx context.Context, now time.Time, recordSHA string) error {
	if o == nil || o.observation == nil || o.observation.owner == nil || !sameContext(ctx, o.ctx) || ctx.Err() != nil || !validTime(now) || o.observation.recordHash != recordSHA || now.Before(o.observation.observed) || !now.Before(o.observation.until) || !time.Now().Before(o.observation.until) {
		return ErrOwner
	}
	return nil
}
func ObserveInstallationCapture(ctx context.Context, raw, signature []byte, pin TrustPin, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, observer *CaptureSigningObserver) (*InstallationCaptureObservation, error) {
	if len(raw) == 0 || len(raw) > 262144 {
		return nil, ErrOwner
	}
	raw = bytes.Clone(raw)
	signature = bytes.Clone(signature)
	a, e := VerifyRecord(raw, signature, pin)
	if e != nil || !matchConfig(a, grant, config) || observer == nil {
		return nil, ErrOwner
	}
	observed, e := observer.observe(ctx, a)
	if e != nil {
		return nil, e
	}
	return &InstallationCaptureObservation{observed, ctx}, nil
}
