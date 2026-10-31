package systembackupkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"regexp"

	w "clawreef/internal/systembackupwire"
)

const PermitDeliveryVersion = "system-backup-provider-permit-delivery.v1"
const PermitDeliveryDomain = "system-backup-original-generate-permit-delivery.v1\x00"

// PermitDeliveryPin is frozen BEFORE an Invocation is hashed. It contains only
// independently deployed ORIGINAL Generate-owner issuer/delegation pins, never
// a future permit digest, Invocation hash, Job UID or Pod UID. These pins are
// neither artifact signing authority nor the worker identity CA.
type PermitDeliveryPin struct {
	Version           string            `json:"schema_version"`
	Issuer            ed25519.PublicKey `json:"issuer_public_key"`
	IssuerGrantSHA256 string            `json:"issuer_grant_sha256"`
}

// The ORIGINAL authenticated control chain supplies the persisted reserve
// nonce. A caller-selected DTO/DownwardAPI value cannot implement this owner.
type OriginalPermitJobAuthority interface {
	OriginalJobAuthority
	PermitNonce() string
}

// DeliveredPermitPayload is signed only AFTER real Job/Pod/SA binding and
// original key-reserve admission. It binds the FULL request and nonce in
// addition to every existing ProviderPermit/Job identity/window check.
type DeliveredPermitPayload struct {
	Version           string         `json:"schema_version"`
	IssuerGrantSHA256 string         `json:"issuer_grant_sha256"`
	Nonce             string         `json:"nonce"`
	Request           w.KeyRequest   `json:"request"`
	Permit            ProviderPermit `json:"permit"`
}

// These public signed bytes are journaled by the original owner and replayed
// byte-for-byte after an unknown ACK. No provider credential or DEK is carried.
type DeliveredProviderPermit struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func (p DeliveredProviderPermit) SHA256() string {
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return hash(raw)
}

type deliveredPermitState struct {
	pin      PermitDeliveryPin
	delivery DeliveredProviderPermit
	original OriginalPermitJobAuthority
	nonce    string
}

func ValidPermitDeliveryPin(p PermitDeliveryPin) bool {
	return p.Version == PermitDeliveryVersion && len(p.Issuer) == ed25519.PublicKeySize && digest.MatchString(p.IssuerGrantSHA256)
}

func NewDeliveredJobResolver(c Config, pin PermitDeliveryPin, delivery DeliveredProviderPermit, original OriginalPermitJobAuthority) (*PinnedJobResolver, error) {
	if !ValidPermitDeliveryPin(pin) || absent(original) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(original.PermitNonce()) || len(delivery.Payload) == 0 || len(delivery.Payload) > 32768 || len(delivery.Signature) != ed25519.SignatureSize {
		return nil, ErrPermission
	}
	i := original.Identity()
	until := original.ValidUntil()
	if !text(i.Namespace) || !text(i.PodUID) || !text(i.ServiceAccountUID) || !text(i.JobUID) || !digest.MatchString(i.InvocationSHA256) || !digest.MatchString(i.ExecutionGrantSHA256) || until.IsZero() {
		return nil, ErrPermission
	}
	pin.Issuer = bytes.Clone(pin.Issuer)
	delivery.Payload = bytes.Clone(delivery.Payload)
	delivery.Signature = bytes.Clone(delivery.Signature)
	r := &PinnedJobResolver{original: original, identity: i, until: until, delivered: &deliveredPermitState{pin: pin, delivery: delivery, original: original, nonce: original.PermitNonce()}}
	t, err := newTransit(c, r, Generate)
	if err != nil {
		return nil, err
	}
	t.client.CloseIdleConnections()
	c.CAPEM = bytes.Clone(c.CAPEM)
	r.config = &c
	return r, nil
}

func (r *PinnedJobResolver) deliveredPermit(ctx context.Context, a Access) (ProviderPermit, error) {
	s := r.delivered
	if s == nil || ctx == nil || ctx.Err() != nil || a.Operation != Generate || s.original.PermitNonce() != s.nonce || !ed25519.Verify(s.pin.Issuer, append([]byte(PermitDeliveryDomain), s.delivery.Payload...), s.delivery.Signature) {
		return ProviderPermit{}, ErrPermission
	}
	var payload DeliveredPermitPayload
	if closedJSON(s.delivery.Payload, &payload) != nil || payload.Version != PermitDeliveryVersion || payload.IssuerGrantSHA256 != s.pin.IssuerGrantSHA256 || payload.Nonce != s.nonce || payload.Request != a.Request || payload.Permit.Operation != Generate || payload.Permit.JWT == (JWTIdentityGrant{}) || payload.Permit.CredentialRef != "" || payload.Permit.CredentialSHA256 != "" {
		return ProviderPermit{}, ErrPermission
	}
	return payload.Permit, nil
}

func NewDeliveredCaptureJob(ctx context.Context, c Config, pin PermitDeliveryPin, delivery DeliveredProviderPermit, original OriginalPermitJobAuthority, frozen w.KeyRequest) (*CaptureJob, error) {
	r, err := NewDeliveredJobResolver(c, pin, delivery, original)
	if err != nil {
		return nil, err
	}
	return newCaptureJob(ctx, c, r, original, frozen)
}
