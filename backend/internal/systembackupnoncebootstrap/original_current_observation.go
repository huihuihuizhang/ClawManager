package systembackupnoncebootstrap

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"
)

type OriginalCurrentObservation struct {
	started time.Time
	ctx     context.Context
	origin  *OriginalCurrentObservation
	native  *check
	proof   string
}

func (*OriginalCurrentObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

// Actual controlled exact-version external-secret mount; no nonce is issued,
// consumed or inserted. The original installer must independently authenticate
// this deployment mapping; New does not turn arbitrary mapping DATA into proof.
func (v *Validator) ObserveOriginalCurrent(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (*OriginalCurrentObservation, error) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	raw, err := v.Prepare(ctx, g, c)
	if err != nil {
		return nil, err
	}
	native, ok := raw.(*check)
	if !ok || native == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	var active sec.BootstrapSecretRef
	for _, ref := range c.References() {
		if ref.Purpose == "nonce_hmac" {
			active = ref
		}
	}
	first, err := v.Material(active.IdentityHash, active.Version)
	if err != nil {
		return nil, err
	}
	defer wipe(first)
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		return nil, err
	}
	defer wipe(challenge)
	h := hmac.New(sha256.New, first)
	h.Write(challenge)
	signed := h.Sum(nil)
	defer wipe(signed)
	second, err := v.Material(active.IdentityHash, active.Version)
	if err != nil {
		return nil, err
	}
	defer wipe(second)
	other := hmac.New(sha256.New, second)
	other.Write(challenge)
	checkMAC := other.Sum(nil)
	defer wipe(checkMAC)
	if len(first) != 32 || len(second) != 32 || subtle.ConstantTimeCompare(first, second) != 1 || !hmac.Equal(signed, checkMAC) {
		return nil, sec.ErrRegistrationUnavailable
	}
	binding, err := v.BindingSHA256()
	if err != nil {
		return nil, err
	}
	proof := sha256.Sum256(append(append([]byte(binding+"\x00"), challenge...), signed...))
	o := &OriginalCurrentObservation{ctx: ctx, native: native, proof: hex.EncodeToString(proof[:]), started: started}
	o.origin = o
	return o, nil
}
func (o *OriginalCurrentObservation) Facts(ctx context.Context) (string, time.Time, time.Time, error) {
	if o == nil || o.origin != o || o.native == nil || !sameCandidateNonceContext(ctx, o.ctx) || ctx.Err() != nil || !time.Now().Before(o.native.expires) {
		return "", time.Time{}, time.Time{}, sec.ErrRegistrationUnavailable
	}
	return o.proof, o.started, o.native.expires, nil
}
