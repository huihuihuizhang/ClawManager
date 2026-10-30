package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	admission "clawreef/internal/systembackupkekadmission"
	reg "clawreef/internal/systembackupkekregistry"
)

// OriginalRecord is issued by the installation authority, never by the config
// writer. The signature covers the complete binding and revocation state.
type OriginalRecord struct {
	Binding                        reg.Binding
	Source                         reg.SourceRecord
	Revision                       string
	NotBefore, Until               time.Time
	GenerateRevoked, UnwrapRevoked bool
}

// OriginalReader reads the installation authority's records. Recheck receives
// only the original transaction: implementations must use the KEK-fenced
// authority record, with no provider I/O or acquisition of earlier locks.
type OriginalReader interface {
	ReadOriginal(context.Context, string, reg.ReferencePin) ([]byte, []byte, error)
	RecheckOriginal(context.Context, reg.SQLReadView, string, reg.ReferencePin) ([]byte, []byte, error)
}

type CapabilityPreparation interface {
	PrepareCapabilities(context.Context, reg.Binding) (admission.Capabilities, error)
}

// InstallationPreparation pins the original installation issuer independently
// of candidate JSON and committed config. Owner records must be signed using
// the domain below; the public key is trusted deployment input.
type InstallationPreparation struct {
	Reader       OriginalReader
	Issuer       ed25519.PublicKey
	Capabilities CapabilityPreparation
	Now          func() time.Time
}

func authenticate(raw, signature []byte, key ed25519.PublicKey, now time.Time) (OriginalRecord, error) {
	var r OriginalRecord
	if len(key) != ed25519.PublicKeySize || len(raw) == 0 || len(raw) > 65536 ||
		!ed25519.Verify(key, append([]byte("system-backup-original-kek.v1\x00"), raw...), signature) || json.Unmarshal(raw, &r) != nil ||
		r.Source.SourceID == "" || r.Source.RecordID == "" || r.Source.RecordVersion == "" || r.Revision == "" ||
		now.IsZero() || r.NotBefore.IsZero() || now.Before(r.NotBefore) || !now.Before(r.Until) || r.GenerateRevoked || r.UnwrapRevoked {
		return OriginalRecord{}, admission.ErrCandidate
	}
	// The source content hash names the exact independently signed binding.
	b, err := json.Marshal(r.Binding)
	h := sha256.Sum256(b)
	if err != nil || r.Source.ContentSHA256 != hex.EncodeToString(h[:]) {
		return OriginalRecord{}, admission.ErrCandidate
	}
	return r, nil
}

func (p InstallationPreparation) PrepareKEK(ctx context.Context, in reg.AdmissionInput) (reg.PreparedMappingSource, admission.Capabilities, error) {
	fail := func() (reg.PreparedMappingSource, admission.Capabilities, error) {
		return nil, admission.Capabilities{}, admission.ErrCandidate
	}
	if ctx == nil || ctx.Err() != nil || nilSource(p.Reader) || nilSource(p.Capabilities) || p.Now == nil {
		return fail()
	}
	if admission.CheckUnadmittedInput(in, p.Now().UTC()) != nil {
		return fail()
	}
	raw, sig, err := p.Reader.ReadOriginal(ctx, in.Candidate.InstallationID, in.Candidate.ConfigRef)
	if err != nil {
		return fail()
	}
	r, err := authenticate(raw, sig, p.Issuer, p.Now().UTC())
	if err != nil || !reflect.DeepEqual(r.Binding, in.Candidate) || r.Source != in.Observation.MappingSource || r.Revision != in.Observation.SourceRevision {
		return fail()
	}
	prepared := &originalMapping{reader: p.Reader, key: append(ed25519.PublicKey(nil), p.Issuer...), record: r}
	caps, err := p.Capabilities.PrepareCapabilities(ctx, prepared.Binding())
	if err != nil {
		return fail()
	}
	return prepared, caps, nil
}

type originalMapping struct {
	reader OriginalReader
	key    ed25519.PublicKey
	record OriginalRecord
}

func (p *originalMapping) Source() reg.SourceRecord { return p.record.Source }
func (p *originalMapping) SourceRevision() string   { return p.record.Revision }
func (p *originalMapping) ValidUntil() time.Time    { return p.record.Until }
func (p *originalMapping) Binding() reg.Binding {
	b := p.record.Binding
	b.GenerateRef.RawJSON = append([]byte(nil), b.GenerateRef.RawJSON...)
	b.UnwrapRef.RawJSON = append([]byte(nil), b.UnwrapRef.RawJSON...)
	return b
}
func (p *originalMapping) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || view == nil || locked.Facts().InstallationID != p.record.Binding.InstallationID {
		return admission.ErrCandidate
	}
	raw, sig, err := p.reader.RecheckOriginal(ctx, view, p.record.Binding.InstallationID, p.record.Binding.ConfigRef)
	if err != nil {
		return admission.ErrCandidate
	}
	r, err := authenticate(raw, sig, p.key, now)
	if err != nil || !reflect.DeepEqual(r, p.record) {
		return admission.ErrCandidate
	}
	return nil
}
