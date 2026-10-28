package recovery

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

const Version = "system-backup.v1"

type Purpose string

const ManifestPurpose Purpose = "manifest"
const AcceptancePurpose Purpose = "acceptance_record"
const CatalogPurpose Purpose = "catalog_record"

type Header struct {
	Algorithm     string  `json:"algorithm"`
	KeyID         string  `json:"key_id"`
	KeyVersion    string  `json:"key_version"`
	Purpose       Purpose `json:"purpose"`
	SchemaVersion string  `json:"schema_version"`
}
type Signature struct {
	Protected Header `json:"protected"`
	Value     []byte `json:"value"`
}
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature Signature       `json:"signature"`
}
type TrustKey struct {
	ID, Version string
	Purpose     Purpose
	Public      ed25519.PublicKey
	Compromised bool
}
type Trust []TrustKey

func (t Trust) Validate() error {
	if len(t) == 0 || len(t) > 256 {
		return ErrContract
	}
	for _, k := range t {
		_, e := t.key(Header{"Ed25519", k.ID, k.Version, k.Purpose, Version})
		if e != nil && !(k.Compromised && e == ErrUnavailable) {
			return e
		}
	}
	return nil
}

func (t Trust) key(h Header) (ed25519.PublicKey, error) {
	if h.Algorithm != "Ed25519" || h.SchemaVersion != Version {
		return nil, ErrContract
	}
	var found ed25519.PublicKey
	for i, k := range t {
		if !validID(k.ID) || !validID(k.Version) || len(k.Public) != ed25519.PublicKeySize || !validPurpose(k.Purpose) {
			return nil, ErrContract
		}
		for _, other := range t[:i] {
			if (k.ID == other.ID && k.Version == other.Version) || k.Purpose != other.Purpose && (k.ID == other.ID || bytes.Equal(k.Public, other.Public)) {
				return nil, ErrContract
			}
		}
		if k.ID == h.KeyID && k.Version == h.KeyVersion && k.Purpose == h.Purpose {
			if k.Compromised {
				return nil, ErrUnavailable
			}
			found = k.Public
		}
	}
	if found == nil {
		return nil, ErrUnavailable
	}
	for _, k := range t {
		if k.Compromised && bytes.Equal(k.Public, found) {
			return nil, ErrUnavailable
		}
	}
	return found, nil
}
func validPurpose(p Purpose) bool {
	return p == ManifestPurpose || p == AcceptancePurpose || p == CatalogPurpose
}
func signingBytes(h Header, p json.RawMessage) ([]byte, error) {
	return Marshal([]any{"clawmanager/system-backup/v1/" + string(h.Purpose), h, p})
}
func Seal(payload any, p Purpose, id, version string, private ed25519.PrivateKey, trust Trust) ([]byte, error) {
	h := Header{"Ed25519", id, version, p, Version}
	pub, e := trust.key(h)
	if e != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), pub) {
		return nil, ErrContract
	}
	b, e := Marshal(payload)
	if e != nil {
		return nil, e
	}
	input, e := signingBytes(h, b)
	if e != nil {
		return nil, e
	}
	return Marshal(Envelope{b, Signature{h, ed25519.Sign(private, input)}})
}
func (t Trust) Open(raw []byte, p Purpose, out any) (Header, error) {
	var env Envelope
	if decode(raw, &env) != nil || env.Signature.Protected.Purpose != p {
		return Header{}, ErrContract
	}
	h := env.Signature.Protected
	key, e := t.key(h)
	if e != nil {
		return h, e
	}
	input, e := signingBytes(h, env.Payload)
	if e != nil || !ed25519.Verify(key, input, env.Signature.Value) || decode(env.Payload, out) != nil {
		return h, ErrContract
	}
	return h, nil
}
