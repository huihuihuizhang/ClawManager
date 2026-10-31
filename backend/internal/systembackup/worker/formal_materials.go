package worker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	k "clawreef/internal/systembackupkms"
)

// Public mappings and independently signed permit MOUNTS only. No DEK, token,
// private key or unverified "approved" flag. The original frozen invocation
// pins the exact bytes; the existing A resolver authenticates the permit/Job.
type FormalCaptureMaterials struct {
	Version        string               `json:"schema_version"`
	KMS            k.Config             `json:"kms"`
	Permit         k.PermitMount        `json:"permit"`
	Resources      *ResourceSourceMount `json:"resources,omitempty"`
	PermitDelivery *k.PermitDeliveryPin `json:"permit_delivery,omitempty"`
}

func LoadFormalCaptureMaterials(path string, i Invocation) (FormalCaptureMaterials, error) {
	var zero FormalCaptureMaterials
	if !validFormalInvocation(i) || path == "" {
		return zero, ErrNotReady
	}
	f, e := os.Open(path)
	if e != nil {
		return zero, ErrNotReady
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return zero, ErrNotReady
	}
	raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(raw) > 1<<20 {
		return zero, ErrNotReady
	}
	defer clear(raw)
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != i.FormalCapture.ConfigSHA256 || !uniqueFormalJSON(raw) {
		return zero, ErrNotReady
	}
	var out FormalCaptureMaterials
	if decodeBounded(bytes.NewReader(raw), &out, 1<<20) != nil || out.Version != FormalCaptureVersion || out.KMS.Key != i.ProviderKey.Request.Key || out.KMS.Endpoint != i.ProviderKey.Endpoint || out.KMS.KeyName != i.ProviderKey.KeyName || out.KMS.InstallationID != i.ProviderKey.Request.Context.InstallationID {
		return zero, ErrNotReady
	}
	if i.FormalCapture.PermitDelivery != nil {
		if out.PermitDelivery == nil || !samePermitDeliveryPin(*out.PermitDelivery, *i.FormalCapture.PermitDelivery) || out.Permit.PermitPath != "" || out.Permit.PermitSHA256 != "" || out.Permit.CredentialDirectory != "" || len(out.Permit.PublicKey) != 0 {
			return zero, ErrNotReady
		}
	} else {
		if out.PermitDelivery != nil || out.Permit.PermitPath == "" || out.Permit.CredentialDirectory == "" || !keyUseHash.MatchString(out.Permit.PermitSHA256) || len(out.Permit.PublicKey) != ed25519.PublicKeySize {
			return zero, ErrNotReady
		}
	}
	if (i.Request.Resources != nil) != (out.Resources != nil) {
		return zero, ErrNotReady
	}
	return out, nil
}

func samePermitDeliveryPin(a, b k.PermitDeliveryPin) bool {
	return k.ValidPermitDeliveryPin(a) && k.ValidPermitDeliveryPin(b) && a.Version == b.Version && a.IssuerGrantSHA256 == b.IssuerGrantSHA256 && bytes.Equal(a.Issuer, b.Issuer)
}
func uniqueFormalJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				name, ok := k.(string)
				if e != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, e = d.Token()
		return e == nil
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
