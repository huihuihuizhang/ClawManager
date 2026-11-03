package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Existing independently pinned installation public history/permission mapping.
// Its SQLOwner/business claims are deliberately not interpreted as bootstrap
// authority. The NEW purpose-partitioned original grant/head supplies that.
type SigningResourceMaterial struct {
	Files RecordFiles
	Pin   sec.InstallationSigningPin
}

func CheckSigningResourceMaterial(ctx context.Context, m SigningResourceMaterial, g SigningResourceGrant) error {
	if !sameContext(ctx, ctx) || ctx.Err() != nil || m.Files.RecordFile == m.Files.SignatureFile || m.Pin.InstallationID != g.Target.InstallationID || m.Pin.RecordSHA256 != g.SigningMaterialSHA256 || m.Pin.Revision != g.SigningMaterialRevision || len(m.Pin.Issuer) != ed25519.PublicKeySize {
		return ErrOwner
	}
	raw, e := localFile(m.Files.RecordFile, 262144)
	sig, f := localFile(m.Files.SignatureFile, 64)
	if e != nil || f != nil || digest(raw) != m.Pin.RecordSHA256 || len(sig) != 64 || !ed25519.Verify(m.Pin.Issuer, append([]byte(sec.InstallationSigningDomain), raw...), sig) {
		return ErrOwner
	}
	var r sec.InstallationSigningRecord
	if json.Unmarshal(raw, &r) != nil {
		return ErrOwner
	}
	round, e := canonical(r)
	original, ce := jsoncanonical(raw)
	// Preserve the EXISTING independently pinned signature bytes, including
	// legacy whitespace/field order and RFC3339 offsets/nanoseconds. Canonical
	// comparison still rejects unknown/missing/case-alias/duplicate fields.
	if e != nil || ce != nil || !bytes.Equal(round, original) || r.InstallationID != g.Target.InstallationID || r.Revision != g.SigningMaterialRevision || len(r.Permissions) != 3 || !signingMaterialTime(r.NotBefore) || !signingMaterialTime(r.Until) || !r.Until.After(r.NotBefore) || g.NotBefore.Before(r.NotBefore) || g.Until.After(r.Until) {
		return ErrOwner
	}
	history, e := sec.NewArtifactSigningKeyHistory(r.InstallationID, r.Keys)
	if e != nil {
		return ErrOwner
	}
	seen := map[string]bool{}
	for _, p := range r.Permissions {
		b := p.Binding
		var expected Binding
		for _, candidate := range g.Bindings {
			if candidate.Purpose == b.Purpose {
				expected = candidate
			}
		}
		if expected.Purpose == "" || seen[b.Purpose] || b.InstallationID != expected.InstallationID || b.KeyID != expected.KeyID || b.KeyVersion != expected.KeyVersion || b.Endpoint != expected.Endpoint || b.KeyName != expected.KeyName || b.ProviderVersion != expected.ProviderVersion || p.AuthMount != expected.AuthMount || p.Role != expected.Role || p.Policy != expected.Policy || p.CASHA256 != expected.CASHA256 {
			return ErrOwner
		}
		seen[b.Purpose] = true
		var publicHistory PurposeKeys
		for _, h := range g.Histories {
			if h.Purpose == b.Purpose {
				publicHistory = h
			}
		}
		keys := history.PurposeKeys(b.Purpose)
		if len(keys) != len(publicHistory.Keys) {
			return ErrOwner
		}
		matched := map[string]bool{}
		active := false
		for _, key := range keys {
			found := false
			for _, declared := range publicHistory.Keys {
				pub, e := publicBytes(declared.PublicKey)
				if e == nil && bytes.Equal(pub, key.PublicKey) && !matched[declared.Version] {
					if !signingMaterialTime(key.NotBefore) || !signingMaterialTime(key.NotAfter) {
						return ErrOwner
					}
					matched[declared.Version], found = true, true
					// Historical revoked/expired keys remain public verification
					// DATA; only the exact selected current version may sign.
					if declared.Version == b.ProviderVersion {
						active = !key.Revoked && key.KeyID == b.KeyID && key.KeyVersion == b.KeyVersion && !g.NotBefore.Before(key.NotBefore) && !g.Until.After(key.NotAfter)
					}
				}
			}
			if !found {
				return ErrOwner
			}
		}
		if !active {
			return ErrOwner
		}
	}
	return nil
}

func signingMaterialTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1000 && t.Year() <= 9999
}
