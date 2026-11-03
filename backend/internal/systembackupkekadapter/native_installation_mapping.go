package systembackupkekadapter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

// SignedInstallationMapping contains the EXISTING original owner record and
// raw signature imported by system-backup-kek-authority. It confers no config,
// coverage, execution, Generate or Unwrap authority on its own.
type SignedInstallationMapping struct{ Record, Signature []byte }

// SignInstallationMapping is an explicit ORIGINAL INSTALLATION OWNER action,
// with an independently pinned owner key. The fixed binding was selected by
// that owner before Observe; it is not read from a browser/config candidate or
// a committed configuration. The private observation qualifies the actual TLS
// provider and both precise permissions for that SAME binding. It cannot stand
// in for historical adoption, target classification or a backup task grant.
func (p *ObservedVaultPermissions) SignInstallationMapping(source reg.SourceRecord, revision string, until time.Time, issuer ed25519.PrivateKey) (SignedInstallationMapping, error) {
	if p == nil || p.owner == nil || p.observed.IsZero() || time.Since(p.observed) < 0 || time.Since(p.observed) > time.Minute || !until.After(time.Now()) || until.After(p.observed.Add(24*time.Hour)) || len(issuer) != ed25519.PrivateKeySize || source.SourceID == "" || len(source.SourceID) > 256 || source.RecordID == "" || len(source.RecordID) > 256 || !authorityExact(source.RecordVersion) || !authorityExact(revision) || p.generate.Operation != kms.Generate || p.unwrap.Operation != kms.Unwrap || !reflect.DeepEqual(p.generate.Binding, p.unwrap.Binding) || !reflect.DeepEqual(p.generate.Binding, p.owner.cfg.Binding) {
		return SignedInstallationMapping{}, kms.ErrPermission
	}
	canonical := ed25519.NewKeyFromSeed(issuer[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(canonical, issuer) {
		return SignedInstallationMapping{}, kms.ErrPermission
	}
	binding := p.generate.Binding
	raw, err := json.Marshal(binding)
	if err != nil {
		return SignedInstallationMapping{}, kms.ErrPermission
	}
	sum := sha256.Sum256(raw)
	source.ContentSHA256 = hex.EncodeToString(sum[:])
	record := OriginalRecord{Binding: binding, Source: source, Revision: revision, NotBefore: p.observed, Until: until}
	raw, err = json.Marshal(record)
	if err != nil {
		return SignedInstallationMapping{}, kms.ErrPermission
	}
	signature := ed25519.Sign(issuer, append([]byte("system-backup-original-kek.v1\x00"), raw...))
	// The original importer, not this API, owns the SQL/fence/CAS write. Check
	// its existing complete signed-record contract before emitting any bytes.
	if _, err := decodeOwnerRecord(raw, signature, issuer.Public().(ed25519.PublicKey)); err != nil {
		return SignedInstallationMapping{}, kms.ErrPermission
	}
	return SignedInstallationMapping{Record: raw, Signature: signature}, nil
}
