package systembackupevidence

import (
	"strconv"

	"clawreef/internal/systembackupproducer"
)

// ProducerEvidenceChannel is immutable trusted admission data, not a credential.
// D must load it under its producer locks and recheck it at the final Guard.
// A user-provided value of this struct must never authorize provider access.
type ProducerEvidenceChannel struct {
	Root                string
	Store, Write        KeyRef
	RecoveryProfileHash string
}

// PendingProducerBinding derives C1 bytes/hashes from successful local framing.
// It accepts neither a caller Manifest nor a caller manifest digest. The result
// is ordinary data: SQL admission must still bind the authenticated run, channel,
// observation, deadline and staged bytes in the same transaction.
func (p Prepared) PendingProducerBinding(channel ProducerEvidenceChannel) (systembackupproducer.EvidenceBinding, error) {
	return producerBinding(p.manifest, channel, "")
}

func producerBinding(m Manifest, c ProducerEvidenceChannel, version string) (systembackupproducer.EvidenceBinding, error) {
	var b systembackupproducer.EvidenceBinding
	i := m.Identity
	if validateManifest(m) != nil || i.OwnerType != "system" || i.Type != "capability_snapshot" || i.Media != "application/json" || i.ContentSize > MaxCapabilityContent ||
		!c.Store.valid() || !c.Write.valid() || !digestPattern.MatchString(c.RecoveryProfileHash) {
		return b, ErrIntegrity
	}
	key, err := keyFor(c.Root, i)
	if err != nil {
		return b, ErrIntegrity
	}
	if version != "" {
		if version == "null" || len(version) > 256 {
			return b, ErrIntegrity
		}
		// The current evidence table stores exact ASCII versions. Reject values
		// it cannot represent; never trim, case-fold or truncate provider bytes.
		for _, ch := range []byte(version) {
			if ch < 0x20 || ch > 0x7e {
				return b, ErrIntegrity
			}
		}
		v := systembackupproducer.Text(version)
		b.ImmutableVersion = &v
	}
	b.EvidenceID = systembackupproducer.EvidenceID(i.ID)
	b.OwnerType, b.EvidenceType, b.Classification = i.OwnerType, i.Type, i.Classification
	b.OwnerID = systembackupproducer.Installation(i.OwnerID)
	b.ManifestHash = systembackupproducer.Hash(hash(canonical(m)))
	b.ContentHash = systembackupproducer.Hash(i.ContentHash)
	b.ContentBytes = systembackupproducer.Counter(strconv.FormatInt(i.ContentSize, 10))
	b.ObjectHash = systembackupproducer.Hash(m.ObjectHash)
	b.ObjectBytes = systembackupproducer.Counter(strconv.FormatInt(m.ObjectSize, 10))
	b.StoreIdentityHash, b.StoreRefVersion = systembackupproducer.Hash(c.Store.Identity), systembackupproducer.RefVersion(c.Store.Version)
	b.RelativeKeyHash = systembackupproducer.Hash(hash([]byte(key)))
	b.KEKIdentityHash, b.KEKVersion = systembackupproducer.Hash(m.Key.Identity), systembackupproducer.RefVersion(m.Key.Version)
	b.WriteIdentityHash, b.WriteRefVersion = systembackupproducer.Hash(c.Write.Identity), systembackupproducer.RefVersion(c.Write.Version)
	b.RecoveryProfileHash = systembackupproducer.Hash(c.RecoveryProfileHash)
	return b, nil
}

// MatchProducerBinding compares ALL C1 evidence fields against a trusted locked
// registry record and channel. It is not a database loader or authorization
// check. The caller must load both under D's transaction locks; supplying a
// record copied from a request proves nothing. Ready evidence requires the
// registered exact object version. Pending/unknown/failed writes require null.
func MatchProducerBinding(r Record, channel ProducerEvidenceChannel, expected systembackupproducer.EvidenceBinding) error {
	if !validRecord(r) || !oneOf(r.State, "pending", "write_unknown", "write_failed", "ready") ||
		(r.State == "ready") != (r.Ref.ImmutableVersion != "") {
		return ErrIntegrity
	}
	key, err := keyFor(channel.Root, r.Manifest.Identity)
	if err != nil || r.Ref.RelativeKey != key || r.Ref.Identity != channel.Store.Identity || r.Ref.Version != channel.Store.Version {
		return ErrIntegrity
	}
	actual, err := producerBinding(r.Manifest, channel, r.Ref.ImmutableVersion)
	if err != nil || (actual.ImmutableVersion == nil) != (expected.ImmutableVersion == nil) {
		return ErrIntegrity
	}
	if actual.ImmutableVersion != nil && *actual.ImmutableVersion != *expected.ImmutableVersion {
		return ErrIntegrity
	}
	actual.ImmutableVersion, expected.ImmutableVersion = nil, nil
	if actual != expected {
		return ErrIntegrity
	}
	return nil
}
