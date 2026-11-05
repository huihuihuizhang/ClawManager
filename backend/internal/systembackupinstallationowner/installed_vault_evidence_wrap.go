package systembackupinstallationowner

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	a "clawreef/internal/systembackupkekadapter"
)

// Exact original installed evidence metadata profile. Its presence is DATA,
// not producer execution/retention permission. Native roles, policies, key
// metadata and current workload are still independently read and verified.
// Optional original archive unwrap is exact-role evidence decrypt only.
// KMS Generate/Unwrap remains forbidden for this evidence key.
type InstalledVaultEvidenceWrapProfile struct {
	Transit       ev.TransitConfig
	Role          a.VaultPermissionRole
	ArchiveUnwrap *a.VaultPermissionRole `json:",omitempty"`
}

func validateInstalledEvidenceWrap(c InstalledVaultDependencyConfig) error {
	p := c.EvidenceWrap
	if p == nil || c.TransitMount != "transit" || p.Transit.Endpoint != c.Endpoint || p.Transit.CASHA256 != c.CASHA256 || !bytes.Equal(p.Transit.CAPEM, c.CAPEM) || p.Transit.KeyName == c.PinnedKeyName || p.Transit.KeyVersion != 1 || p.Transit.Key.Version != "1" || p.Role.AuthMount != c.JWTMount || p.Role.PodUID == "" || p.Role.Workload != nil {
		return ErrOwner
	}
	if _, err := a.EvidenceVaultRuntimeACL(p.Transit, ev.TransitWrap); err != nil {
		return ErrOwner
	}
	if _, err := a.VaultJWTAuthRole(p.Role); err != nil {
		return ErrOwner
	}
	if r := p.ArchiveUnwrap; r != nil {
		if r.AuthMount != c.JWTMount || r.PodUID == "" || r.Workload != nil || r.Role == p.Role.Role || r.Policy == p.Role.Policy || r.Audience == p.Role.Audience || r.Namespace != p.Role.Namespace {
			return ErrOwner
		}
		if _, e := a.VaultJWTAuthRole(*r); e != nil {
			return ErrOwner
		}
	}
	return nil
}
func installedEvidenceWrapMatches(c InstalledVaultDependencyConfig, name string, raw []byte, policy string, keys []InstalledVaultKey) bool {
	if validateInstalledEvidenceWrap(c) != nil {
		return false
	}
	role, op := c.EvidenceWrap.Role, ev.TransitWrap
	if name != role.Role {
		if c.EvidenceWrap.ArchiveUnwrap == nil || name != c.EvidenceWrap.ArchiveUnwrap.Role {
			return false
		}
		role, op = *c.EvidenceWrap.ArchiveUnwrap, ev.TransitUnwrap
	}
	found := false
	for _, key := range keys {
		if key.Name == c.EvidenceWrap.Transit.KeyName && key.Type == "aes256-gcm96" && key.Latest == 1 && key.MinimumEncryption == 0 && key.MinimumDecryption == 1 && len(key.Versions) == 1 && key.Versions[0].Version == "1" {
			found = true
		}
	}
	if !found {
		return false
	}
	expected, err := a.VaultJWTAuthRole(role)
	if err != nil || !jsonSubset(raw, expected) {
		return false
	}
	acl, err := a.EvidenceVaultRuntimeACL(c.EvidenceWrap.Transit, op)
	return err == nil && policy == acl
}
