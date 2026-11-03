package systembackupinstallationowner

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"strings"
)

// Existing bootstrap signing identity profile, now with the ACTUAL distinct
// purpose. Never derive identity from key material, current health or a task.
func SigningResourceReferenceIdentity(b Binding) (string, error) {
	bootstrap := SigningResourceBootstrapPurpose(b.Purpose)
	if bootstrap == "" || !validText(b.InstallationID) || !validText(b.ProviderClusterID) || !safeName.MatchString(b.TransitMount) || !safeName.MatchString(b.KeyName) {
		return "", ErrOwner
	}
	raw, err := canonical(struct{ SchemaVersion, InstallationID, Provider, ProviderClusterID, Endpoint, TransitMount, KeyName, BootstrapPurpose, SigningPurpose string }{IdentityVersion, b.InstallationID, "vault-transit-ed25519", b.ProviderClusterID, b.Endpoint, b.TransitMount, b.KeyName, bootstrap, b.Purpose})
	if err != nil {
		return "", ErrOwner
	}
	return digest(raw), nil
}

func signingPinValid(p SigningResourceTrustPin) bool {
	if SigningResourceBootstrapPurpose(p.Purpose) == "" || !safeName.MatchString(p.AuthorityID) || !safeName.MatchString(p.Target.Namespace) || p.EnrollmentRevision > 9007199254740991 || p.Actor.UserID < 1 || p.Actor.UserID > 9007199254740991 || !validText(p.Actor.Username) || p.Actor.OwnerSubject != p.OwnerSubject || !hashPattern.MatchString(p.EnrollmentDocumentSHA256) || !hashPattern.MatchString(p.GrantSHA256) || p.MinimumPermissionEpoch != 1 || p.GrantRevision != 1 || p.MinimumHeadRevision < 1 || p.MinimumHeadRevision > 2 {
		return false
	}
	return (TrustPin{InstallationID: p.Target.InstallationID, EnrollmentID: p.EnrollmentID, IssuerID: p.IssuerID, EnrollmentRevision: p.EnrollmentRevision, MinimumHeadRevision: p.MinimumHeadRevision, Issuer: p.Issuer, ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.NamespaceUID, OwnerSubject: p.OwnerSubject, ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, DatabaseAccount: p.Target.DatabaseAccount, GrantID: p.GrantID, GrantRevision: p.GrantRevision, RecordSHA256: p.GrantSHA256}).valid()
}
func signingBindingValid(b Binding, t Target) bool {
	if b.InstallationID != t.InstallationID || b.Namespace != t.Namespace || b.NamespaceUID != t.NamespaceUID || !validText(b.ProviderClusterID) || !validText(b.PodUID) || !validText(b.ServiceAccountUID) || !validText(b.Audience) || !numericVersion(b.ProviderVersion) {
		return false
	}
	for _, name := range []string{b.KeyID, b.KeyVersion, b.TransitMount, b.KeyName, b.AuthMount, b.Role, b.Policy, b.PodName, b.ServiceAccountName, b.Namespace} {
		if !safeName.MatchString(name) || strings.EqualFold(name, "root") || strings.EqualFold(name, "default") || strings.EqualFold(name, "latest") || strings.EqualFold(name, "current") {
			return false
		}
	}
	for _, sum := range []string{b.CASHA256, b.RoleSHA256, b.PolicySHA256, b.JWTConfigSHA256} {
		if !hashPattern.MatchString(sum) {
			return false
		}
	}
	return true
}
func signingGrantValid(r SigningResourceGrant, p SigningResourceTrustPin) bool {
	if !signingPinValid(p) || r.SchemaVersion != SigningResourceGrantVersion || r.AuthorityID != p.AuthorityID || r.GrantID != p.GrantID || r.RecordRevision != p.GrantRevision || r.PermissionEpoch != p.MinimumPermissionEpoch || r.EnrollmentID != p.EnrollmentID || r.EnrollmentRevision != p.EnrollmentRevision || r.IssuerID != p.IssuerID || r.EnrollmentDocumentSHA256 != p.EnrollmentDocumentSHA256 || r.Target != p.Target || r.Actor != p.Actor || !validWindow(r.NotBefore, r.Until) || r.Binding.Purpose != p.Purpose || !signingBindingValid(r.Binding, r.Target) || len(r.Bindings) != 3 || len(r.Histories) != 3 {
		return false
	}
	for _, sum := range []string{r.PlanSHA256, r.BootstrapGrantSHA256, r.ConfigSHA256} {
		if !hashPattern.MatchString(sum) {
			return false
		}
	}
	identity, err := SigningResourceReferenceIdentity(r.Binding)
	if !hashPattern.MatchString(r.SigningMaterialSHA256) || r.SigningMaterialRevision < 1 || r.SigningMaterialRevision > 9007199254740991 {
		return false
	}
	if err != nil || r.Reference.Purpose != SigningResourceBootstrapPurpose(p.Purpose) || r.Reference.IdentityHash != identity || r.Reference.Version != r.Binding.KeyVersion {
		return false
	}
	purposes := []string{"acceptance_record", "capture_certificate", "catalog_record"}
	roles, policies, names, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	current := false
	for n, b := range r.Bindings {
		if b.Purpose != purposes[n] || !signingBindingValid(b, r.Target) || b.Endpoint != r.Binding.Endpoint || b.ProviderClusterID != r.Binding.ProviderClusterID || b.CASHA256 != r.Binding.CASHA256 || b.TransitMount != r.Binding.TransitMount || roles[b.AuthMount+"/"+b.Role] || policies[b.Policy] || names[b.KeyName] {
			return false
		}
		roles[b.AuthMount+"/"+b.Role], policies[b.Policy], names[b.KeyName] = true, true, true
		if b.Purpose == p.Purpose && b != r.Binding {
			return false
		}
		h := r.Histories[n]
		if h.Purpose != purposes[n] || h.KeyName != b.KeyName || len(h.Keys) == 0 || len(h.Keys) > 1000 {
			return false
		}
		var prior uint64
		active := false
		for _, key := range h.Keys {
			version, err := strconv.ParseUint(key.Version, 10, 32)
			pub, pe := publicBytes(key.PublicKey)
			if err != nil || pe != nil || !numericVersion(key.Version) || version <= prior || keys[key.PublicKey] || bytes.Equal(pub, p.Issuer) || !validTime(key.ProtectedUntil) || key.ProtectedUntil.Before(r.Until) {
				return false
			}
			prior, keys[key.PublicKey] = version, true
			active = active || key.Version == b.ProviderVersion
		}
		if !active {
			return false
		}
		current = current || b.Purpose == r.Binding.Purpose
	}
	return current
}

// Codec returns detached public DATA only. Current original SQL rows and the
// native observer/guard remain mandatory for any successful admission.
func InspectSigningResourceGrant(raw, signature []byte, pin SigningResourceTrustPin) (SigningResourceGrant, error) {
	var grant SigningResourceGrant
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != 64 || !signingPinValid(pin) || digest(raw) != pin.GrantSHA256 || !ed25519.Verify(pin.Issuer, append([]byte(SigningResourceGrantDomain), raw...), signature) || decodeCanonical(raw, &grant) != nil || !signingGrantValid(grant, pin) {
		return grant, ErrOwner
	}
	return grant, nil
}
func InspectSigningResourceHead(raw, signature []byte, pin SigningResourceTrustPin) (SigningResourceHead, error) {
	var head SigningResourceHead
	if len(raw) == 0 || len(raw) > 65536 || len(signature) != 64 || !signingPinValid(pin) || !ed25519.Verify(pin.Issuer, append([]byte(SigningResourceHeadDomain), raw...), signature) || decodeCanonical(raw, &head) != nil || head.SchemaVersion != SigningResourceHeadVersion || head.AuthorityID != pin.AuthorityID || head.Purpose != pin.Purpose || head.Target != pin.Target || head.EnrollmentID != pin.EnrollmentID || head.EnrollmentRevision != pin.EnrollmentRevision || head.IssuerID != pin.IssuerID || head.OwnerSubject != pin.OwnerSubject || head.HeadRevision < pin.MinimumHeadRevision || head.PermissionEpoch != pin.MinimumPermissionEpoch || head.CurrentGrantID != pin.GrantID || head.CurrentGrantRevision != pin.GrantRevision || head.GrantSHA256 != pin.GrantSHA256 || !validWindow(head.NotBefore, head.Until) || head.State != "active" && head.State != "revoked" || head.State == "active" && head.HeadRevision != 1 || head.State == "revoked" && head.HeadRevision != 2 {
		return head, ErrOwner
	}
	return head, nil
}
func EncodeSigningResourceGrant(grant SigningResourceGrant) ([]byte, error) { return canonical(grant) }
func EncodeSigningResourceHead(head SigningResourceHead) ([]byte, error)    { return canonical(head) }
