package systembackupinstallationowner

import (
	"crypto/ed25519"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

const SigningResourceGrantVersion = "system-backup-original-signing-resource-grant.v1"
const SigningResourceHeadVersion = "system-backup-original-signing-resource-head.v1"
const SigningResourceGrantDomain = SigningResourceGrantVersion + "\x00"
const SigningResourceHeadDomain = SigningResourceHeadVersion + "\x00"
const SigningResourceProbeVersion = "system-backup-original-signing-resource-probe.v1"
const SigningResourceProbeDomain = SigningResourceProbeVersion + "\x00"

// Permission metadata for one EXISTING installed purpose/key/role. This is a
// distinct original owner grant; a capture-only record, configured version or
// future backup/catalog business object cannot supply this resource authority.
// No installer credential, issuer private key or provider token is serialized.
type SigningResourceGrant struct {
	SchemaVersion, AuthorityID, GrantID, PlanSHA256     string
	EnrollmentID, IssuerID, EnrollmentDocumentSHA256    string
	EnrollmentRevision, RecordRevision, PermissionEpoch uint64
	Target                                              Target
	Actor                                               Actor
	BootstrapGrantSHA256, ConfigSHA256                  string
	SigningMaterialSHA256                               string
	SigningMaterialRevision                             uint64
	Reference                                           sec.BootstrapSecretRef
	Binding                                             Binding
	// Exact installed three-purpose role/policy/key separation observations.
	// They grant NOTHING for the other two purposes; only Binding/Reference
	// select the purpose admitted by this independent SQL head/grant.
	Bindings         []Binding
	Histories        []PurposeKeys
	NotBefore, Until time.Time
}

// Current SQL head is terminal active->revoked, purpose-specific and separate
// from capture and the task business signing evidence. Revoke preserves the
// original grant bytes/window/epoch and increments only head/row revisions.
type SigningResourceHead struct {
	SchemaVersion, AuthorityID, Purpose               string
	EnrollmentID, IssuerID                            string
	EnrollmentRevision, HeadRevision, PermissionEpoch uint64
	Target                                            Target
	OwnerSubject, CurrentGrantID                      string
	CurrentGrantRevision                              uint64
	GrantSHA256, State                                string
	NotBefore, Until                                  time.Time
}

// Independently installed selected issuer/enrollment/authority/purpose tuple.
// No self-declared public key in a grant/head can create this trust pin.
type SigningResourceTrustPin struct {
	Target                                                         Target
	Actor                                                          Actor
	EnrollmentID, IssuerID, EnrollmentDocumentSHA256, OwnerSubject string
	EnrollmentRevision                                             uint64
	Issuer                                                         ed25519.PublicKey
	AuthorityID, Purpose, GrantID, GrantSHA256                     string
	GrantRevision, MinimumHeadRevision, MinimumPermissionEpoch     uint64
}

// Detached original SQL comparison data only, not a lock/permission handle.
type SigningResourceCAS struct {
	HeadRevision, HeadRowVersion, GrantRevision, GrantRowVersion uint64
	PermissionEpoch                                              uint64
	GrantID, HeadSHA256, GrantSHA256, State                      string
}

// D schema/installer owns these EXACT table and column projections. The two
// known purposes are acceptance_record and catalog_record (binary sort order).
// NO capture or task table is part of this source domain.
const SigningResourceHeadTable = "system_backup_signing_resource_heads"
const SigningResourceGrantTable = "system_backup_signing_resource_grants"

const SigningResourceHeadReadSQL = `SELECT head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_signing_resource_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? FOR SHARE`
const SigningResourceGrantReadSQL = `SELECT permission_epoch,record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_signing_resource_grants WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND grant_id=? AND record_revision=? FOR SHARE`

func SigningResourcePurposes() []string { return []string{"acceptance_record", "catalog_record"} }
func SigningResourceBootstrapPurpose(purpose string) string {
	switch purpose {
	case "acceptance_record":
		return "acceptance_signing"
	case "catalog_record":
		return "catalog_signing"
	}
	return ""
}
