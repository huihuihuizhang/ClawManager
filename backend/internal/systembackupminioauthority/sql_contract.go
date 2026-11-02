package systembackupminioauthority

// SQL-aligned proposal for D's independent three-table original owner domain.
// The earlier contract.go is retained unchanged as proposal history/shared
// metadata types. These distinct SQL domains must NOT decode its old Grant or
// Head shape, or capture/Kubernetes permission records, as SQL authority.
// This file still provides declarations only: no lifecycle or admission code.

import "time"

const (
	SQLGrantVersion     = "system-backup-minio-sql-owner-grant.v1"
	SQLHeadVersion      = "system-backup-minio-sql-owner-head.v1"
	SQLReferenceVersion = "system-backup-minio-sql-owner-ref.v1"
	SQLBundleVersion    = "system-backup-minio-sql-owner-bundle.v1"
	SQLGrantDomain      = SQLGrantVersion + "\x00"
	SQLHeadDomain       = SQLHeadVersion + "\x00"
	SQLReferenceDomain  = SQLReferenceVersion + "\x00"
	SQLActionInstall    = "install"
	SQLActionRevoke     = "revoke"
)

// SQLReferenceRecord has no GrantSHA256: that would create a digest cycle.
// Instead its exact original authority/grant/revision/epoch/config key binds
// the reference, and the signed grant names the hash of each signed-ref RAW
// RECORD. Record state changes only through the authoritative signed SQL head.
type SQLReferenceRecord struct {
	Version                         string
	AuthorityID, GrantID            string
	RecordRevision, PermissionEpoch uint64
	Target                          Target
	Enrollment                      Enrollment
	ConfigSHA256                    Digest
	Reference                       Reference
}

// SQLReferenceHash arrays are exactly five entries in binary Purpose order.
// ReferenceSetSHA256 hashes canonical JSON of this array; hashes cover exact
// canonical ref record bytes, NOT credentials, row projections or signatures.
type SQLReferenceHash struct {
	Purpose Purpose
	SHA256  Digest
}

type SQLGrant struct {
	Version                                                string
	AuthorityID, GrantID                                   string
	RecordRevision, PermissionEpoch                        uint64
	Target                                                 Target
	Enrollment                                             Enrollment
	Actor                                                  Actor
	ConfigSHA256, BootstrapGrantSHA256, ReferenceSetSHA256 Digest
	Provider                                               Provider
	PermissionSource                                       PermissionSource
	Observation                                            ObservationBinding
	References                                             []SQLReferenceHash
	NotBefore, Until                                       time.Time
}

// SQLHead indexes exactly the current_grant_* + permission_epoch columns.
// Initial: HeadRevision=RecordRevision=PermissionEpoch=1, State=active.
// Revoke: HeadRevision+1 and State=revoked; all other ORIGINAL fields/windows
// stay fixed. This version has no reactivation, grant rotation or new epoch.
type SQLHead struct {
	Version                         string
	AuthorityID                     string
	Target                          Target
	Enrollment                      Enrollment
	HeadRevision, PermissionEpoch   uint64
	CurrentGrantID                  string
	CurrentGrantRevision            uint64
	GrantSHA256, ReferenceSetSHA256 Digest
	State                           string
	NotBefore, Until                time.Time
}

// SQLTrustPin must be selected independently from actual enrolled owner import
// receipt. AuthorityID is fixed: revocation cannot be bypassed by choosing a
// new authority ID from a candidate, row, task, request or alternative startup.
type SQLTrustPin struct {
	Target                                                     Target
	Enrollment                                                 Enrollment
	AuthorityID, GrantID                                       string
	GrantRevision, MinimumHeadRevision, MinimumPermissionEpoch uint64
	GrantSHA256, ReferenceSetSHA256                            Digest
	IssuerPublic                                               []byte
}

type SQLReferenceCAS struct {
	Purpose    Purpose
	SHA256     Digest
	RowVersion uint64
}

// Exact all-or-nothing comparison tuple, not an authorization capability.
// Initial Expected is all zero/empty with no ReferenceRows; actual locked SQL
// must prove head absence. Revoke captures all five exact original row versions.
type SQLExpected struct {
	HeadRevision, PermissionEpoch, HeadRowVersion uint64
	CurrentGrantID                                string
	CurrentGrantRevision, GrantRowVersion         uint64
	HeadSHA256, GrantSHA256, ReferenceSetSHA256   Digest
	State                                         string
	ReferenceRows                                 []SQLReferenceCAS
}

type SQLSignedReference struct {
	Purpose           Purpose
	Record, Signature []byte
}

// Public issuer is intentionally absent; import uses the independent original
// Plan/enrollment public pin. Install/revoke retries use these exact frozen
// signatures/bytes, never sign again or extend bounds after a failed commit.
type SQLBundle struct {
	Version, Action                            string
	PlanSHA256, EnrollmentDocumentSHA256       Digest
	Expected                                   SQLExpected
	Grant, GrantSignature, Head, HeadSignature []byte
	References                                 []SQLSignedReference
}
