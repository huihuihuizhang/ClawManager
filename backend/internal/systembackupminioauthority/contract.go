// Package systembackupminioauthority declares the proposed original MinIO
// bootstrap authority wire contract for A/C/D schema alignment. It contains
// NO issuer, importer, SQL adapter, validator, callback or admission method.
// Constructing/marshalling these values confers no authorization. D must
// align actual schema/lock order before C implements the concrete lifecycle.
package systembackupminioauthority

import "time"

const (
	GrantVersion                             = "system-backup-minio-bootstrap-authority-grant.v1"
	HeadVersion                              = "system-backup-minio-bootstrap-authority-head.v1"
	GrantDomain                              = GrantVersion + "\x00"
	HeadDomain                               = HeadVersion + "\x00"
	NativeObservationProfile                 = "minio-2025-04-22-six-principal-current-source.v1"
	PermissionProfile                        = "minio-2025-04-22-builtin-flat.v2"
	MaximumObservationAgeMicroseconds uint64 = 30_000_000
	StateActive                              = "active"
	StateRevoked                             = "revoked"
)

// Digest is lowercase 64-hex SHA256 of the NAMED original bytes/profile.
// Credential file pins and AccessKey hashes are not reference identities.
// These named types do not implement validation or a trust capability.
type Digest string
type Purpose string

const (
	ArtifactDelete Purpose = "artifact_delete"
	ArtifactRead   Purpose = "artifact_read"
	ArtifactWrite  Purpose = "artifact_write"
	CatalogAppend  Purpose = "catalog_append"
	CatalogRead    Purpose = "catalog_read"
)

// Target pins the independently selected ORIGINAL database and Kubernetes
// installation. Consumer account is different from installer SQL account.
type Target struct {
	InstallationID          string
	ServerUUID              string
	Database                string
	ConsumerDatabaseAccount string
	ClusterUID              string
	Namespace               string
	NamespaceUID            string
}

// Enrollment identifies an EXISTING authenticated immutable registration, not
// a key proposed by this record. Consumers use an independently installed pin.
type Enrollment struct {
	ID                 string
	Revision           uint64
	ConfigMapName      string
	ConfigMapUID       string
	DocumentSHA256     Digest
	PlanSHA256         Digest
	IssuerID           string
	IssuerPublicSHA256 Digest
	OwnerSubject       string
	OwnerUID           string
	OwnerGroupsSHA256  Digest
}

type Actor struct {
	LocalAdminUserID         int64
	LocalAdminUsername       string
	InstallerDatabaseAccount string
}

type ObjectIdentity struct{ Name, UID string }

// Provider is finite original native identity, not a version-string assertion.
// Endpoint is exact HTTPS origin; CA/SPKI and actual upstream image/binary
// provenance must be independently selected and actually observed at Prepare.
type Provider struct {
	IdentityHash                                         Digest
	IdentityProfile                                      string
	Endpoint, Region, DeploymentID                       string
	CASHA256, SPKISHA256                                 Digest
	ServerVersion, ServerCommit                          string
	ImageProvenanceSHA256                                Digest
	Deployment, ReplicaSet, Pod, Service, ServiceAccount ObjectIdentity
	Container, ImageID, Node, NodeUID                    string
}

// Reference is one exact original descriptor/ref/account/purpose mapping.
// DescriptorSHA256 pins the existing closed security-reference bytes. Provider
// identity and scope hashes retain their reviewed original canonical profile;
// neither is invented by hashing secret bytes or a current API response.
type Reference struct {
	Purpose                          Purpose
	IdentityHash                     Digest
	IdentityVersion                  string
	DescriptorSHA256                 Digest
	IdentityProfile                  string
	ProviderIdentityHash             Digest
	ScopeSHA256                      Digest
	ScopeProfile                     string
	AccountSHA256                    Digest
	CredentialFileSHA256             Digest
	CredentialLocatorSHA256          Digest
	PolicyName                       string
	NormalizedPolicySHA256           Digest
	Bucket, Root, StagingRoot        string
	Capability                       string
	CapabilityProfile                string
	CapabilityIntentSHA256           Digest
	NotBefore, Until, ProtectedUntil time.Time
}

// PermissionSource binds the previously reviewed actual Kubernetes permission
// source without turning it into the SQL current authority. On this new route
// the SQL head is authoritative; the Kubernetes source must still match and be
// actually observed outside locks. Old v2-only readers are not a deployment of
// this new contract and cannot ignore SQL revocation.
type PermissionSource struct {
	Profile                        string
	Grant, Head                    ObjectIdentity
	GrantSHA256                    Digest
	InitialHeadSHA256              Digest
	ObserverAccountSHA256          Digest
	ObserverCredentialFileSHA256   Digest
	ObserverLocatorSHA256          Digest
	ObserverPolicyName             string
	ObserverNormalizedPolicySHA256 Digest
}

// ObservationBinding is scoped original authority to collect evidence, not
// evidence itself. No caller observation hash/Passed/Until authenticates a
// successful probe. Actual samples live in private one-shot Prepare state.
type ObservationBinding struct {
	Profile                string
	DefinitionSHA256       Digest
	CapabilityIntentSHA256 Digest
	MaximumAgeMicroseconds uint64
}

// Grant is canonical JSON + GrantDomain signature by the existing enrolled
// owner. References are exactly FIVE, in binary Purpose order, one per constant
// above, with distinct original accounts. It is a declaration of authorized
// original scope; native permission AND protocol capability must be measured.
// ConfigSHA256 binds the original disabled candidate bytes, not an active row.
type Grant struct {
	Version              string
	GrantID              string
	Epoch                uint64
	Target               Target
	Enrollment           Enrollment
	Actor                Actor
	ConfigSHA256         Digest
	BootstrapGrantSHA256 Digest
	ReferenceSetSHA256   Digest
	Provider             Provider
	PermissionSource     PermissionSource
	Observation          ObservationBinding
	References           []Reference
	NotBefore, Until     time.Time
}

// Head is canonical JSON + HeadDomain signature. Initial: Epoch=1,
// Revision=1, State=active. Revoke: same Epoch/Grant/hash/windows, Revision+1,
// State=revoked. Revoked is terminal for this initial-install contract.
type Head struct {
	Version            string
	Target             Target
	Enrollment         Enrollment
	GrantID            string
	GrantSHA256        Digest
	ReferenceSetSHA256 Digest
	Epoch, Revision    uint64
	State              string
	NotBefore, Until   time.Time
}

// Expected is a comparison/CAS declaration, never evidence of current state.
// Zero means ORIGINAL head absent. SQL must prove this under its exact unique
// key; caller values alone cannot manufacture initial-install authorization.
type Expected struct {
	Epoch, HeadRevision, HeadRowVersion, GrantRowVersion uint64
	HeadSHA256, GrantSHA256, ReferenceSetSHA256          Digest
	State                                                string
}

// SignedBundle freezes bytes before import; retries never re-sign, renew or
// repair authority. Public issuer is deliberately absent: it comes from the
// independently selected original enrollment, never this bundle.
type SignedBundle struct {
	Version                                    string
	PlanSHA256                                 Digest
	EnrollmentDocumentSHA256                   Digest
	Expected                                   Expected
	Grant, GrantSignature, Head, HeadSignature []byte
}

// These are required semantic limits, not runtime validation in this file:
// unique/canonical complete JSON; UTC microsecond SQL times; positive counters
// <= 2^53-1; original signed windows never extended; no secrets/private keys;
// no active-config/task dependency; no generic authority interface defaults.
