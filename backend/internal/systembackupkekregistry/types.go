// Package systembackupkekregistry owns D's persisted backup KEK facts.
// These data types confer no grant. Admission remains in the original
// BootstrapAdmission/ConfigMutation transaction and requires A's validator.
package systembackupkekregistry

import (
	"context"
	"database/sql"
	"time"

	wire "clawreef/internal/systembackupwire"
)

type DatabaseIdentity struct{ ServerUUID, Database string }

type ReferencePin struct{ IdentityHash, Version string }

// SourceRecord is a locator in an authenticated owner source, not a path or
// URL to open. Content must be resolved by that owner and verified byte-for-byte.
type SourceRecord struct {
	SourceID, RecordID, RecordVersion, ContentSHA256 string
}

type TypedReference struct {
	RawJSON []byte
	SHA256  string
}

type ProviderBinding struct {
	Endpoint, KeyName, ProviderIdentityHash, ScopeHash, CAPEMSHA256 string
	CASource                                                        SourceRecord
}

// Binding carries the security-bearing immutable core and the exact typed
// reference bytes received at admission. Redacted descriptions inside those
// bytes are provenance metadata, not part of the semantic rebinding decision;
// an existing binding row must never be overwritten to change its provenance.
// Config hashes, observation windows and source revisions belong to
// AdmissionObservation, not the binding identity.
// A distinct config may reuse exactly the same binding. Never derive the
// identity/version from a provider name, numeric version or observation hash.
type Binding struct {
	// Nil preserves the existing executable backup mapping wire. A nonnil
	// value is STRICTLY retention-only evidence provenance, never key-use grant.
	Retention      *RetainedEvidenceSource `json:",omitempty"`
	InstallationID string
	ConfigRef      ReferencePin
	Key            wire.KeyBinding
	Provider       ProviderBinding
	GenerateRef    TypedReference
	UnwrapRef      TypedReference
}

type RetainedEvidenceSource struct {
	Purpose          string
	Source           SourceRecord
	KeyContextSHA256 string
}

// Supplied only by the independently authenticated original C1 history owner.
// The actual installer entry accepts that owner's opaque concrete object;
// neither DTO fields, hashes, healthy/Passed nor this interface mint authority.
// Native work finishes before D's original transaction. Recheck is SQL-only
// over the original prelocked source/hold ranges, never a callback to probe.
type PreparedRetainedEvidenceBackfill interface {
	Bindings() []Binding
	References() []Reference
	ExpectedSnapshot() Snapshot
	ValidUntil() time.Time
	RecheckOriginalRetained(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

// AdmissionObservation records provenance, not an authorization token. The two
// capability sources do not grant a Job permission to generate or recover.
type AdmissionObservation struct {
	InstallationID, ConfigSHA256, SourceRevision     string
	MappingSource                                    SourceRecord
	GenerateCapabilitySource, UnwrapCapabilitySource SourceRecord
	NotBefore, ValidUntil                            time.Time
}

// AdmissionInput is non-authorizing comparison data from C and D. A must
// authenticate it through an INDEPENDENT original mapping source; a caller
// supplying both Candidate and its expected hash is not that source.
type AdmissionInput struct {
	Candidate   Binding
	Observation AdmissionObservation
	Snapshot    Snapshot
	Coverage    PreparedCoverage
}

// Risk describes additional original config-mutation authorization required.
// Neither field is an approval or permission to use a key.
type Risk struct{ SecurityBoundary, ProtectionReduction bool }

type Partition string

const (
	RetainedArtifacts        Partition = "retained_artifacts"
	InflightAndUnknownWrites Partition = "inflight_and_unknown_writes"
	HoldsAndCatalog          Partition = "holds_and_catalog"
	RestoreAndPrune          Partition = "restore_and_prune"
)

type Reference struct {
	Partition                                             Partition
	State                                                 ReferenceState
	SourceRecordID, SourceRecordVersion                   string
	BackupPublicID, AttemptNo, EnvelopeID                 string
	Key                                                   wire.KeyBinding
	BindingSHA256                                         string
	MappingSource, ExpectedRequestSource, LifecycleSource SourceRecord
}

type ReferenceState string

const (
	ReferencePlanned  ReferenceState = "planned"
	ReferenceUnknown  ReferenceState = "unknown"
	ReferenceRetained ReferenceState = "retained"
	ReferenceReleased ReferenceState = "released"
)

// CoverageSource names the original adoption/backfill and source receipts.
// Merely populating this DTO never establishes that writers participate.
type CoverageSource struct {
	Partition                                 Partition
	SourceID, SnapshotRevision, FenceRevision string
	AdoptionSource                            SourceRecord
}

type RevocationPurpose string

const (
	GenerateRevocation RevocationPurpose = "generate"
	UnwrapRevocation   RevocationPurpose = "unwrap"
)

// Revocation is a persisted invalidation with original provenance. Revoking
// generation never releases a reference or authorizes destroying retained keys.
type Revocation struct {
	Purpose        RevocationPurpose
	Source         SourceRecord
	SourceRevision string
	ObservedAt     time.Time
}

type BindingFacts struct {
	Binding                        Binding
	BindingSHA256                  string
	RowVersion                     uint64
	GenerateRevoked, UnwrapRevoked *Revocation
}

// Snapshot is comparison data from D's SQL fact source, not proof supplied by
// an HTTP request. Epoch is the stable fence's actual revision, not MAX(id).
// Missing coverage remains missing; nil is never converted into proven empty.
type Snapshot struct {
	Database       DatabaseIdentity
	InstallationID string
	Epoch          uint64
	ObservedAt     time.Time
	Coverage       []CoverageSource
	Bindings       []BindingFacts
	References     []Reference
}

// LockedSnapshot can only be constructed by D's bound transaction. A gets a
// defensive copy through Facts and must use the supplied original SQL time.
type LockedSnapshot struct{ facts Snapshot }

func (s LockedSnapshot) Facts() Snapshot { return cloneSnapshot(s.facts) }

// SQLReadView is scoped to the originating transaction and callback. A may
// recheck original already-locked facts, but must not acquire an earlier task,
// gate, producer or evidence lock after D's KEK fence. No network I/O or commit.
type SQLReadView interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// SQLWriteView is the original owner's already-open transaction. It exposes
// neither Commit nor Rollback, so D cannot create a second commit boundary.
type SQLWriteView interface {
	SQLReadView
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// PreparedAdmission is implemented by A, retaining its original authority and
// C's authenticated source observations. There is deliberately no allow-all
// implementation here. DTO decoding, a provider profile, or constructor success
// cannot produce it. D copies all getters and checks they remain stable.
type PreparedAdmission interface {
	Binding() Binding
	Observation() AdmissionObservation
	ExpectedSnapshot() Snapshot
	OriginalMapping() PreparedMappingSource
	Risk() Risk
	ValidUntil() time.Time
	Recheck(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

// PreparedMappingSource is prepared by A's independently configured original
// mapping authority. It authenticates the entire immutable binding, operation
// ref relationship and provenance, independently of the config pin or candidate
// hash. A pinned caller JSON file or a successful config commit is insufficient.
type PreparedMappingSource interface {
	Source() SourceRecord
	Binding() Binding
	SourceRevision() string
	ValidUntil() time.Time
	Recheck(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

// PreparedCoverage belongs to the original C/source owner with A's admission
// checks. It is required for adoption and complete scans; absent adapters fail
// closed. It must cover every writer, old history, unknown call and lifecycle
// source under the original maintenance/authorization protocol.
type PreparedCoverage interface {
	Sources() []CoverageSource
	References() []Reference
	ExpectedEpoch() uint64
	ValidUntil() time.Time
	Recheck(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

// PreparedReferenceChange retains the original Job/producer/hold/recovery/GC
// authority. A release must authenticate original cleanup/absence/protection
// facts, not a task terminal status. No default production implementation exists.
type PreparedReferenceChange interface {
	Reference() Reference
	Source() SourceRecord
	ExpectedEpoch() uint64
	ValidUntil() time.Time
	Recheck(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

// PreparedRevocation is an invalidation under the original authority, not a
// new grant endpoint. Generation and unwrap invalidations are independent.
type PreparedRevocation interface {
	Reference() ReferencePin
	Revocation() Revocation
	ExpectedEpoch() uint64
	ValidUntil() time.Time
	Recheck(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

func cloneBinding(b Binding) Binding {
	if b.Retention != nil {
		r := *b.Retention
		b.Retention = &r
	}
	b.GenerateRef.RawJSON = append([]byte(nil), b.GenerateRef.RawJSON...)
	b.UnwrapRef.RawJSON = append([]byte(nil), b.UnwrapRef.RawJSON...)
	return b
}

func cloneSnapshot(s Snapshot) Snapshot {
	if s.Coverage != nil {
		s.Coverage = append(make([]CoverageSource, 0, len(s.Coverage)), s.Coverage...)
	}
	if s.References != nil {
		s.References = append(make([]Reference, 0, len(s.References)), s.References...)
	}
	if s.Bindings != nil {
		s.Bindings = append(make([]BindingFacts, 0, len(s.Bindings)), s.Bindings...)
	}
	for i := range s.Bindings {
		s.Bindings[i].Binding = cloneBinding(s.Bindings[i].Binding)
		if r := s.Bindings[i].GenerateRevoked; r != nil {
			copy := *r
			s.Bindings[i].GenerateRevoked = &copy
		}
		if r := s.Bindings[i].UnwrapRevoked; r != nil {
			copy := *r
			s.Bindings[i].UnwrapRevoked = &copy
		}
	}
	return s
}
