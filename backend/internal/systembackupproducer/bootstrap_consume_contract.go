package systembackupproducer

import (
	"context"
	"database/sql"
	"time"
)

// BootstrapCandidateSelection is comparison data, never a bootstrap grant.
// The constructor-fixed A authority authenticates the complete original
// purpose/reference/mapping to receipt relationship, including allowed aliases.
type BootstrapCandidateSelection struct {
	Purpose               string
	ReferenceIdentityHash Hash
	ReferenceVersion      RefVersion
	MappingHash           Hash
	Request               ResultRequest
	ResultVersion         Counter
}

// BootstrapConsumptionRequest binds all original grant semantics through
// OfflineGrantHash and preserves each purpose-to-candidate association. The
// original trusted deployment must select the exact config/set digest profile.
// Operation IDs are deliberately absent: a generated insertion ID does not
// change the stable request identity used to resolve an uncertain commit.
type BootstrapConsumptionRequest struct {
	Scope                                   Scope
	OfflineGrantHash                        Hash
	ConfigHash, RegistrySetHash, RefSetHash Hash
	ActorID                                 Counter
	Username, MatrixKey                     string
	Endpoint, IdempotencyKey                string
	Candidates                              []BootstrapCandidateSelection
}

// BootstrapSQL has one controlled clock. Every authoritative A/D SQL-time
// observation in this path must use SampleTime; raw SELECT clock scans are not
// intercepted. This capability exposes neither Commit nor Rollback.
type BootstrapSQL interface {
	SQL
	SampleTime(context.Context) (time.Time, error)
}

type BootstrapReadSQL interface {
	ReadSQL
	SampleTime(context.Context) (time.Time, error)
}

// BootstrapConsumptionEnvironment is a trusted assembly dependency. It must
// authenticate the original offline/deployment mapping independently; it is not
// selected from a request, a generic Policy, or an approved boolean.
type BootstrapConsumptionEnvironment interface {
	PrepareBootstrapConsumption(context.Context, BootstrapConsumptionRequest) (PreparedBootstrapAuthority, error)
}

type PreparedBootstrapAuthority struct {
	Session            BootstrapConsumptionSession
	OperationPublicID  string
	CapacityObservedAt *time.Time
}

func (PreparedBootstrapAuthority) String() string               { return "PreparedBootstrapAuthority" }
func (PreparedBootstrapAuthority) GoString() string             { return "PreparedBootstrapAuthority" }
func (PreparedBootstrapAuthority) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*PreparedBootstrapAuthority) UnmarshalJSON([]byte) error  { return ErrInvalid }

type BootstrapConsumptionAdmission struct {
	BindingHash                            Hash
	IdentityExpiresAt, DependencyExpiresAt Timestamp
}

// BootstrapOperation is observed SQL state, not authorization. Found only
// selects an exact historical-read branch after current A authority succeeds.
type BootstrapOperation struct {
	Found       bool
	PublicID    string
	RequestHash Hash
	Status      string
	Version     int64
	HTTPStatus  int
}

type BootstrapConsumptionFacts struct {
	Domain     DomainRecord
	Admission  BootstrapConsumptionAdmission
	Operation  BootstrapOperation
	Candidates []ResultFacts
	Replayed   bool
	Write      BootstrapWriteResult
}

// SQL-generated audit IDs identify the two rows already inserted/locked by A,
// so fixed final readback does not discover or lock a new audit range.
type BootstrapWriteResult struct{ IntentAuditID, ResultAuditID int64 }

// All stages use the original caller transaction. No stage may perform remote
// I/O, acquire a new earlier-layer lock, create an execution handle, commit, or
// renew the original observation. Prepare must retain the original selection
// even when its domain is now closed or its observation has expired: L3 decides
// historical read versus first consumption, before new-consume freshness checks.
type BootstrapConsumptionSession interface {
	// L0 and A installation/config L1, including complete absence ranges.
	LockInstallation(context.Context, BootstrapSQL, BootstrapConsumptionRequest) error
	// L2: current offline/admin/RBAC plus independently trusted original mapping.
	Authorize(context.Context, BootstrapSQL, BootstrapConsumptionRequest, DomainRecord, time.Time) (BootstrapConsumptionAdmission, error)
	// L3 A operation key and new public-ID absence range; D locks receipts next.
	LockOperation(context.Context, BootstrapSQL, BootstrapConsumptionRequest, Hash, string) (BootstrapOperation, error)
	// L4 and L5 respectively: each receives the complete batch, once.
	LockHosts(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error
	LockReferences(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error
	// L6 original metadata capacity reservation, no fabricated release.
	Reserve(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error
	// L7 intent, L8 evidence/chunks in public-ID order, L9 config/operation/result
	// audit writes. All affected A/FK keys must already belong to the prefix.
	AuditIntent(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) error
	LockEvidence(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts) ([]ResultEvidence, error)
	WriteBootstrap(context.Context, BootstrapSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts, string, Hash, time.Time) (BootstrapWriteResult, error)
	// Runs at the end of Work, after writes/audits and after the public write
	// capability is closed, before D's separate SQL-only fixed FinalGuard.
	// Check only already-held SQL ranges and original controlled exact local
	// file sources; no provider/TLS/network, new business locks, or renewal.
	// All callbacks finish before independent readback and final time/context.
	Recheck(context.Context, BootstrapReadSQL, BootstrapConsumptionRequest, BootstrapConsumptionFacts, time.Time) error
}

type BootstrapConsumptionResult struct {
	OperationPublicID string
	Replayed          bool
}

// BootstrapCandidateConsumer never owns transaction completion. A alone begins
// RepeatableRead, calls ConsumeBootstrapInTx before taking any prefix lock,
// rolls back on error, then checks the original context and performs one commit.
type BootstrapCandidateConsumer struct {
	db          *sql.DB
	scope       Scope
	environment BootstrapConsumptionEnvironment
}

func (BootstrapCandidateConsumer) String() string               { return "BootstrapCandidateConsumer" }
func (BootstrapCandidateConsumer) GoString() string             { return "BootstrapCandidateConsumer" }
func (BootstrapCandidateConsumer) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*BootstrapCandidateConsumer) UnmarshalJSON([]byte) error  { return ErrInvalid }
