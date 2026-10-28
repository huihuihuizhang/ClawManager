// Package systembackupproducer implements the C1 internal data contract and
// guarded SQL transaction boundary. Records are not authentication credentials.
// There is no default producer authority, provider adapter or runtime wiring.
package systembackupproducer

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

var (
	ErrInvalid       = errors.New("producer_invalid_record")
	ErrUnavailable   = errors.New("producer_unavailable")
	ErrExpired       = errors.New("producer_authority_expired")
	ErrConflict      = errors.New("producer_cas_conflict")
	ErrCommitUnknown = errors.New("producer_commit_unknown")
	ErrGuardRequired = errors.New("producer_final_guard_required")
)

type Hash string
type ID string
type EvidenceID string
type Installation string
type ServerUUID string
type Database string
type Text string
type ProviderVersion string
type RefVersion string
type RequestKey string
type RelativeKey string
type Counter string
type ZeroCounter string
type Timestamp string
type Role string
type Purpose string
type Owner string

// Uint64 and SQLInt64 never round via float64 or silently wrap a legacy BIGINT.
func (c Counter) Uint64() (uint64, error)     { return parseCounter(string(c), false) }
func (c ZeroCounter) Uint64() (uint64, error) { return parseCounter(string(c), true) }
func (c Counter) SQLInt64() (int64, error) {
	v, err := c.Uint64()
	if err != nil || v > 1<<63-1 {
		return 0, ErrInvalid
	}
	return int64(v), nil
}
func parseCounter(s string, zero bool) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	v, e := strconv.ParseUint(s, 10, 64)
	if e != nil || (!zero && v == 0) {
		return 0, ErrInvalid
	}
	return v, nil
}

const timeLayout = "2006-01-02T15:04:05.000000Z"

func (s Timestamp) Time() (time.Time, error) {
	t, e := time.Parse(timeLayout, string(s))
	if e != nil || t.Year() < 1000 || t.Year() > 9999 || t.Format(timeLayout) != string(s) {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

type Scope struct {
	ServerUUID   ServerUUID   `json:"server_uuid"`
	Database     Database     `json:"database"`
	Installation Installation `json:"installation"`
}
type UnconfiguredAdmission struct {
	Scenario              string `json:"scenario"`
	DeploymentAdmissionID ID     `json:"deployment_admission_id"`
	CandidateHash         Hash   `json:"candidate_hash"`
	RegistrySetHash       Hash   `json:"registry_set_hash"`
	RefSetHash            Hash   `json:"ref_set_hash"`
	PolicyHash            Hash   `json:"policy_hash"`
	ChannelProfileHash    Hash   `json:"channel_profile_hash"`
}
type ConfiguredAdmission struct {
	Scenario           string  `json:"scenario"`
	CheckAdmissionID   ID      `json:"check_admission_id"`
	ConfigVersion      Counter `json:"config_version"`
	ConfigHash         Hash    `json:"config_hash"`
	RegistrySetHash    Hash    `json:"registry_set_hash"`
	RefSetHash         Hash    `json:"ref_set_hash"`
	PolicyHash         Hash    `json:"policy_hash"`
	ChannelProfileHash Hash    `json:"channel_profile_hash"`
}

// Admission is a data union, not a handle. Exactly one branch must be present.
type Admission struct {
	Unconfigured *UnconfiguredAdmission
	Configured   *ConfiguredAdmission
}

func (a Admission) MarshalJSON() ([]byte, error) {
	if a.Unconfigured != nil && a.Configured == nil {
		return json.Marshal(a.Unconfigured)
	}
	if a.Configured != nil && a.Unconfigured == nil {
		return json.Marshal(a.Configured)
	}
	return nil, ErrInvalid
}
func (a *Admission) UnmarshalJSON(raw []byte) error {
	v, e := parseJSON(raw)
	if e != nil {
		return e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	var next Admission
	switch m["scenario"] {
	case "unconfigured":
		next.Unconfigured = &UnconfiguredAdmission{}
		e = decodeObject(raw, next.Unconfigured)
	case "disabled", "enabled":
		next.Configured = &ConfiguredAdmission{}
		e = decodeObject(raw, next.Configured)
	default:
		return ErrInvalid
	}
	if e == nil {
		*a = next
	}
	return e
}

type Target struct {
	EvaluatorOwner       Owner           `json:"evaluator_owner"`
	EvaluatorProfileHash Hash            `json:"evaluator_profile_hash"`
	Role                 Role            `json:"role"`
	IdentityHash         Hash            `json:"identity_hash"`
	RefVersion           ProviderVersion `json:"ref_version"`
	ProbeScopeHash       Hash            `json:"probe_scope_hash"`
	ResultSlots          []ID            `json:"result_slots"`
}
type ServiceHost struct {
	Kind                 string `json:"kind"`
	WorkloadIdentityHash Hash   `json:"workload_identity_hash"`
}
type JobHost struct {
	Kind                 string  `json:"kind"`
	WorkloadIdentityHash Hash    `json:"workload_identity_hash"`
	ClusterIdentityHash  Hash    `json:"cluster_identity_hash"`
	NamespaceUID         ID      `json:"namespace_uid"`
	JobUID               ID      `json:"job_uid"`
	Generation           Counter `json:"generation"`
}
type Host struct {
	Service *ServiceHost
	Job     *JobHost
}

func (h Host) MarshalJSON() ([]byte, error) {
	if h.Service != nil && h.Job == nil {
		return json.Marshal(h.Service)
	}
	if h.Job != nil && h.Service == nil {
		return json.Marshal(h.Job)
	}
	return nil, ErrInvalid
}
func (h *Host) UnmarshalJSON(raw []byte) error {
	v, e := parseJSON(raw)
	if e != nil {
		return e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	var next Host
	switch m["kind"] {
	case "service":
		next.Service = &ServiceHost{}
		e = decodeObject(raw, next.Service)
	case "job":
		next.Job = &JobHost{}
		e = decodeObject(raw, next.Job)
	default:
		return ErrInvalid
	}
	if e == nil {
		*h = next
	}
	return e
}

type EvidenceBinding struct {
	EvidenceID          EvidenceID   `json:"evidence_id"`
	OwnerType           string       `json:"owner_type"`
	OwnerID             Installation `json:"owner_id"`
	EvidenceType        string       `json:"evidence_type"`
	Classification      string       `json:"classification"`
	ManifestHash        Hash         `json:"manifest_hash"`
	ContentHash         Hash         `json:"content_hash"`
	ContentBytes        Counter      `json:"content_bytes"`
	ObjectHash          Hash         `json:"object_hash"`
	ObjectBytes         Counter      `json:"object_bytes"`
	StoreIdentityHash   Hash         `json:"store_identity_hash"`
	StoreRefVersion     RefVersion   `json:"store_ref_version"`
	RelativeKeyHash     Hash         `json:"relative_key_hash"`
	ImmutableVersion    *Text        `json:"immutable_version"`
	KEKIdentityHash     Hash         `json:"kek_identity_hash"`
	KEKVersion          RefVersion   `json:"kek_version"`
	WriteIdentityHash   Hash         `json:"write_identity_hash"`
	WriteRefVersion     RefVersion   `json:"write_ref_version"`
	RecoveryProfileHash Hash         `json:"recovery_profile_hash"`
}
type ProviderObservation struct {
	Slot            ID               `json:"slot"`
	Status          string           `json:"status"`
	Reason          string           `json:"reason"`
	ObservedVersion *ProviderVersion `json:"observed_version"`
}
type DependencyObservation struct {
	Slot             string `json:"slot"`
	Status           string `json:"status"`
	Reason           string `json:"reason"`
	ObservedVersion  *Text  `json:"observed_version"`
	ObservedChecksum *Hash  `json:"observed_checksum"`
}
type ProviderResults struct {
	Kind         string                `json:"kind"`
	Observations []ProviderObservation `json:"observations"`
}
type DependencyResults struct {
	Kind         string                  `json:"kind"`
	Observations []DependencyObservation `json:"observations"`
}
type Results struct {
	Provider   *ProviderResults
	Dependency *DependencyResults
}

func (r Results) MarshalJSON() ([]byte, error) {
	if r.Provider != nil && r.Dependency == nil {
		return json.Marshal(r.Provider)
	}
	if r.Dependency != nil && r.Provider == nil {
		return json.Marshal(r.Dependency)
	}
	return nil, ErrInvalid
}
func (r *Results) UnmarshalJSON(raw []byte) error {
	v, e := parseJSON(raw)
	if e != nil {
		return e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ErrInvalid
	}
	var next Results
	switch m["kind"] {
	case "provider":
		next.Provider = &ProviderResults{}
		e = decodeObject(raw, next.Provider)
	case "dependency":
		next.Dependency = &DependencyResults{}
		e = decodeObject(raw, next.Dependency)
	default:
		return ErrInvalid
	}
	if e == nil {
		*r = next
	}
	return e
}

type ResultRequest struct {
	SchemaVersion           string          `json:"schema_version"`
	Scope                   Scope           `json:"scope"`
	GrantID                 ID              `json:"grant_id"`
	GrantGeneration         Counter         `json:"grant_generation"`
	RunID                   ID              `json:"run_id"`
	DomainEpoch             Counter         `json:"domain_epoch"`
	Admission               Admission       `json:"admission"`
	Purpose                 Purpose         `json:"purpose"`
	Target                  Target          `json:"target"`
	InputHash               Hash            `json:"input_hash"`
	RequestKey              RequestKey      `json:"request_key"`
	TargetGeneration        Counter         `json:"target_generation"`
	ExpectedResultVersion   ZeroCounter     `json:"expected_result_version"`
	Evidence                EvidenceBinding `json:"evidence"`
	ExpectedEvidenceVersion Counter         `json:"expected_evidence_version"`
	ObservedAt              Timestamp       `json:"observed_at"`
	ObservationExpiresAt    Timestamp       `json:"observation_expires_at"`
	Results                 Results         `json:"results"`
}
type CommandExpected struct {
	GrantID          ID      `json:"grant_id"`
	GrantGeneration  Counter `json:"grant_generation"`
	GrantRowVersion  Counter `json:"grant_row_version"`
	RunID            ID      `json:"run_id"`
	TargetGeneration Counter `json:"target_generation"`
}
type CommandNext struct {
	GrantID                ID         `json:"grant_id"`
	GrantGeneration        Counter    `json:"grant_generation"`
	RunID                  ID         `json:"run_id"`
	EvidenceID             EvidenceID `json:"evidence_id"`
	SubjectIdentityHash    Hash       `json:"subject_identity_hash"`
	IssuerIdentityHash     Hash       `json:"issuer_identity_hash"`
	Host                   Host       `json:"host"`
	Admission              Admission  `json:"admission"`
	Purpose                Purpose    `json:"purpose"`
	InputHash              Hash       `json:"input_hash"`
	AuthorizationExpiresAt Timestamp  `json:"authorization_expires_at"`
	OwnerWriteExpiresAt    Timestamp  `json:"owner_write_expires_at"`
}
type CommandRequest struct {
	SchemaVersion            string           `json:"schema_version"`
	Scope                    Scope            `json:"scope"`
	ActorIdentityHash        Hash             `json:"actor_identity_hash"`
	Command                  string           `json:"command"`
	RequestKey               RequestKey       `json:"request_key"`
	Target                   Target           `json:"target"`
	ExpectedDomainEpoch      Counter          `json:"expected_domain_epoch"`
	ExpectedTargetGeneration ZeroCounter      `json:"expected_target_generation"`
	Expected                 *CommandExpected `json:"expected"`
	Next                     *CommandNext     `json:"next"`
	LeaseExpiresAt           *Timestamp       `json:"lease_expires_at"`
	TerminationDecisionHash  *Hash            `json:"termination_decision_hash"`
}
type DomainRecord struct {
	Scope              Scope     `json:"scope"`
	Epoch              Counter   `json:"epoch"`
	RowVersion         Counter   `json:"row_version"`
	State              string    `json:"state"`
	IssuerIdentityHash Hash      `json:"issuer_identity_hash"`
	Admission          Admission `json:"admission"`
	AdmissionExpiresAt Timestamp `json:"admission_expires_at"`
	CreatedAt          Timestamp `json:"created_at"`
	UpdatedAt          Timestamp `json:"updated_at"`
}
type GrantRecord struct {
	Scope                  Scope     `json:"scope"`
	GrantID                ID        `json:"grant_id"`
	Generation             Counter   `json:"generation"`
	DomainEpoch            Counter   `json:"domain_epoch"`
	RowVersion             Counter   `json:"row_version"`
	State                  string    `json:"state"`
	SubjectIdentityHash    Hash      `json:"subject_identity_hash"`
	IssuerIdentityHash     Hash      `json:"issuer_identity_hash"`
	Host                   Host      `json:"host"`
	Admission              Admission `json:"admission"`
	Purpose                Purpose   `json:"purpose"`
	Target                 Target    `json:"target"`
	LeaseExpiresAt         Timestamp `json:"lease_expires_at"`
	AuthorizationExpiresAt Timestamp `json:"authorization_expires_at"`
	CreatedAt              Timestamp `json:"created_at"`
}
type RunRecord struct {
	Scope                Scope      `json:"scope"`
	RunID                ID         `json:"run_id"`
	GrantID              ID         `json:"grant_id"`
	GrantGeneration      Counter    `json:"grant_generation"`
	TargetHash           Hash       `json:"target_hash"`
	TargetGeneration     Counter    `json:"target_generation"`
	InputHash            Hash       `json:"input_hash"`
	EvidenceID           EvidenceID `json:"evidence_id"`
	OwnerWriteExpiresAt  Timestamp  `json:"owner_write_expires_at"`
	ObservedAt           *Timestamp `json:"observed_at"`
	ObservationExpiresAt *Timestamp `json:"observation_expires_at"`
	State                string     `json:"state"`
	RowVersion           Counter    `json:"row_version"`
}
type TargetRecord struct {
	Scope         Scope       `json:"scope"`
	TargetHash    Hash        `json:"target_hash"`
	Target        Target      `json:"target"`
	Generation    Counter     `json:"generation"`
	CurrentRunID  ID          `json:"current_run_id"`
	ResultVersion ZeroCounter `json:"result_version"`
	RowVersion    Counter     `json:"row_version"`
}
type HistoricalBindingRecord struct {
	Scope                Scope           `json:"scope"`
	RunID                ID              `json:"run_id"`
	GrantID              ID              `json:"grant_id"`
	GrantGeneration      Counter         `json:"grant_generation"`
	DomainEpoch          Counter         `json:"domain_epoch"`
	Admission            Admission       `json:"admission"`
	TargetHash           Hash            `json:"target_hash"`
	InputHash            Hash            `json:"input_hash"`
	Evidence             EvidenceBinding `json:"evidence"`
	RelativeKey          RelativeKey     `json:"relative_key"`
	OwnerWriteExpiresAt  Timestamp       `json:"owner_write_expires_at"`
	ObservedAt           Timestamp       `json:"observed_at"`
	ObservationExpiresAt Timestamp       `json:"observation_expires_at"`
	RetentionExpiresAt   Timestamp       `json:"retention_expires_at"`
	RetentionPolicyHash  Hash            `json:"retention_policy_hash"`
	CreatedAt            Timestamp       `json:"created_at"`
}
type ReceiptRecord struct {
	Scope              Scope         `json:"scope"`
	ReceiptKeyHash     Hash          `json:"receipt_key_hash"`
	RequestHash        Hash          `json:"request_hash"`
	Request            ResultRequest `json:"request"`
	ResultVersion      Counter       `json:"result_version"`
	CommittedAt        Timestamp     `json:"committed_at"`
	RetentionExpiresAt Timestamp     `json:"retention_expires_at"`
	ChargedBytes       Counter       `json:"charged_bytes"`
}
type CommandReceiptRecord struct {
	Scope              Scope           `json:"scope"`
	ReceiptKeyHash     Hash            `json:"receipt_key_hash"`
	RequestHash        Hash            `json:"request_hash"`
	Request            CommandRequest  `json:"request"`
	Outcome            CommandExpected `json:"outcome"`
	CommittedAt        Timestamp       `json:"committed_at"`
	RetentionExpiresAt Timestamp       `json:"retention_expires_at"`
	ChargedBytes       Counter         `json:"charged_bytes"`
}
type ReferenceRecord struct {
	Scope            Scope      `json:"scope"`
	EvidenceID       EvidenceID `json:"evidence_id"`
	ReferenceKind    string     `json:"reference_kind"`
	ReferenceKeyHash Hash       `json:"reference_key_hash"`
	ProtectedUntil   Timestamp  `json:"protected_until"`
	CreatedAt        Timestamp  `json:"created_at"`
}
