package recovery

import (
	"bytes"
	"context"
	"io"
)

// These are provider evidence, not values inferred from HTTP status or LIST.
// A production adapter must validate its native proof and immutable identity.
type Observation struct {
	State      string // present, absent, unknown
	Key        string
	Object     Object
	Proof      Reference
	Strong     bool
	ValidUntil int64
}

func (o Observation) decisive(key string, now int64) bool {
	return o.Key == key && o.Proof.valid() && o.Strong && o.ValidUntil >= now && (o.State == "absent" || o.State == "present" && o.Object.valid() && o.Object.Key == key)
}

// ValidateOutcome is also called by durable journals with their database clock.
// A provider 404 or an unexpired in-flight grant cannot prove final absence.
func (o Observation) ValidateOutcome(r Request, state string, now int64) error {
	if r.Validate() != nil || now <= 0 {
		return ErrContract
	}
	if state == "provider_unreachable" {
		return nil
	}
	if !o.decisive(r.Key, now) {
		return ErrUnavailable
	}
	switch state {
	case "absent":
		if o.State == "absent" && now >= r.Deadline {
			return nil
		}
	case "present":
		if o.State == "present" && o.Object.SHA256 == r.SHA256 && o.Object.Size == r.Size {
			return nil
		}
	case "conflict":
		if o.State == "present" {
			return nil
		}
	}
	return ErrContract
}

type Reader interface {
	Open(context.Context, Object) (io.ReadCloser, error)  // exact immutable version
	Observe(context.Context, string) (Observation, error) // authoritative absence or unknown
}
type Request struct {
	ActionID   string    `json:"action_id"`
	Key        string    `json:"key"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"content_length"`
	Deadline   int64     `json:"deadline_at_ms"`
	Generation int64     `json:"dispatch_generation"`
	Condition  string    `json:"condition"`
	Payload    []byte    `json:"canonical_bytes"`
	Target     Reference `json:"provider_identity"`
}

func (r Request) Validate() error {
	if !validID(r.ActionID) || !safeKey(r.Key) || !digest(r.SHA256) || r.Size != int64(len(r.Payload)) || r.Size <= 0 || r.Size > MaxDocument || Hash(r.Payload) != r.SHA256 || r.Deadline <= 0 || r.Generation < 1 || r.Condition != "create-if-absent" {
		return ErrContract
	}
	if canonical, e := Canonical(r.Payload); e != nil || !bytes.Equal(canonical, r.Payload) {
		return ErrContract
	}
	if r.Target != (Reference{}) && !r.Target.valid() {
		return ErrContract
	}
	return nil
}

type AppendProvider interface {
	Reader
	Identity() Reference // immutable provider role/root/policy identity, no secrets
	Location() Locator   // exact bound root; must not depend on the requested document
	// Must use native conditional create with key/checksum/length/expiry bound
	// grants, never a general overwrite credential. Provider rejects late writes.
	Create(context.Context, Request) (Observation, error)
}
type Capability struct {
	Role, Code, Status    string
	Identity              Reference
	ObservedAt, ExpiresAt int64
}
type ProviderConfig struct {
	Provider      string     `json:"provider"`
	Root          Locator    `json:"root"`
	DiscoveryMode string     `json:"discovery_mode"`
	Read          Reference  `json:"read_credential"`
	Append        Reference  `json:"append_credential"`
	Discovery     *Reference `json:"discovery_credential,omitempty"`
}

func (c ProviderConfig) Validate() error {
	if c.Provider != "s3" || !c.Root.valid() || !c.Read.valid() || !c.Append.valid() || c.Read.ID == c.Append.ID {
		return ErrContract
	}
	switch c.DiscoveryMode {
	case "provider_snapshot", "inventory_manifest":
		if c.Discovery == nil || !c.Discovery.valid() || c.Discovery.ID == c.Append.ID {
			return ErrContract
		}
	case "known_record_only":
	default:
		return ErrContract
	}
	return nil
}

// RequireCapabilities matches CURRENT identity/time. Missing/unknown/stale is
// not success; the two discovery and two absence mechanisms are alternatives.
func RequireCapabilities(c []Capability, identity Reference, now int64, appendWrite, fullScan bool) error {
	if !identity.valid() || now <= 0 {
		return ErrContract
	}
	have := map[string]bool{}
	for _, v := range c {
		if v.Role != "catalog" || v.Identity != identity {
			continue
		}
		if v.Status != "supported" || v.ObservedAt > now || v.ExpiresAt <= now || have[v.Code] {
			return ErrUnavailable
		}
		have[v.Code] = true
	}
	for _, code := range []string{"scoped_read_credential", "tls_verified"} {
		if !have[code] {
			return ErrUnavailable
		}
	}
	if !have["strong_read_after_write"] && !have["versioned_absence_proof"] {
		return ErrUnavailable
	}
	if appendWrite {
		for _, code := range []string{"conditional_create", "checksum_bound_request", "content_length_bound_request", "native_deadline_enforced", "scoped_append_credential"} {
			if !have[code] {
				return ErrUnavailable
			}
		}
	}
	if fullScan && !have["provider_snapshot_listing"] && !have["inventory_manifest_listing"] {
		return ErrUnavailable
	}
	return nil
}

type Snapshot struct {
	ID            string
	Mode          string
	Root          Reference
	Count         int64
	RecordsSHA256 string
	ExpiresAt     int64
}
type Page struct {
	SnapshotID   string
	Number       int64
	Cursor, Next string
	Objects      []Object
}
type Discovery interface {
	Reader
	Begin(context.Context, int64) (Snapshot, error)
	Page(context.Context, Snapshot, string, int64) (Page, error)
}

// Source adapters intentionally separate capture, normalization and verification
// credentials. Implementations may not receive a shared write-capable client.
type CaptureRequest struct {
	Task                 string
	Attempt              int64
	Deadline             int64
	Config               Reference
	CaptureContextSHA256 string
}

func (r CaptureRequest) Validate() error {
	if !validID(r.Task) || r.Attempt < 1 || r.Deadline <= 0 || !r.Config.valid() || !digest(r.CaptureContextSHA256) {
		return ErrContract
	}
	return nil
}

type PartResult struct {
	Schema, Part, Status string
	Consistency          string
	Checkpoint           Reference
	Objects              []Object
	Warnings             []Warning
}
type Collector interface {
	Capture(context.Context, CaptureRequest) (PartResult, error)
}
type RestoreTarget struct {
	ID, Namespace, Database string
	Isolation               Reference
}
type NormalizationPolicy struct {
	Version     string
	RulesSHA256 string
}
type Normalizer interface {
	Normalize(context.Context, RestoreTarget, NormalizationPolicy) (Reference, error)
}
type ReadOnlyTarget struct {
	ID             string
	ReadCredential Reference
	Isolation      Reference
}
type Verifier interface {
	Verify(context.Context, ReadOnlyTarget, string) (Summary, error)
}
