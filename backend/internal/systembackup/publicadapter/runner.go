// Package publicadapter executes B components under D's public authority. It
// has no control database, task state machine, local Vault or artifact signer.
package publicadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"clawreef/internal/systembackup/flow"
	d "clawreef/internal/systembackupdispatch"
)

const PlanVersion = "system-backup-b-plan.v1"

// Profile is an admitted READ-ONLY discovery/binding factory. Bind constructs
// local writer handles only; it must not create resources or rediscover a plan.
// The old profile.Driver is intentionally not an implementation of this type.
type Profile interface {
	Discover(context.Context, d.Input) (Discovery, error)
	BindWriters(context.Context, d.Input, Discovery) ([]flow.Writer, error)
	CheckSource(context.Context, d.Input, Discovery) error
}

type ProfileKey struct{ ID, Revision string }
type FrozenWriter struct {
	ID       string
	Original flow.State
}
type JobPart struct {
	Part, Category, InvocationSHA256 string
	InvocationJSON                   json.RawMessage
	InvocationConfigMap              string
	Intent                           d.JobIntent
}
type Discovery struct {
	Writers []FrozenWriter
	Parts   []JobPart
	Source  json.RawMessage
	// SourceSHA256 is the read-only inventory/checkpoint input digest. It is
	// neither a manifest hash nor a capture certificate.
	SourceSHA256 string
	HoldUntil    time.Time
}

// Results reads an A-authenticated immutable evidence object referenced by the
// public observation. It must verify original bytes/hash/identity, not accept a
// worker self-report. No default reader or embedded credentials are provided.
type Results interface {
	Read(context.Context, d.Authority, d.JobBinding, d.EvidenceRef) ([]byte, error)
}

// RecoveryInventory must return the COMPLETE durable intent/Job set, including
// uncertain dispatch and pause-without-ACK, under the new recovery scope. The
// current shared Ports ABI has no such read method, so it is an explicit D
// composition input, not a scan of today's power state or Input.Jobs hints.
type RecoveryInventory interface {
	Pending(context.Context, d.Authority) (RecoverySnapshot, error)
}

// RecoverySnapshot is one consistent authoritative journal read. Every planned
// unit must have either its original Job binding or an explicit Undispatched
// entry. D may attest Undispatched only after ruling out any dispatched/unknown
// create intent; absence of a currently visible Job is not that proof.
type RecoverySnapshot struct {
	Pauses       []flow.PauseRecord
	Jobs         []d.JobBinding
	Undispatched []string
}

type Dependencies struct {
	Profiles map[ProfileKey]Profile
	Results  Results
	Recovery RecoveryInventory
	// Admission verifies current owner/profile/parts/writer-registry readiness;
	// it is mandatory, even when every local dependency is non-nil.
	Admission func(context.Context, d.Input) error
	// ValidateInventory proves exact writer/part coverage against the reviewed
	// public registries, including external storage writers. Non-empty lists
	// alone are not coverage. This receives a detached copy of the plan data.
	ValidateInventory func(context.Context, d.Input, Discovery) error
	RecoveryTimeout   time.Duration
}

type runner struct{ deps Dependencies }

func nilValue(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func NewPublicRunner(deps Dependencies) (d.Runner, error) {
	if len(deps.Profiles) == 0 || nilValue(deps.Results) || nilValue(deps.Recovery) || deps.Admission == nil || deps.ValidateInventory == nil || deps.RecoveryTimeout <= 0 || deps.RecoveryTimeout > 5*time.Minute {
		return nil, d.ErrNotReady
	}
	profiles := make(map[ProfileKey]Profile, len(deps.Profiles))
	for k, p := range deps.Profiles {
		if k.ID == "" || k.Revision == "" || nilValue(p) {
			return nil, d.ErrNotReady
		}
		profiles[k] = p
	}
	deps.Profiles = profiles
	return &runner{deps}, nil
}

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var installation = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var taskID = regexp.MustCompile(`^(sbk|spf)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var unit = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:-]{0,63}$`)
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var evidenceID = regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`)
var immutableImage = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func validateInput(in d.Input, recovery bool) error {
	a := in.Authority
	if !installation.MatchString(a.InstallationID) || !taskID.MatchString(a.TaskPublicID) || a.RequestID == "" || a.ConfigVersion == 0 || !hexHash.MatchString(a.ConfigSHA256) || a.AttemptNo == 0 || a.ClaimOwner == "" || a.ClaimRowVersion == 0 || a.DeadlineAt.IsZero() || in.ProfileID == "" || in.ProfileRevision == "" || len(in.ConfigSnapshot) < 2 || len(in.ConfigSnapshot) > 262144 || !utf8.Valid(in.ConfigSnapshot) || uniqueJSON(in.ConfigSnapshot) != nil || digest(in.ConfigSnapshot) != a.ConfigSHA256 {
		return d.ErrNotReady
	}
	if (a.TaskType != "backup" || a.TaskPublicID[:4] != "sbk_" || a.Phase != "capture") && (a.TaskType != "preflight" || a.TaskPublicID[:4] != "spf_" || a.Phase != "preflight") {
		return d.ErrNotReady
	}
	if !recovery && !time.Now().Before(a.DeadlineAt) {
		return context.DeadlineExceeded
	}
	seen := map[string]bool{}
	if len(in.Jobs) > 10000 {
		return d.ErrNotReady
	}
	for _, b := range in.Jobs {
		if !validBinding(b) || seen[b.JobUnitKey] || b.RelayExpiresAt.After(a.DeadlineAt) {
			return d.ErrNotReady
		}
		seen[b.JobUnitKey] = true
	}
	return nil
}

// binding excludes renewable claim and maintenance tokens. A takeover must use
// the original attempt/config/profile/deadline; every action still checks the
// FULL current Authority via Ports, including its new claim/gate fence.
type binding struct {
	Installation, Task, Kind, Request, ConfigSHA, Phase, Profile, Revision string
	ConfigVersion, Attempt                                                 uint64
	Deadline                                                               time.Time
}

func bind(in d.Input) binding {
	a := in.Authority
	return binding{a.InstallationID, a.TaskPublicID, a.TaskType, a.RequestID, a.ConfigSHA256, a.Phase, in.ProfileID, in.ProfileRevision, a.ConfigVersion, a.AttemptNo, a.DeadlineAt.UTC()}
}

type frozen struct {
	Version string
	Binding binding
	// LocalFlowGeneration is a versioned local dispatch discriminator, fixed at
	// 1. It is NOT claim row_version, maintenance fence, or Job generation.
	LocalFlowGeneration int64
	Discovery           Discovery
}

func (r *runner) admit(ctx context.Context, in d.Input, ports d.Ports, recovery bool) (Profile, error) {
	if nilValue(ctx) || nilValue(ports) {
		return nil, d.ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return nil, classify(err)
	}
	if err := validateInput(in, recovery); err != nil {
		return nil, err
	}
	p := r.deps.Profiles[ProfileKey{in.ProfileID, in.ProfileRevision}]
	if nilValue(p) {
		return nil, d.ErrNotReady
	}
	if !recovery {
		if err := ports.Check(ctx, in.Authority); err != nil {
			return nil, classify(err)
		}
	}
	if err := r.deps.Admission(ctx, cloneInput(in)); err != nil {
		return nil, classify(err)
	}
	return p, nil
}

func (r *runner) Prepare(ctx context.Context, in d.Input, ports d.Ports) (d.Plan, error) {
	p, err := r.admit(ctx, in, ports, false)
	if err != nil {
		return d.Plan{}, err
	}
	bounded, cancel := context.WithDeadline(ctx, in.Authority.DeadlineAt)
	defer cancel()
	discovered, err := p.Discover(bounded, cloneInput(in))
	if err != nil {
		return d.Plan{}, classify(err)
	}
	if err := validateDiscovery(in, discovered); err != nil {
		return d.Plan{}, err
	}
	if in.Authority.TaskType == "backup" && !freshInvocations(discovered) {
		return d.Plan{}, &Failure{"deadline_exceeded"}
	}
	if err := r.guardInventory(bounded, in, discovered); err != nil {
		return d.Plan{}, err
	}
	if err := ports.Check(bounded, in.Authority); err != nil {
		return d.Plan{}, classify(err)
	}
	if err := bounded.Err(); err != nil {
		return d.Plan{}, classify(err)
	}
	raw, err := json.Marshal(frozen{PlanVersion, bind(in), 1, discovered})
	if err != nil || len(raw) > 4<<20 {
		return d.Plan{}, d.ErrNotReady
	}
	plan := d.Plan{SchemaVersion: PlanVersion, CanonicalJSON: raw, SHA256: digest(raw)}
	if _, err := loadPlan(in, plan); err != nil {
		return d.Plan{}, err
	}
	return plan, nil
}

func (r *runner) guardInventory(ctx context.Context, in d.Input, x Discovery) error {
	detached, err := copyDiscovery(x)
	if err != nil {
		return err
	}
	return classify(r.deps.ValidateInventory(ctx, cloneInput(in), detached))
}

func copyDiscovery(x Discovery) (Discovery, error) {
	raw, err := json.Marshal(x)
	var out Discovery
	if err != nil || decodeStrict(raw, &out) != nil {
		return out, d.ErrNotReady
	}
	return out, nil
}

func decodeStrict(raw []byte, v any) error {
	if !utf8.Valid(raw) || uniqueJSON(raw) != nil {
		return d.ErrNotReady
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return d.ErrNotReady
	}
	return nil
}

// Required public objects use exact wire property names. encoding/json alone
// accepts case-insensitive aliases, which could otherwise override a second
// spelling of a signed/hashed field. Do not apply this to embedded K8s structs.
func decodeRequiredObject(raw []byte, v any) error {
	typ := reflect.TypeOf(v).Elem()
	var fields map[string]json.RawMessage
	if typ.Kind() != reflect.Struct || json.Unmarshal(raw, &fields) != nil || len(fields) != typ.NumField() {
		return d.ErrNotReady
	}
	for i := 0; i < typ.NumField(); i++ {
		if _, ok := fields[typ.Field(i).Tag.Get("json")]; !ok {
			return d.ErrNotReady
		}
	}
	return decodeStrict(raw, v)
}

func uniqueJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return d.ErrNotReady
		}
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || keys[s] {
					return d.ErrNotReady
				}
				keys[s] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return d.ErrNotReady
		}
		_, err = dec.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return d.ErrNotReady
	}
	return nil
}

func loadPlan(in d.Input, p d.Plan) (frozen, error) {
	var f frozen
	if validateInput(in, true) != nil {
		return f, d.ErrNotReady
	}
	if p.SchemaVersion != PlanVersion || len(p.CanonicalJSON) == 0 || len(p.CanonicalJSON) > 4<<20 || !hexHash.MatchString(p.SHA256) || digest(p.CanonicalJSON) != p.SHA256 || decodeStrict(p.CanonicalJSON, &f) != nil || f.Version != PlanVersion || f.Binding != bind(in) || f.LocalFlowGeneration != 1 {
		return f, d.ErrNotReady
	}
	canonical, err := json.Marshal(f)
	if err != nil || !bytes.Equal(canonical, p.CanonicalJSON) {
		return f, d.ErrNotReady
	}
	return f, validateDiscovery(in, f.Discovery)
}

func validateDiscovery(in d.Input, x Discovery) error {
	if !hexHash.MatchString(x.SourceSHA256) || len(x.Source) == 0 || !json.Valid(x.Source) || digest(x.Source) != x.SourceSHA256 || len(x.Writers) > 10000 || len(x.Parts) == 0 || len(x.Parts) > 10000 || x.HoldUntil.IsZero() || x.HoldUntil.After(in.Authority.DeadlineAt) {
		return d.ErrNotReady
	}
	seen := map[string]bool{}
	for _, w := range x.Writers {
		if w.ID == "" || seen[w.ID] || w.Original.UID == "" || w.Original.Generation <= 0 {
			return d.ErrNotReady
		}
		seen[w.ID] = true
	}
	seen = map[string]bool{}
	units := map[string]bool{}
	names := map[string]bool{}
	configMaps := map[string]bool{}
	indices := map[uint32]bool{}
	for _, p := range x.Parts {
		if !unit.MatchString(p.Part) || !unit.MatchString(p.Category) || seen[p.Part] {
			return d.ErrNotReady
		}
		seen[p.Part] = true
		if in.Authority.TaskType == "preflight" {
			if len(x.Parts) != 1 || p.Part != "source_inventory" || p.Category != "preflight" || p.InvocationSHA256 != "" || (len(p.InvocationJSON) != 0 && !bytes.Equal(p.InvocationJSON, []byte("null"))) || p.InvocationConfigMap != "" || (len(p.Intent.SpecJSON) != 0 && !bytes.Equal(p.Intent.SpecJSON, []byte("null"))) {
				return d.ErrNotReady
			}
			continue
		}
		if !hexHash.MatchString(p.InvocationSHA256) || !validIntent(p.Intent, in.Authority.TaskPublicID) || !validWorkerPart(in, p, x.HoldUntil) || units[p.Intent.JobUnitKey] || names[p.Intent.Namespace+"/"+p.Intent.Name] {
			return d.ErrNotReady
		}
		idx, err := invocationIndex(p)
		if err != nil || indices[idx] || configMaps[p.Intent.Namespace+"/"+p.InvocationConfigMap] {
			return d.ErrNotReady
		}
		indices[idx] = true
		configMaps[p.Intent.Namespace+"/"+p.InvocationConfigMap] = true
		units[p.Intent.JobUnitKey] = true
		names[p.Intent.Namespace+"/"+p.Intent.Name] = true
	}
	return nil
}

func cloneInput(in d.Input) d.Input {
	in.ConfigSnapshot = bytes.Clone(in.ConfigSnapshot)
	in.Jobs = append([]d.JobBinding(nil), in.Jobs...)
	if in.Backup != nil {
		b := *in.Backup
		b.RequestedParts = append([]string(nil), b.RequestedParts...)
		in.Backup = &b
	}
	return in
}

// DescribePlan exposes a detached copy of the SAME persisted plan for D to
// materialize public ConfigMap/grant intents. It grants no execution authority.
func DescribePlan(in d.Input, p d.Plan) (Discovery, error) {
	f, err := loadPlan(in, p)
	if err != nil {
		return Discovery{}, err
	}
	return copyDiscovery(f.Discovery)
}

func identity(in d.Input) flow.Identity {
	return flow.Identity{Task: in.Authority.TaskPublicID, Attempt: strconv.FormatUint(in.Authority.AttemptNo, 10), Phase: in.Authority.Phase, Generation: 1}
}

// Failure contains only the public category; driver/provider error text never
// crosses this boundary. Original failures may be logged by their owner.
type Failure struct{ Category string }

func (e *Failure) Error() string {
	if !failureCategories[e.Category] {
		return "runner_failed"
	}
	return e.Category
}

var failureCategories = map[string]bool{"permission_denied": true, "writer_registry_drift": true, "isolation_invalid": true, "unsupported_profile_p1": true, "quiesce_timeout": true, "quiesce_resume_failed": true, "runner_failed": true, "checksum_mismatch": true, "fencing_token_lost": true, "coordination_invalid": true, "control_evidence_invalid": true, "deadline_exceeded": true}

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, flow.ErrResume) {
		return &Failure{"quiesce_resume_failed"}
	}
	var f *Failure
	if errors.As(err, &f) && failureCategories[f.Category] {
		return &Failure{f.Category}
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return &Failure{"deadline_exceeded"}
	case errors.Is(err, flow.ErrJournal):
		return &Failure{"coordination_invalid"}
	case errors.Is(err, flow.ErrQuiesce):
		return &Failure{"quiesce_timeout"}
	case errors.Is(err, d.ErrNotReady), errors.Is(err, flow.ErrNotReady):
		return d.ErrNotReady
	default:
		return &Failure{"runner_failed"}
	}
}

var _ d.Runner = (*runner)(nil)
