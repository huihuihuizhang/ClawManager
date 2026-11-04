package systembackupcontroller

import (
	"bytes"
	sb "clawreef/internal/systembackup"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/services"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	"clawreef/internal/systembackupsecurity"
)

var ErrSourceRecoveryProofRequired = errors.New("original source recovery positive facts required")
var ErrSourceRecoveryStoppedWitnessRequired = errors.New("originally stopped source requires independent native stopped witness")

// SourceRecoveryObservation is supplied only by the deployment's actual
// observer. It is data, never a grant or a caller-constructible prepared proof.
// Each observation covers exactly one writer from the encrypted original plan.
type SourceRecoveryObservation struct {
	redisNative                     *sb.VerifiedRedisReadServiceObservation
	minioNative                     *sb.VerifiedMinIOReadServiceObservation
	WriterID, OriginalSHA256, Scope string
	Facts                           json.RawMessage
	References                      []SourceRecoverySQLReference
}

// SourceRecoverySQLReference pins original durable witness bytes. The complete
// native receipt/witness remains in its existing table, not in the frozen CE.
type SourceRecoverySQLReference struct {
	Kind, Identity, SHA256 string
	RequestSHA256          string `json:",omitempty"`
}

type SourceRecoveryObserver func(context.Context, d.Input, b.Discovery) ([]SourceRecoveryObservation, error)

type sourceRecoveryRoot struct {
	Version string
	ce.Scope
	ConfigVersion                                                                            uint64
	ConfigSHA256, PlanSHA256, SourceSHA256, RegistrySHA256                                   string
	CaptureResultSHA256, CaptureResultCipherSHA256, CaptureResultKeyRef, FrozenControlSHA256 string
	Epoch                                                                                    uint64
	CollectorsStoppedAt, SourceResumedAt, ObservedAt                                         time.Time
	WriterCount                                                                              int
	WritersSHA256                                                                            string
}

type sourceRecoveryLeaf struct {
	Version string
	ce.Scope
	ConfigSHA256, SourceSHA256, RegistrySHA256 string
	CaptureResultSHA256, FrozenControlSHA256   string
	Epoch                                      uint64
	SourceRecoveryObservation
}

// PreparedSourceRecovery can only be constructed by authenticated original-plan
// readback plus the actual observer, or by exact durable replay. Registration
// alone grants nothing; current publisher history consumption is separate.
type PreparedSourceRecovery struct {
	redisNative map[string]*sb.VerifiedRedisReadServiceObservation
	minioNative map[string]*sb.VerifiedMinIOReadServiceObservation
	gate        SQLCaptureGate
	a           d.Authority
	desc        b.Discovery
	root        sourceRecoveryRoot
	entries     []ce.RegisteredEvidence
	parts       []sourceRecoveryCapturedPart
}

type sourceRecoveryCapturedPart struct {
	Part                          string
	Job                           d.JobBinding
	Checkpoint                    b.Checkpoint
	CandidateSHA256, ResultSHA256 string
}

func (g SQLCaptureGate) sourceRecoveryResult(ctx context.Context, in d.Input, plan d.Plan, desc b.Discovery) ([]sourceRecoveryCapturedPart, string, string, string, error) {
	a := in.Authority
	var digest, ref string
	var cipher []byte
	if g.Recovery.Check(ctx, a) != nil || g.Authority.DB.QueryRowContext(ctx, `SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind='capture_result'`, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase).Scan(&digest, &ref, &cipher) != nil || !executionHash.MatchString(digest) || len(cipher) > (8<<20)+4096 {
		return nil, "", "", "", ErrExecutionRecord
	}
	actual, key, err := g.Recovery.Identity.Resolve(ctx, a, ref)
	defer clear(key)
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if err != nil || actual != ref || len(key) != 32 || staging.Open(ctx, bytes.NewReader(cipher), &plain, key, recordBinding(a, "capture_result", digest), 8<<20) != nil || recordHash(plain.Bytes()) != digest {
		return nil, "", "", "", ErrExecutionRecord
	}
	parts, err := sourceRecoveryParsedParts(in, plan, desc, plain.Bytes())
	if err != nil {
		return nil, "", "", "", err
	}
	if g.Recovery.Check(ctx, a) != nil {
		return nil, "", "", "", ErrExecutionAuthority
	}
	return parts, digest, recordHash(cipher), ref, nil
}

func sourceRecoveryParsedParts(in d.Input, plan d.Plan, desc b.Discovery, rawResult []byte) ([]sourceRecoveryCapturedPart, error) {
	outcome, err := decodeExecutionResult(rawResult, plan.SHA256)
	if err != nil || outcome.Err != nil || len(outcome.Results) != len(desc.Parts) {
		return nil, ErrExecutionRecord
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return nil, err
	}
	defer clear(inner.CanonicalJSON)
	parts := []sourceRecoveryCapturedPart{}
	seen := map[string]bool{}
	for _, result := range outcome.Results {
		var cp b.Checkpoint
		if seen[result.Part] || json.Unmarshal(result.Checkpoint, &cp) != nil {
			return nil, ErrExecutionRecord
		}
		seen[result.Part] = true
		found := false
		for _, part := range desc.Parts {
			if part.Part != result.Part {
				continue
			}
			job := d.JobBinding{JobUnitKey: part.Intent.JobUnitKey, Namespace: part.Intent.Namespace, Name: part.Intent.Name, UID: cp.JobUID, Generation: part.Intent.Generation}
			raw, e := json.Marshal(result)
			if found || e != nil || b.ValidatePartResult(in, inner, job, raw) != nil {
				return nil, ErrExecutionRecord
			}
			parts = append(parts, sourceRecoveryCapturedPart{Part: result.Part, Job: job, Checkpoint: cp})
			found = true
		}
		if !found {
			return nil, ErrExecutionRecord
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Part < parts[j].Part })
	return parts, nil
}

func (p *PreparedSourceRecovery) frozenControlTx(ctx context.Context, tx *sql.Tx) (string, error) {
	for i := range p.parts {
		part := &p.parts[i]
		var uid, candidate, result string
		if tx.QueryRowContext(ctx, `SELECT observed_uid,candidate_sha256,result_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND create_dispatched=TRUE AND revoked=TRUE AND stopped_at IS NOT NULL FOR SHARE`, p.a.TaskPublicID, p.a.AttemptNo, p.a.Phase, part.Job.Namespace, part.Job.Name).Scan(&uid, &candidate, &result) != nil || uid != part.Job.UID || !executionHash.MatchString(candidate) || !executionHash.MatchString(result) {
			return "", ErrSourceRecoveryProofRequired
		}
		if part.CandidateSHA256 != "" && (part.CandidateSHA256 != candidate || part.ResultSHA256 != result) {
			return "", ErrSourceRecoveryProofRequired
		}
		part.CandidateSHA256, part.ResultSHA256 = candidate, result
	}
	var seed *ce.CaptureLocator
	controlParts := map[string]bool{}
	for _, part := range p.desc.Parts {
		if part.Part != ce.Part && part.Part != ce.ProofPart {
			continue
		}
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil || invocation.Request.ControlEvidence == nil || invocation.Request.ControlEvidence.Finalization == nil {
			return "", ErrSourceRecoveryProofRequired
		}
		if seed != nil && !sourceRecoveryEqual(*seed, *invocation.Request.ControlEvidence) {
			return "", ErrSourceRecoveryProofRequired
		}
		seed = invocation.Request.ControlEvidence
		controlParts[part.Part] = true
	}
	if seed == nil || !controlParts[ce.Part] || !controlParts[ce.ProofPart] || seed.Expected.Scope != p.root.Scope || seed.Expected.ConfigSHA256 != p.a.ConfigSHA256 {
		return "", ErrSourceRecoveryProofRequired
	}
	id, err := ce.FinalizedSourceEvidenceID(*seed)
	if err != nil {
		return "", err
	}
	load := func(ref ce.EvidenceRef) (ce.RegisteredEvidence, error) {
		return ce.LoadRegisteredSQL(ctx, tx, p.root.Scope, ref)
	}
	var checksum string
	if tx.QueryRowContext(ctx, "SELECT content_checksum FROM system_backup_v2_evidence WHERE public_id=? FOR SHARE", id).Scan(&checksum) != nil {
		return "", ErrSourceRecoveryProofRequired
	}
	seal, err := load(ce.EvidenceRef{PublicID: id, SHA256: checksum})
	if err != nil {
		return "", err
	}
	refs, err := ce.FinalizedSourceReferences(*seed, seal)
	if err != nil {
		return "", err
	}
	chunks := []ce.RegisteredEvidence{}
	for _, ref := range refs {
		entry, e := load(ref)
		if e != nil {
			return "", e
		}
		chunks = append(chunks, entry)
	}
	final, err := ce.ReadFinalizedSourceSeal(*seed, seal, chunks...)
	if err != nil {
		return "", err
	}
	entries := []ce.RegisteredEvidence{}
	for _, ref := range final.Evidence {
		entry, e := load(ref)
		if e != nil {
			return "", e
		}
		entries = append(entries, entry)
	}
	verified, err := ce.VerifyFinalized(ctx, *seed, final, entries)
	if err != nil {
		return "", err
	}
	defer clear(verified.SidecarJSON)
	defer clear(verified.ProofsJSON)
	raw, err := ce.Canonical(struct {
		Parts                       []sourceRecoveryCapturedPart
		Seal                        ce.EvidenceRef
		SidecarSHA256, ProofsSHA256 string
	}{p.parts, ce.EvidenceRef{PublicID: id, SHA256: checksum}, verified.SidecarSHA256, verified.ProofsSHA256})
	if err != nil {
		return "", err
	}
	return recordHash(raw), nil
}

func sourceRecoveryID(scope ce.Scope, writer string) string {
	raw, _ := json.Marshal([]any{"original-source-recovery.v1", scope, writer})
	return sourceRecoveryFamily(scope) + recordHash(raw)
}

func sourceRecoveryFamily(scope ce.Scope) string {
	raw, _ := json.Marshal([]any{"original-source-recovery-family.v1", scope})
	return "sev_source_recovery_" + recordHash(raw)[:32] + "_"
}

// Unfiltered family inventory deliberately includes expired/bad/cross-owner
// roots, leaves and future descendants. An orphan cannot mint a new root/time.
func sourceRecoveryFamilyCountTx(ctx context.Context, tx *sql.Tx, scope ce.Scope) (int, error) {
	prefix := strings.NewReplacer("=", "==", "_", "=_", "%", "=%").Replace(sourceRecoveryFamily(scope))
	rows, err := tx.QueryContext(ctx, "SELECT public_id FROM system_backup_v2_evidence WHERE public_id LIKE ? ESCAPE '=' ORDER BY public_id LIMIT 10002 FOR SHARE", prefix+"%")
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return 0, ErrSourceRecoveryProofRequired
		}
		count++
	}
	return count, rows.Err()
}

func sourceRecoveryOriginalSHA(w b.FrozenWriter) string {
	raw, _ := json.Marshal(d.WriterState{UID: w.Original.UID, Generation: w.Original.Generation, Running: w.Original.Running, Checkpoint: w.Original.Checkpoint})
	return recordHash(raw)
}

func validSourceRecoveryObservation(ob SourceRecoveryObservation) bool {
	if ob.WriterID == "" || !executionHash.MatchString(ob.OriginalSHA256) {
		return false
	}
	if ob.Scope == sharedTaskRecoveryScope {
		var summary runtimeSharedRecoverySummary
		return json.Unmarshal(ob.Facts, &summary) == nil && summary.Version == "source-recovery-shared-runtime-ref.v1" && summary.Original.ID == ob.WriterID && len(ob.References) == 1 && ob.References[0].Kind == "runtime_stop" && ob.References[0].SHA256 == summary.PayloadSHA256 && executionHash.MatchString(summary.DefinitionSHA256) && executionHash.MatchString(summary.PayloadSHA256)
	}
	var facts struct {
		Version, Kind string
		Runtime       json.RawMessage
		Recovered     []json.RawMessage
	}
	if json.Unmarshal(ob.Facts, &facts) != nil {
		return false
	}
	switch ob.Scope {
	case MinIOReadServiceRecoveryScope:
		_, e := minioReadServiceFacts(ob)
		return e == nil
	case RedisReadServiceRecoveryScope:
		_, e := redisReadServiceFacts(ob)
		return e == nil
	case "registered_application_mutation_lease_boundary":
		return facts.Version == "source-recovery-lease-observation.v1" && len(ob.References) == 1 && ob.References[0].Kind == "lease_epoch" && ob.References[0].Identity == ob.WriterID && ob.References[0].SHA256 == recordHash(ob.Facts)
	case "current_stopped_pro_native_baseline_and_volume_bindings":
		if facts.Version != "source-recovery-current-stopped-pro.v1" || facts.Kind != "stopped" || len(facts.Runtime) < 2 || string(facts.Runtime) == "null" || len(facts.Recovered) != 0 || len(ob.References) != 2 {
			return false
		}
		seen := map[string]bool{}
		for _, ref := range ob.References {
			if ref.Identity != ob.WriterID || !executionHash.MatchString(ref.SHA256) || seen[ref.Kind] || (ref.Kind != "runtime_control" && ref.Kind != "runtime_source") {
				return false
			}
			seen[ref.Kind] = true
		}
		return seen["runtime_control"] && seen["runtime_source"]
	case "native_instance_pid_namespace_and_mount_lifecycle_with_kubernetes_volume_bindings":
		if facts.Kind != "gateway" || len(facts.Runtime) < 2 || string(facts.Runtime) == "null" {
			return false
		}
	case "original_kubelet_exit_witness_and_recovered_ready_pod_container_volume_api_bindings":
		if facts.Kind != "pod" && facts.Kind != "deployment" {
			return false
		}
	default:
		return false
	}
	if facts.Version != "source-recovery-physical-observation.v1" || len(facts.Recovered) == 0 || len(ob.References) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, ref := range ob.References {
		id := ref.Kind + "/" + ref.Identity
		if ref.Identity == "" || !executionHash.MatchString(ref.SHA256) || seen[id] {
			return false
		}
		seen[id] = true
	}
	if facts.Kind == "gateway" {
		for _, kind := range []string{"runtime_control", "runtime_source", "gateway_binding", "gateway_stopped", "gateway_resumed"} {
			if !seen[kind+"/"+ob.WriterID] {
				return false
			}
		}
	} else {
		stop := false
		for _, ref := range ob.References {
			stop = stop || ref.Kind == "runtime_stop"
		}
		if !stop {
			return false
		}
	}
	return true
}

func sourceRecoveryEntry(scope ce.Scope, writer string, value any) (ce.RegisteredEvidence, error) {
	raw, err := ce.Canonical(value)
	if err != nil || len(raw) < 2 || len(raw) > 8192 {
		return ce.RegisteredEvidence{}, ErrSourceRecoveryProofRequired
	}
	return ce.RegisteredEvidence{PublicID: sourceRecoveryID(scope, writer), SHA256: recordHash(raw), OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: raw}, nil
}

func sourceRecoveryReadEntry(ctx context.Context, tx *sql.Tx, scope ce.Scope, writer string) (ce.RegisteredEvidence, error) {
	var digest string
	err := tx.QueryRowContext(ctx, "SELECT content_checksum FROM system_backup_v2_evidence WHERE public_id=?", sourceRecoveryID(scope, writer)).Scan(&digest)
	if err != nil {
		return ce.RegisteredEvidence{}, err
	}
	return ce.LoadRegisteredSQL(ctx, tx, scope, ce.EvidenceRef{PublicID: sourceRecoveryID(scope, writer), SHA256: digest})
}

func (p *PreparedSourceRecovery) snapshotTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || tx == nil || p.gate.Recovery.CheckTx(ctx, tx, p.a) != nil {
		return ErrExecutionAuthority
	}
	var epoch uint64
	var registry, plan string
	var writers []byte
	var stopped, resumed sql.NullTime
	if tx.QueryRowContext(ctx, `SELECT gate_generation,registry_sha256,writers_json,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE`, p.a.TaskPublicID, p.gate.Authority.ApplicationScope).Scan(&epoch, &registry, &writers, &stopped, &resumed) != nil {
		return ErrSourceRecoveryProofRequired
	}
	want, err := json.Marshal(p.desc.Writers)
	if err != nil || !bytes.Equal(want, writers) || recordHash(writers) != registry || epoch != p.a.MaintenanceFencingToken || !stopped.Valid || !resumed.Valid || resumed.Time.Before(stopped.Time) {
		return ErrSourceRecoveryProofRequired
	}
	if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind='plan' FOR SHARE`, p.a.InstallationID, p.a.TaskPublicID, p.a.AttemptNo, p.a.Phase).Scan(&plan) != nil || plan != p.root.PlanSHA256 {
		return ErrSourceRecoveryProofRequired
	}
	var result, ref string
	var cipher []byte
	if tx.QueryRowContext(ctx, `SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind='capture_result' FOR SHARE`, p.a.InstallationID, p.a.TaskPublicID, p.a.AttemptNo, p.a.Phase).Scan(&result, &ref, &cipher) != nil || result != p.root.CaptureResultSHA256 || ref != p.root.CaptureResultKeyRef || len(cipher) > (8<<20)+4096 || recordHash(cipher) != p.root.CaptureResultCipherSHA256 {
		return ErrSourceRecoveryProofRequired
	}
	frozenControl, err := p.frozenControlTx(ctx, tx)
	if err != nil || (p.root.FrozenControlSHA256 != "" && p.root.FrozenControlSHA256 != frozenControl) {
		return ErrSourceRecoveryProofRequired
	}
	p.root.FrozenControlSHA256 = frozenControl
	if p.root.RegistrySHA256 != "" && (p.root.RegistrySHA256 != registry || !p.root.CollectorsStoppedAt.Equal(stopped.Time) || !p.root.SourceResumedAt.Equal(resumed.Time)) {
		return ErrSourceRecoveryProofRequired
	}
	p.root.RegistrySHA256, p.root.Epoch = registry, epoch
	p.root.CollectorsStoppedAt, p.root.SourceResumedAt = stopped.Time.UTC(), resumed.Time.UTC()
	if _, err = recoveryInventoryTx(ctx, tx, p.a, p.gate.Authority.ApplicationScope, true); err != nil {
		return err
	}
	return nil
}

// PrepareSourceRecovery runs after B's original Resume defer has returned. No
// source discovery or new writer inventory is permitted here. The encrypted
// original plan is re-opened under original recovery authority before any I/O.
func (g SQLCaptureGate) PrepareSourceRecovery(ctx context.Context, w ExecutionWork, observe SourceRecoveryObserver) (*PreparedSourceRecovery, error) {
	if !g.ready() || w.Step != ExecutionCapture || observe == nil {
		return nil, ErrSourceRecoveryProofRequired
	}
	plan, err := g.Records.LoadRecoveryPlan(ctx, w.Input, g.Recovery)
	if err != nil {
		return nil, err
	}
	defer clear(plan.CanonicalJSON)
	if !bytes.Equal(plan.CanonicalJSON, w.Plan.CanonicalJSON) {
		return nil, ErrExecutionRecord
	}
	desc, err := describeExecutionPlan(w.Input, plan)
	if err != nil || len(desc.Writers) == 0 || len(desc.Writers) > 10000 || recordHash(desc.Source) != desc.SourceSHA256 {
		return nil, ErrSourceRecoveryProofRequired
	}
	parts, resultSHA, resultCipherSHA, resultKey, err := g.sourceRecoveryResult(ctx, w.Input, plan, desc)
	if err != nil {
		return nil, err
	}
	a := w.Input.Authority
	p := &PreparedSourceRecovery{gate: g, a: a, desc: desc, parts: parts, root: sourceRecoveryRoot{Version: "original-source-recovery.v1", Scope: ce.Scope{Installation: a.InstallationID, Backup: a.TaskPublicID, Attempt: a.AttemptNo}, ConfigVersion: a.ConfigVersion, ConfigSHA256: a.ConfigSHA256, PlanSHA256: recordHash(plan.CanonicalJSON), SourceSHA256: desc.SourceSHA256, WriterCount: len(desc.Writers), CaptureResultSHA256: resultSHA, CaptureResultCipherSHA256: resultCipherSHA, CaptureResultKeyRef: resultKey}}
	tx, err := g.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = p.snapshotTx(ctx, tx); err != nil {
		return nil, err
	}
	root, err := sourceRecoveryReadEntry(ctx, tx, p.root.Scope, "")
	if err == nil {
		var saved sourceRecoveryRoot
		if json.Unmarshal(root.Payload, &saved) != nil {
			return nil, ErrSourceRecoveryProofRequired
		}
		observed := saved.ObservedAt
		saved.ObservedAt, saved.WritersSHA256 = time.Time{}, ""
		want := p.root
		if !sourceRecoveryEqual(saved, want) || observed.Before(p.root.SourceResumedAt) {
			return nil, ErrSourceRecoveryProofRequired
		}
		p.root.ObservedAt = observed
		p.entries = []ce.RegisteredEvidence{root}
		for _, writer := range sourceRecoverySorted(desc.Writers) {
			entry, e := sourceRecoveryReadEntry(ctx, tx, p.root.Scope, writer.ID)
			if e != nil {
				return nil, ErrSourceRecoveryProofRequired
			}
			p.entries = append(p.entries, entry)
		}
		if json.Unmarshal(root.Payload, &p.root) != nil || p.validateEntries() != nil || p.validateProducerLeaves() != nil || p.referencesTx(ctx, tx) != nil {
			return nil, ErrSourceRecoveryProofRequired
		}
		if count, e := sourceRecoveryFamilyCountTx(ctx, tx, p.root.Scope); e != nil || count != len(p.entries) {
			return nil, ErrSourceRecoveryProofRequired
		}
		if g.Recovery.CheckTx(ctx, tx, a) != nil {
			return nil, ErrExecutionAuthority
		}
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSourceRecoveryProofRequired
	}
	if count, e := sourceRecoveryFamilyCountTx(ctx, tx, p.root.Scope); e != nil || count != 0 {
		return nil, ErrSourceRecoveryProofRequired
	}
	// Drop locks before native Agent or Kubernetes calls. StageTx rechecks the
	// exact plan/registry/witness bytes inside FinishCapture's transaction.
	tx.Rollback()
	_, detached := cloneOriginalPlanData(d.Plan{}, desc)
	inputRaw, err := json.Marshal(w.Input)
	var originalInput d.Input
	if err != nil || json.Unmarshal(inputRaw, &originalInput) != nil {
		return nil, ErrExecutionRecord
	}
	observations, err := observe(ctx, originalInput, detached)
	if err != nil {
		return nil, err
	}
	if len(observations) != len(desc.Writers) {
		return nil, ErrSourceRecoveryProofRequired
	}
	p.redisNative = map[string]*sb.VerifiedRedisReadServiceObservation{}
	p.minioNative = map[string]*sb.VerifiedMinIOReadServiceObservation{}
	byID := map[string]SourceRecoveryObservation{}
	for _, ob := range observations {
		if !validSourceRecoveryObservation(ob) || byID[ob.WriterID].WriterID != "" {
			return nil, ErrSourceRecoveryProofRequired
		}
		if ob.Scope == RedisReadServiceRecoveryScope {
			if ob.redisNative == nil {
				return nil, ErrSourceRecoveryProofRequired
			}
			p.redisNative[ob.WriterID] = ob.redisNative
		}
		if ob.Scope == MinIOReadServiceRecoveryScope {
			if ob.minioNative == nil {
				return nil, ErrSourceRecoveryProofRequired
			}
			p.minioNative[ob.WriterID] = ob.minioNative
		}
		byID[ob.WriterID] = ob
	}
	for _, writer := range sourceRecoverySorted(desc.Writers) {
		ob := byID[writer.ID]
		if ob.OriginalSHA256 != sourceRecoveryOriginalSHA(writer) {
			return nil, ErrSourceRecoveryProofRequired
		}
		entry, e := sourceRecoveryEntry(p.root.Scope, writer.ID, sourceRecoveryLeaf{Version: "original-source-recovery-writer.v1", Scope: p.root.Scope, ConfigSHA256: a.ConfigSHA256, SourceSHA256: desc.SourceSHA256, RegistrySHA256: p.root.RegistrySHA256, CaptureResultSHA256: p.root.CaptureResultSHA256, FrozenControlSHA256: p.root.FrozenControlSHA256, Epoch: p.root.Epoch, SourceRecoveryObservation: ob})
		if e != nil {
			return nil, e
		}
		p.entries = append(p.entries, entry)
	}
	refs := make([]ce.EvidenceRef, 0, len(p.entries))
	for _, entry := range p.entries {
		refs = append(refs, ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256})
	}
	if g.Authority.DB.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&p.root.ObservedAt) != nil || p.root.ObservedAt.Before(p.root.SourceResumedAt) {
		return nil, ErrSourceRecoveryProofRequired
	}
	p.root.ObservedAt = p.root.ObservedAt.UTC().Truncate(time.Microsecond)
	raw, _ := json.Marshal(refs)
	p.root.WritersSHA256 = recordHash(raw)
	root, err = sourceRecoveryEntry(p.root.Scope, "", p.root)
	if err != nil {
		return nil, err
	}
	p.entries = append([]ce.RegisteredEvidence{root}, p.entries...)
	if p.validateEntries() != nil || p.validateProducerLeaves() != nil {
		return nil, ErrSourceRecoveryProofRequired
	}
	return p, nil
}

func sourceRecoveryEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func sourceRecoverySorted(writers []b.FrozenWriter) []b.FrozenWriter {
	copy := append([]b.FrozenWriter(nil), writers...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].ID < copy[j].ID })
	return copy
}

func (p *PreparedSourceRecovery) validateEntries() error {
	if p == nil || len(p.desc.Writers) == 0 || p.root.WriterCount != len(p.desc.Writers) || len(p.entries) != len(p.desc.Writers)+1 {
		return ErrSourceRecoveryProofRequired
	}
	refs := []ce.EvidenceRef{}
	seen := map[string]bool{}
	for i, writer := range sourceRecoverySorted(p.desc.Writers) {
		if writer.ID == "" || seen[writer.ID] {
			return ErrSourceRecoveryProofRequired
		}
		seen[writer.ID] = true
		entry := p.entries[i+1]
		var leaf sourceRecoveryLeaf
		if json.Unmarshal(entry.Payload, &leaf) != nil || leaf.Version != "original-source-recovery-writer.v1" || leaf.Scope != p.root.Scope || leaf.ConfigSHA256 != p.root.ConfigSHA256 || leaf.SourceSHA256 != p.root.SourceSHA256 || leaf.RegistrySHA256 != p.root.RegistrySHA256 || leaf.CaptureResultSHA256 != p.root.CaptureResultSHA256 || leaf.FrozenControlSHA256 != p.root.FrozenControlSHA256 || leaf.Epoch != p.root.Epoch || leaf.WriterID != writer.ID || leaf.OriginalSHA256 != sourceRecoveryOriginalSHA(writer) || !validSourceRecoveryObservation(leaf.SourceRecoveryObservation) || entry.PublicID != sourceRecoveryID(p.root.Scope, writer.ID) || recordHash(entry.Payload) != entry.SHA256 {
			return ErrSourceRecoveryProofRequired
		}
		refs = append(refs, ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256})
	}
	raw, _ := json.Marshal(refs)
	root, err := sourceRecoveryEntry(p.root.Scope, "", p.root)
	if err != nil || p.root.WritersSHA256 != recordHash(raw) || !bytes.Equal(root.Payload, p.entries[0].Payload) || root.SHA256 != p.entries[0].SHA256 {
		return ErrSourceRecoveryProofRequired
	}
	return nil
}

func (p *PreparedSourceRecovery) referencesTx(ctx context.Context, tx *sql.Tx) error {
	for _, entry := range p.entries[1:] {
		var leaf sourceRecoveryLeaf
		if json.Unmarshal(entry.Payload, &leaf) != nil {
			return ErrSourceRecoveryProofRequired
		}
		for _, ref := range leaf.References {
			var raw []byte
			var digest string
			var err error
			switch ref.Kind {
			case "lease_epoch":
				raw, err = p.gate.sourceRecoveryLeaseFactsTx(ctx, tx, p.a)
				digest = recordHash(raw)
			case "runtime_stop":
				err = tx.QueryRowContext(ctx, "SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=? FOR SHARE", p.a.TaskPublicID, ref.Identity).Scan(&raw, &digest)
			case "gateway_stopped", "gateway_resumed":
				var request string
				err = tx.QueryRowContext(ctx, "SELECT body_raw,body_sha256,request_sha256 FROM system_backup_v2_gateway_proofs WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND proof_kind=? FOR SHARE", p.a.TaskPublicID, p.a.AttemptNo, leaf.WriterID, ref.Kind[len("gateway_"):]).Scan(&raw, &digest, &request)
				if !executionHash.MatchString(ref.RequestSHA256) || request != ref.RequestSHA256 || ref.Identity != leaf.WriterID {
					return ErrSourceRecoveryProofRequired
				}
			case "runtime_control":
				row, e := readRuntimeControl(ctx, tx, p.a, leaf.WriterID)
				err = e
				raw, _ = ce.Canonical(sourceRecoveryRuntimeRow(row))
				digest = recordHash(raw)
			case "runtime_source":
				row, e := readRuntimeControl(ctx, tx, p.a, leaf.WriterID)
				if e != nil {
					return ErrSourceRecoveryProofRequired
				}
				current, e := sourceRow(ctx, tx, row.Spec.Source.ID)
				err = e
				raw, _ = ce.Canonical(current)
				digest = recordHash(raw)
			case "gateway_binding":
				row, e := readRuntimeControl(ctx, tx, p.a, leaf.WriterID)
				if e != nil {
					return ErrSourceRecoveryProofRequired
				}
				binding, e := readGatewayBinding(ctx, tx, row.Spec.Source.ID, true)
				err = e
				raw, _ = ce.Canonical(binding)
				digest = recordHash(raw)
			default:
				return ErrSourceRecoveryProofRequired
			}
			if err != nil || !executionHash.MatchString(ref.SHA256) || ref.SHA256 != digest || recordHash(raw) != digest {
				return ErrSourceRecoveryProofRequired
			}
			if leaf.SourceRecoveryObservation.Scope == sharedTaskRecoveryScope && ref.Kind == "runtime_stop" {
				var originalSource b.SourceInventory
				var summary runtimeSharedRecoverySummary
				if json.Unmarshal(p.desc.Source, &originalSource) != nil || json.Unmarshal(leaf.Facts, &summary) != nil {
					return ErrSourceRecoveryProofRequired
				}
				instances := map[int]b.InstanceIdentity{}
				for _, source := range originalSource.Instances {
					instances[source.ID] = source
				}
				var facts RuntimeSharedRecoveryFacts
				if json.Unmarshal(raw, &facts) != nil || recordHash(mustSharedJSON(facts.Definition)) != summary.DefinitionSHA256 {
					return ErrSourceRecoveryProofRequired
				}
				full := leaf
				full.Facts = raw
				if validateFullSharedTaskRecoveryLeaf(p.a, summary.Original, full, instances) != nil {
					return ErrSourceRecoveryProofRequired
				}
			}
		}
	}
	return nil
}

type sourceRecoveryLeaseRow struct {
	ID                    string
	Generation            uint64
	ExpiresAt, ReleasedAt time.Time
}

func (g SQLCaptureGate) sourceRecoveryLeaseFactsTx(ctx context.Context, tx *sql.Tx, a d.Authority) ([]byte, error) {
	var epoch, acquire uint64
	var held sql.NullInt64
	var stopped, resumed sql.NullTime
	if tx.QueryRowContext(ctx, `SELECT gate_generation,acquire_token,held_token,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE`, a.TaskPublicID, g.Authority.ApplicationScope).Scan(&epoch, &acquire, &held, &stopped, &resumed) != nil || epoch != a.MaintenanceFencingToken || epoch == 0 || !held.Valid || held.Int64 <= 0 || uint64(held.Int64) != acquire+1 || !stopped.Valid || !resumed.Valid || resumed.Time.Before(stopped.Time) {
		return nil, ErrSourceRecoveryProofRequired
	}
	// AcquireMutation reads the idle gate generation under its shared lock;
	// acquisition increments that generation. New legitimate requests after
	// Resume carry epoch, whereas the old finite work set has generation<epoch.
	// Expiry is never a substitute for a positive ReleaseMutation acknowledgement.
	rows, err := tx.QueryContext(ctx, `SELECT public_id,generation,expires_at,released_at FROM system_backup_mutation_leases WHERE scope=? AND generation<? ORDER BY public_id LIMIT 10001 FOR SHARE`, g.Authority.ApplicationScope, epoch)
	if err != nil {
		return nil, err
	}
	old := []sourceRecoveryLeaseRow{}
	for rows.Next() {
		var row sourceRecoveryLeaseRow
		var released sql.NullTime
		if rows.Scan(&row.ID, &row.Generation, &row.ExpiresAt, &released) != nil || row.ID == "" || row.Generation >= epoch || !released.Valid || released.Time.After(stopped.Time) || len(old) >= 10000 {
			rows.Close()
			return nil, ErrSourceRecoveryProofRequired
		}
		row.ReleasedAt = released.Time.UTC()
		row.ExpiresAt = row.ExpiresAt.UTC()
		old = append(old, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(old)
	return ce.Canonical(struct {
		Version, ApplicationScope, WorkBoundary string
		CaptureEpoch, OriginalHeldToken         uint64
		OldWorkCount                            int
		OldWorkSHA256                           string
		CollectorsStoppedAt, SourceResumedAt    time.Time
	}{"source-recovery-lease-observation.v1", g.Authority.ApplicationScope, "registered_mutation_work_generation_less_than_capture_epoch", epoch, uint64(held.Int64), len(old), recordHash(raw), stopped.Time.UTC(), resumed.Time.UTC()})
}

func (g SQLCaptureGate) ObserveSourceRecoveryParticipant(ctx context.Context, in d.Input, writer b.FrozenWriter) (SourceRecoveryObservation, error) {
	var out SourceRecoveryObservation
	a := in.Authority
	if writer.Original.UID != g.Authority.ApplicationScope+"/"+writer.ID || writer.Original.Generation != int64(a.ConfigVersion) || writer.Original.Checkpoint != recordHash([]byte(g.Authority.ApplicationScope+"/"+writer.ID+"/"+a.ConfigSHA256)) {
		return out, ErrSourceRecoveryProofRequired
	}
	tx, err := g.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if g.Recovery.CheckTx(ctx, tx, a) != nil {
		return out, ErrExecutionAuthority
	}
	if _, err = recoveryInventoryTx(ctx, tx, a, g.Authority.ApplicationScope, true); err != nil {
		return out, err
	}
	raw, err := g.sourceRecoveryLeaseFactsTx(ctx, tx, a)
	if err != nil {
		return out, err
	}
	if g.Recovery.CheckTx(ctx, tx, a) != nil {
		return out, ErrExecutionAuthority
	}
	return SourceRecoveryObservation{WriterID: writer.ID, OriginalSHA256: sourceRecoveryOriginalSHA(writer), Scope: "registered_application_mutation_lease_boundary", Facts: raw, References: []SourceRecoverySQLReference{{Kind: "lease_epoch", Identity: writer.ID, SHA256: recordHash(raw)}}}, nil
}

// SourceRecoveryRuntime contains no restart material or credentials. The live
// Agent state is read here using the original request, not inferred from the
// Ready state of its shared Pod. The deployment observer adds actual Pod and
// original volume observations before this data can become a prepared proof.
type SourceRecoveryRuntime struct {
	Spec                              b.RuntimeWriterSpec
	SpecSHA256                        string
	Resumed                           json.RawMessage
	GatewayRequest                    *services.RuntimeBackupRequest `json:",omitempty"`
	GatewayPID                        int                            `json:",omitempty"`
	GatewayStateSHA256                string                         `json:",omitempty"`
	References                        []SourceRecoverySQLReference   `json:"-"`
	ControlRow, SourceRow, BindingRow json.RawMessage                `json:",omitempty"`
}

func sourceRecoveryRuntimeRow(row runtimeControlRow) any {
	return struct {
		Spec                                 b.RuntimeWriterSpec
		MaterialSHA256, CipherSHA256, KeyRef string
		Claimed, Completed                   bool
		Resumed                              json.RawMessage
		Stopped                              sql.NullString
		Version                              uint64
	}{row.Spec, row.Digest, recordHash(row.Sealed), row.Key, row.Claimed, row.Completed, row.Resumed, row.Stopped, row.Version}
}

func (o *SQLRuntimeControl) ObserveSourceRecoveryRuntime(ctx context.Context, in d.Input, writer b.FrozenWriter) (SourceRecoveryRuntime, error) {
	var out SourceRecoveryRuntime
	if o == nil || o.cfg.Gate.Recovery.Check(ctx, in.Authority) != nil {
		return out, ErrExecutionAuthority
	}
	a := in.Authority
	tx, err := o.cfg.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if o.cfg.Gate.Recovery.CheckTx(ctx, tx, a) != nil || originalRuntimeState(ctx, tx, a, writer.ID, writer.Original) != nil {
		return out, ErrExecutionAuthority
	}
	row, err := readRuntimeControl(ctx, tx, a, writer.ID)
	if err != nil || !row.Completed {
		return out, ErrSourceRecoveryProofRequired
	}
	// The existing isolated-backup protocol only reserves an originally running
	// instance. SQL status, an empty shared Pod, 404 or absent GatewayState cannot
	// substitute for the separate positive originally-stopped native witness.
	if row.Spec.Kind == "stopped" {
		var record RuntimeStoppedProRecord
		if row.Spec.Stopped != writer.Original || json.Unmarshal(row.Resumed, &record) != nil || !validStoppedProRecoveryRecord(record, row.Spec, a) {
			return out, ErrSourceRecoveryStoppedWitnessRequired
		}
		body, err := json.Marshal(record.Stopped)
		if err != nil || !row.Stopped.Valid || recordHash(body) != row.Stopped.String {
			return out, ErrSourceRecoveryStoppedWitnessRequired
		}
	}
	if row.Spec.Kind != "stopped" && !writer.Original.Running || !row.Stopped.Valid {
		return out, ErrSourceRecoveryProofRequired
	}
	current, err := sourceRow(ctx, tx, row.Spec.Source.ID)
	want := row.Spec.Source
	if row.Spec.Kind == "gateway" {
		want.Generation = row.Spec.ResumeGeneration
	}
	if row.Spec.Kind == "deployment" {
		var resumed deploymentResume
		if json.Unmarshal(row.Resumed, &resumed) != nil || resumed.PodName == "" || resumed.PodUID == "" {
			return out, ErrSourceRecoveryProofRequired
		}
		want.Pod = resumed.PodName
	}
	if err != nil || current != want {
		return out, ErrSourceRecoveryProofRequired
	}
	ref := func(kind string, value any) json.RawMessage {
		raw, _ := ce.Canonical(value)
		out.References = append(out.References, SourceRecoverySQLReference{Kind: kind, Identity: writer.ID, SHA256: recordHash(raw)})
		return raw
	}
	out.ControlRow = ref("runtime_control", sourceRecoveryRuntimeRow(row))
	out.SourceRow = ref("runtime_source", current)
	out.Spec, out.Resumed = row.Spec, bytes.Clone(row.Resumed)
	var specRaw []byte
	if tx.QueryRowContext(ctx, `SELECT spec_json FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? AND writer_id=? FOR SHARE`, a.TaskPublicID, a.AttemptNo, writer.ID).Scan(&specRaw) != nil {
		return out, ErrSourceRecoveryProofRequired
	}
	out.SpecSHA256 = recordHash(specRaw)
	var resume services.RuntimeBackupObservation
	if row.Spec.Kind == "gateway" {
		req, e := gatewayBackupRequest(a, row.Spec)
		if e != nil || !row.Claimed {
			return out, ErrSourceRecoveryProofRequired
		}
		stop, e := readGatewayProof(ctx, tx, a, writer.ID, req, "stopped")
		if e != nil || recordHash(stop.Raw) != row.Stopped.String {
			return out, ErrSourceRecoveryProofRequired
		}
		resume, e = readGatewayProof(ctx, tx, a, writer.ID, req, "resumed")
		if e != nil || resume.Receipt.ConfirmedAt.Before(stop.Receipt.ConfirmedAt) || resume.Receipt.PID == req.ExpectedPID {
			return out, ErrSourceRecoveryProofRequired
		}
		binding, e := readGatewayBinding(ctx, tx, row.Spec.Source.ID, true)
		if e != nil || !bindingMatchesSource(binding, want, row.Spec.RuntimeNamespace()) || binding.PID != resume.Receipt.PID || binding.UID != row.Spec.UID || binding.ID != row.Spec.Runtime.RuntimePodID || binding.Endpoint != row.Spec.Endpoint {
			return out, ErrSourceRecoveryProofRequired
		}
		out.BindingRow = ref("gateway_binding", binding)
		out.GatewayRequest, out.GatewayPID = &req, resume.Receipt.PID
		out.GatewayStateSHA256 = recordHash(resume.Raw)
		out.References = append(out.References, SourceRecoverySQLReference{Kind: "gateway_stopped", Identity: writer.ID, SHA256: recordHash(stop.Raw), RequestSHA256: gatewayRequestHash(req)}, SourceRecoverySQLReference{Kind: "gateway_resumed", Identity: writer.ID, SHA256: recordHash(resume.Raw), RequestSHA256: gatewayRequestHash(req)})
	}
	if o.cfg.Gate.Recovery.CheckTx(ctx, tx, a) != nil {
		return out, ErrExecutionAuthority
	}
	tx.Rollback()
	if row.Spec.Kind == "gateway" {
		agent, ok := o.cfg.Agent.(services.RuntimeAgentBackupClient)
		if !ok || o.checkGatewayPod(ctx, row.Spec) != nil {
			return out, ErrSourceRecoveryProofRequired
		}
		live, e := agent.BackupControl(ctx, row.Spec.Endpoint, "state", *out.GatewayRequest, nil)
		if e != nil || live.Pending || !bytes.Equal(live.Raw, resume.Raw) || !services.ValidateRuntimeBackupReceipt(*out.GatewayRequest, live.Receipt) {
			return out, ErrSourceRecoveryProofRequired
		}
		gatewayID := "gw-" + strconv.Itoa(row.Spec.Source.ID) + "-" + strconv.Itoa(row.Spec.ResumeGeneration)
		state, e := o.cfg.Agent.GatewayState(ctx, row.Spec.Endpoint, gatewayID)
		if e != nil || state == nil || state.GatewayID != gatewayID || state.State != "running" || state.PID != out.GatewayPID || state.InstanceID != row.Spec.Source.ID || state.UserID != row.Spec.Source.UserID || state.Generation != row.Spec.ResumeGeneration || state.Port != row.Spec.Port {
			return out, ErrSourceRecoveryProofRequired
		}
	}
	return out, nil
}

// StageTx is used only in the original FinishCapture success transaction. It
// retains original expiry and exact bytes on replay/ACK-unknown; no external
// action or expired forward-grant resurrection occurs under these SQL locks.
func (p *PreparedSourceRecovery) StageTx(ctx context.Context, tx *sql.Tx, w ExecutionWork) error {
	if p == nil || w.Step != ExecutionCapture || p.a != w.Input.Authority || p.root.PlanSHA256 != recordHash(w.Plan.CanonicalJSON) || p.validateEntries() != nil || p.validateProducerLeaves() != nil {
		return ErrSourceRecoveryProofRequired
	}
	if err := p.snapshotTx(ctx, tx); err != nil {
		return err
	}
	if err := p.referencesTx(ctx, tx); err != nil {
		return err
	}
	if existing, err := sourceRecoveryReadEntry(ctx, tx, p.root.Scope, ""); err == nil {
		if !bytes.Equal(existing.Payload, p.entries[0].Payload) {
			return ErrSourceRecoveryProofRequired
		}
		for _, entry := range p.entries[1:] {
			actual, e := ce.LoadRegisteredSQL(ctx, tx, p.root.Scope, ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256})
			if e != nil || !bytes.Equal(actual.Payload, entry.Payload) {
				return ErrSourceRecoveryProofRequired
			}
		}
		if count, e := sourceRecoveryFamilyCountTx(ctx, tx, p.root.Scope); e != nil || count != len(p.entries) {
			return ErrSourceRecoveryProofRequired
		}
		return p.gate.Recovery.CheckTx(ctx, tx, p.a)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ErrSourceRecoveryProofRequired
	}
	if count, err := sourceRecoveryFamilyCountTx(ctx, tx, p.root.Scope); err != nil || count != 0 {
		return ErrSourceRecoveryProofRequired
	}
	if p.checkRedisReadServiceNative(ctx) != nil || p.checkMinIOReadServiceNative(ctx) != nil {
		return ErrSourceRecoveryProofRequired
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, p.a.InstallationID, p.a.ConfigVersion, p.a.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return ErrSourceRecoveryProofRequired
	}
	total := 0
	for _, entry := range p.entries {
		total += len(entry.Payload)
	}
	if err := (systembackupsecurity.RegistrationCapacity{ReportFile: p.gate.Records.CapacityReportFile}).ReserveExecutionPayload(ctx, tx, capacity, total); err != nil {
		return err
	}
	for start := 0; start < len(p.entries); start += 256 {
		if err := ce.RegisterSQL(ctx, tx, p.root.Scope, p.entries[start:min(start+256, len(p.entries))], now.Add(time.Duration(retention)*time.Second)); err != nil {
			return err
		}
	}
	if p.checkRedisReadServiceNative(ctx) != nil || p.checkMinIOReadServiceNative(ctx) != nil {
		return ErrSourceRecoveryProofRequired
	}
	return p.gate.Recovery.CheckTx(ctx, tx, p.a)
}
