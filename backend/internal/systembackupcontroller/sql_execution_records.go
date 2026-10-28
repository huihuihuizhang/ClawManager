package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

var ErrExecutionRecord = errors.New("execution record unavailable or conflicting")
var ErrExecutionCommitUnknown = errors.New("execution record commit requires readback")

// ExecutionRecordKeys returns a fresh caller-owned copy of the exact original
// task-scoped key. Empty reference selects the admitted current key; reads
// resolve the recorded version. Implementations must enforce A's purpose,
// resource and revocation policy. The store clears every returned key.
type ExecutionRecordKeys interface {
	Resolve(context.Context, d.Authority, string) (string, []byte, error)
}

// SQLExecutionRecords stores observations, never acceptance or a task terminal
// state. C's authenticated finalization transaction consumes these records.
// It uses the same authenticated staging format as plan custody; plaintext
// plans/checkpoints and keys never enter SQL. No provider call occurs in a Tx.
type SQLExecutionRecords struct {
	Authority          SQLExecutionAuthority
	Keys               ExecutionRecordKeys
	CapacityReportFile string
}

func recordHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func recordBinding(a d.Authority, kind, digest string) staging.Binding {
	return staging.Binding{BackupID: a.TaskPublicID, Attempt: strconv.FormatUint(a.AttemptNo, 10), Path: a.InstallationID + "/" + a.Phase + "/" + kind, CaptureContextHash: a.ConfigSHA256, EnvelopeID: digest}
}

func (s SQLExecutionRecords) ready() bool {
	return s.Authority.DB != nil && s.Authority.DeploymentEnabled && !absentExecutionDependency(s.Authority.Authorization) && !absentExecutionDependency(s.Keys)
}

func (s SQLExecutionRecords) Ready(ctx context.Context) error {
	if !s.ready() || absentExecutionDependency(ctx) || ctx.Err() != nil {
		return d.ErrNotReady
	}
	// Reject a missing migration/read grant before the scheduler can claim.
	rows, err := s.Authority.DB.QueryContext(ctx, "SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE 1=0")
	if err != nil {
		return err
	}
	return rows.Close()
}

func (s SQLExecutionRecords) write(ctx context.Context, a d.Authority, kind string, raw []byte) error {
	if !s.ready() || a.TaskType != "backup" || len(raw) < 2 || len(raw) > 8<<20 {
		return d.ErrNotReady
	}
	if err := s.Authority.Check(ctx, a); err != nil {
		return err
	}
	ref, key, err := s.Keys.Resolve(ctx, a, "")
	defer clear(key)
	if err != nil || ref == "" || len(ref) > 256 || len(key) != 32 {
		return ErrExecutionRecord
	}
	digest := recordHash(raw)
	var sealed bytes.Buffer
	if err := staging.Seal(ctx, &sealed, key, recordBinding(a, kind, digest), func(w io.Writer) error { _, e := w.Write(raw); return e }); err != nil {
		return ErrExecutionRecord
	}
	tx, err := s.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := s.Authority.Bind(ctx, tx, a)
	if err != nil {
		return err
	}
	var oldHash string
	err = tx.QueryRowContext(ctx, "SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind=? FOR SHARE", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, kind).Scan(&oldHash)
	if err == nil {
		if oldHash != digest {
			return ErrExecutionRecord
		}
		// This is an authoritative readback, including after an unknown commit.
		return g.Recheck(ctx, tx)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if s.CapacityReportFile != "" {
		var capacity int64
		if tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", a.InstallationID, a.ConfigVersion).Scan(&capacity) != nil {
			return ErrExecutionRecord
		}
		if err = (security.RegistrationCapacity{ReportFile: s.CapacityReportFile}).ReserveExecutionPayload(ctx, tx, capacity, sealed.Len()); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_execution_records (origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) VALUES (?,?,?,?,?,?,?,?)", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, kind, digest, ref, sealed.Bytes())
	if err != nil {
		return err
	}
	if err = g.Recheck(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}

func (s SQLExecutionRecords) read(ctx context.Context, a d.Authority, kind string) ([]byte, error) {
	if !s.ready() || a.TaskType != "backup" {
		return nil, d.ErrNotReady
	}
	if err := s.Authority.Check(ctx, a); err != nil {
		return nil, err
	}
	var ref, digest string
	var sealed []byte
	err := s.Authority.DB.QueryRowContext(ctx, "SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind=?", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, kind).Scan(&digest, &ref, &sealed)
	if err != nil {
		return nil, err
	}
	if len(sealed) > (8<<20)+4096 || !executionHash.MatchString(digest) {
		return nil, ErrExecutionRecord
	}
	resolved, key, err := s.Keys.Resolve(ctx, a, ref)
	defer clear(key)
	if err != nil || resolved != ref || len(key) != 32 {
		return nil, ErrExecutionRecord
	}
	plain := bytes.NewBuffer(make([]byte, 0, 8<<20))
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(sealed), plain, key, recordBinding(a, kind, digest), 8<<20) != nil || recordHash(plain.Bytes()) != digest {
		return nil, ErrExecutionRecord
	}
	if err := s.Authority.Check(ctx, a); err != nil {
		return nil, err
	}
	return bytes.Clone(plain.Bytes()), nil
}

func (s SQLExecutionRecords) SavePlan(ctx context.Context, in d.Input, plan d.Plan) error {
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	clear(inner.CanonicalJSON)
	if err != nil {
		return err
	}
	return s.write(ctx, in.Authority, "plan", plan.CanonicalJSON)
}

func (s SQLExecutionRecords) LoadPlan(ctx context.Context, in d.Input) (d.Plan, error) {
	raw, err := s.read(ctx, in.Authority, "plan")
	if err != nil {
		return d.Plan{}, err
	}
	plan := d.Plan{SchemaVersion: d.TaskPlanVersion, CanonicalJSON: raw, SHA256: recordHash(raw)}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	clear(inner.CanonicalJSON)
	if err != nil {
		clear(raw)
		return d.Plan{}, err
	}
	return plan, nil
}

// LoadRecoveryPlan decrypts ONLY the original plan under a separately issued
// recovery grant. It does not relax forward LoadPlan or permit source capture.
func (s SQLExecutionRecords) LoadRecoveryPlan(ctx context.Context, in d.Input, recovery SQLRecoveryAuthority) (d.Plan, error) {
	a := in.Authority
	if recovery.DB != s.Authority.DB || recovery.Identity == nil {
		return d.Plan{}, ErrExecutionAuthority
	}
	if e := recovery.Check(ctx, a); e != nil {
		return d.Plan{}, e
	}
	var digest, ref string
	var sealed []byte
	e := recovery.DB.QueryRowContext(ctx, "SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase=? AND record_kind='plan'", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase).Scan(&digest, &ref, &sealed)
	if e != nil {
		return d.Plan{}, e
	}
	if !executionHash.MatchString(digest) || len(sealed) > (8<<20)+4096 {
		return d.Plan{}, ErrExecutionRecord
	}
	actual, key, e := recovery.Identity.Resolve(ctx, a, ref)
	defer clear(key)
	if e != nil || actual != ref || len(key) != 32 {
		return d.Plan{}, ErrExecutionRecord
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(sealed), &plain, key, recordBinding(a, "plan", digest), 8<<20) != nil || recordHash(plain.Bytes()) != digest {
		return d.Plan{}, ErrExecutionRecord
	}
	p := d.Plan{SchemaVersion: d.TaskPlanVersion, CanonicalJSON: bytes.Clone(plain.Bytes()), SHA256: digest}
	inner, e := d.UnwrapTaskPlan(in, p, b.PlanVersion)
	clear(inner.CanonicalJSON)
	if e != nil {
		clear(p.CanonicalJSON)
		return d.Plan{}, e
	}
	if e = recovery.Check(ctx, a); e != nil {
		clear(p.CanonicalJSON)
		return d.Plan{}, e
	}
	return p, nil
}

type executionResultRecord struct {
	Version    string           `json:"schema_version"`
	PlanSHA256 string           `json:"plan_sha256"`
	Results    []d.ModuleResult `json:"results"`
	Failed     bool             `json:"failed"`
}

func decodeExecutionResult(raw []byte, planHash string) (ExecutionOutcome, error) {
	var r executionResultRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || r.Version != "system-backup-execution-result.v1" || r.PlanSHA256 != planHash {
		return ExecutionOutcome{}, ErrExecutionRecord
	}
	out := ExecutionOutcome{Results: r.Results}
	if r.Failed {
		out.Err = ErrExecutionRecord
	}
	return out, nil
}

// RecordCapture preserves partial observations and never serializes Err text.
// Failed=false only describes B returning nil; it is NOT finalizer acceptance.
func (s SQLExecutionRecords) RecordCapture(ctx context.Context, w ExecutionWork, out ExecutionOutcome) error {
	if w.Step != ExecutionCapture {
		return d.ErrNotReady
	}
	stored, err := s.LoadPlan(ctx, w.Input)
	if err != nil {
		return err
	}
	defer clear(stored.CanonicalJSON)
	if stored.SHA256 != w.Plan.SHA256 || !bytes.Equal(stored.CanonicalJSON, w.Plan.CanonicalJSON) {
		return ErrExecutionRecord
	}
	raw, err := json.Marshal(executionResultRecord{"system-backup-execution-result.v1", stored.SHA256, out.Results, out.Err != nil})
	if err != nil {
		return ErrExecutionRecord
	}
	defer clear(raw)
	return s.write(ctx, w.Input.Authority, "capture_result", raw)
}
