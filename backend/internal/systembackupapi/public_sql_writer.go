package systembackupapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// TaskRequestContract owns the reviewed closed request schema, duplicate-key
// rejection, defaults/null rules and normalization. There is deliberately no
// built-in empty-object request. Prepare is local and must not access providers.
type TaskRequestContract interface {
	Decode(context.Context, read.TaskKind, string, json.RawMessage) (NormalizedTaskRequest, error)
}

// CanonicalJSON is the business DTO after the schema's defaults and removal of
// explicitly excluded transport/auth fields, encoded as JCS. The original plan
// hashes exactly these bytes; installation/actor/endpoint belong to the unique
// tuple, and are not an additional hash frame.
type NormalizedTaskRequest interface {
	CanonicalJSON() []byte
}

// TaskAdmission must use ONLY the caller's SQL capability, in the established
// domain lock order. It validates B/C readiness, trusted resource mappings,
// source/target restrictions, concurrency and physical metadata capacity, and
// reserves capacity for the task, full config copy, event and audit together.
// It must not commit, dispatch work, open another connection or contact a
// provider. Required external observations must already be deployment-owned.
type TaskAdmission interface {
	Admit(TaskWriteSQL, TaskSubmissionIdentity, TaskConfigSnapshot, read.TaskKind, []byte) (TaskCreation, TaskAdmissionGuard, error)
}

// Recheck checks the original reservation and all admission facts after audit.
// ValidUntil is an ORIGINAL strict expiry, never a renewed deadline.
type TaskAdmissionGuard interface {
	Recheck(TaskWriteSQL) error
	ValidUntil() time.Time
}

type TaskConfigSnapshot struct {
	Version, InstallationRowVersion uint64
	CanonicalJSON                   []byte
	SHA256, Matrix                  string
	DeadlineSeconds                 uint64
}

func (TaskConfigSnapshot) MarshalJSON() ([]byte, error) { return nil, &Error{"not_ready"} }

// These are trusted admission outputs, never fields copied from HTTP JSON.
// Every inserted column is fixed here; no caller can supply SQL identifiers.
type TaskCreation struct {
	Backup    *BackupCreation
	Preflight *PreflightCreation
}
type BackupCreation struct {
	Orchestrator, Profile, Runner, Purpose                                           string
	Parts, TargetRisks                                                               []string
	TargetClass, FailureDomain                                                       string
	ArtifactReadIdentity, ArtifactReadVersion, ArtifactCAIdentity, ArtifactCAVersion string
}
type PreflightCreation struct {
	SourceType, SourcePublicID, Mode, TargetProfile, TargetConfigRef, TargetConfigHash string
	SourceManifest, SourceAcceptance, SourceCatalog                                    *string
	Compatibility                                                                      string
}

type PublicSQLTaskWriter struct {
	contract          TaskRequestContract
	admission         TaskAdmission
	deploymentEnabled bool
}

// deploymentEnabled is the trusted deployment switch, not a request value or
// the installation's last_effective_enabled hint. Missing owners reject
// construction; this persistence core does not certify their readiness.
func NewPublicSQLTaskWriter(contract TaskRequestContract, admission TaskAdmission, deploymentEnabled bool) (*PublicSQLTaskWriter, error) {
	if nilDependency(contract) || nilDependency(admission) {
		return nil, &Error{"not_ready"}
	}
	return &PublicSQLTaskWriter{contract, admission, deploymentEnabled}, nil
}

type preparedSQLTaskWrite struct {
	writer    *PublicSQLTaskWriter
	ctx       context.Context
	kind      read.TaskKind
	endpoint  string
	request   NormalizedTaskRequest
	canonical []byte
	used      atomic.Bool
}

func (w *PublicSQLTaskWriter) Prepare(ctx context.Context, kind read.TaskKind, endpoint string, raw json.RawMessage) (PreparedTaskWrite, error) {
	_, expected, _ := taskRoute(kind)
	if w == nil || nilDependency(w.contract) || nilDependency(w.admission) || ctx == nil || ctx.Err() != nil {
		return nil, &Error{"not_ready"}
	}
	if expected == "" || endpoint != expected || len(raw) < 2 || len(raw) > maxTaskBody {
		return nil, &Error{"validation_failed"}
	}
	r, err := w.contract.Decode(ctx, kind, endpoint, append(json.RawMessage(nil), raw...))
	if err != nil {
		return nil, err
	}
	if nilDependency(r) {
		return nil, &Error{"not_ready"}
	}
	canonical := append([]byte(nil), r.CanonicalJSON()...)
	if len(canonical) < 2 || len(canonical) > maxTaskBody || !json.Valid(canonical) || canonical[0] != '{' || canonical[len(canonical)-1] != '}' || ctx.Err() != nil {
		return nil, &Error{"not_ready"}
	}
	return &preparedSQLTaskWrite{writer: w, ctx: ctx, kind: kind, endpoint: endpoint, request: r, canonical: canonical}, nil
}

var taskWriterInstallation = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var taskWriterHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var taskWriterValue = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

const writerHeaderColumns = "id,public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,retry_of_public_id,status,pending_reason,attention_reason,can_cancel,config_version,retryable,failure_category,row_version,deadline_at,created_at,updated_at"

func writerTable(kind read.TaskKind) string {
	if kind == read.BackupTask {
		return "system_backup_v2_backups"
	}
	if kind == read.PreflightTask {
		return "system_backup_v2_preflights"
	}
	return ""
}

func writerScan(row TaskRow, kind read.TaskKind) (read.TaskHeader, error) {
	t := read.TaskHeader{Kind: kind}
	err := row.Scan(&t.ID, &t.PublicID, &t.InstallationID, &t.ActorType, &t.ActorID, &t.Endpoint, &t.IdempotencyKey, &t.RequestHash, &t.RequestID, &t.RetryOfPublicID, &t.Status, &t.PendingReason, &t.AttentionReason, &t.CanCancel, &t.ConfigVersion, &t.Retryable, &t.FailureCategory, &t.RowVersion, &t.DeadlineAt, &t.CreatedAt, &t.UpdatedAt)
	if err == nil {
		_, err = read.ProjectTask(t)
	}
	return t, err
}

func (p *preparedSQLTaskWrite) Stage(q TaskWriteSQL, identity TaskSubmissionIdentity) (read.TaskHeader, error) {
	var zero read.TaskHeader
	fail := func() (read.TaskHeader, error) { return zero, &Error{"not_ready"} }
	if p == nil || !p.used.CompareAndSwap(false, true) || p.ctx == nil || p.ctx.Err() != nil || nilDependency(q) {
		return fail()
	}
	actor, err := strconv.ParseInt(identity.ActorID, 10, 64)
	if err != nil || actor < 1 || strconv.FormatInt(actor, 10) != identity.ActorID || !taskWriterInstallation.MatchString(identity.InstallationID) || identity.Endpoint != p.endpoint || !token.MatchString(identity.IdempotencyKey) {
		return fail()
	}
	digest := sha256.Sum256(p.canonical)
	hash := hex.EncodeToString(digest[:])
	if !bytes.Equal(p.canonical, p.request.CanonicalJSON()) {
		return fail()
	}
	// Serialize new submissions with config/kill-switch transitions before
	// looking up the full idempotency tuple. This also closes absent-key races.
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine) != nil {
		return fail()
	}
	var active, stateVersion uint64
	var effective bool
	var matrix string
	if q.QueryRow("SELECT active_config_version,row_version,last_effective_enabled,matrix_key FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", identity.InstallationID).Scan(&active, &stateVersion, &effective, &matrix) != nil || active == 0 || stateVersion == 0 {
		return fail()
	}
	table := writerTable(p.kind)
	where := " WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=?"
	keyArgs := []any{identity.InstallationID, identity.ActorID, identity.Endpoint, identity.IdempotencyKey}
	original, err := writerScan(q.QueryRow("SELECT "+writerHeaderColumns+" FROM "+table+where+" FOR UPDATE", keyArgs...), p.kind)
	if err == nil {
		if original.RequestHash != hash {
			return zero, &Error{"idempotency_conflict"}
		}
		// Original task/deadline/config/schedule are immutable on replay, also
		// after a lost commit response. A reauthorizes before and after Stage.
		return original, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fail()
	}
	var retiredHash, retiredKind, retiredID, retiredStatus, retiredFailure string
	err = q.QueryRow("SELECT request_hash,source_type,source_public_id,terminal_status,failure_category FROM system_backup_v2_compact_tombstones"+where+" FOR UPDATE", keyArgs...).Scan(&retiredHash, &retiredKind, &retiredID, &retiredStatus, &retiredFailure)
	if err == nil {
		if retiredHash != hash {
			return zero, &Error{"idempotency_conflict"}
		}
		_, _, prefix := taskRoute(p.kind)
		if retiredKind != string(p.kind) || len(retiredID) != 40 || !strings.HasPrefix(retiredID, prefix) || !uuid.MatchString(retiredID[4:]) || !writerEnum(retiredStatus, "succeeded", "failed", "canceled") || !writerEnum(retiredFailure, contract.FailureCategories...) {
			return fail()
		}
		return zero, &ExpiredTaskError{retiredID, retiredStatus, retiredFailure}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fail()
	}
	// The original plan checks authorized history before the new-work kill
	// switch. An exact replay above creates no reservation, event or work.
	if !p.writer.deploymentEnabled || !effective {
		return fail()
	}
	config, err := writerConfig(q, identity.InstallationID, p.kind, active, stateVersion, matrix)
	if err != nil {
		return fail()
	}
	admissionConfig := config
	admissionConfig.CanonicalJSON = append([]byte(nil), config.CanonicalJSON...)
	creation, guard, err := p.writer.admission.Admit(q, identity, admissionConfig, p.kind, append([]byte(nil), p.canonical...))
	if err != nil {
		return zero, err
	}
	if nilDependency(guard) {
		return fail()
	}
	until := guard.ValidUntil()
	if until.IsZero() {
		return fail()
	}
	now, err := writerClock(q, time.Time{}, until)
	if err != nil {
		return fail()
	}
	_, _, prefix := taskRoute(p.kind)
	id, err := writerID(prefix)
	if err != nil {
		return fail()
	}
	requestID, _ := p.ctx.Value(taskRequestIDKey{}).(string)
	if !taskWriterValue.MatchString(requestID) {
		requestID, err = writerID("")
		if err != nil {
			return fail()
		}
	}
	columns := []string{"public_id", "origin_installation_id", "actor_type", "actor_id", "endpoint", "idempotency_key", "request_hash", "request_id", "config_version", "config_snapshot_json", "config_snapshot_size_bytes", "config_snapshot_sha256", "next_reconcile_at", "deadline_at", "created_at", "updated_at"}
	args := []any{id, identity.InstallationID, "admin", identity.ActorID, identity.Endpoint, identity.IdempotencyKey, hash, requestID, config.Version, config.CanonicalJSON, len(config.CanonicalJSON), config.SHA256, now, now.Add(time.Duration(config.DeadlineSeconds) * time.Second), now, now}
	ownerColumns, ownerArgs, err := writerCreation(p.kind, config, creation)
	if err != nil {
		return fail()
	}
	columns = append(columns, ownerColumns...)
	args = append(args, ownerArgs...)
	marks := strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")
	if !writerOne(q.Exec("INSERT INTO "+table+" ("+strings.Join(columns, ",")+") VALUES ("+marks+")", args...)) {
		return fail()
	}
	if inputs, ok := guard.(taskInputGuard); ok {
		if err := inputs.storeInputs(q, id); err != nil {
			return fail()
		}
	}
	// This durable receipt observes the initial scheduling decision even after
	// the controller clears next_reconcile_at at terminal. Replays add no row.
	if !writerOne(q.Exec("INSERT INTO system_backup_v2_events (origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id,created_at) VALUES (?,?,?,'diagnostic.d.task_enqueued','info','pending','Task durably scheduled',?,?)", identity.InstallationID, string(p.kind), id, requestID, now)) {
		return fail()
	}
	audit, _ := json.Marshal(map[string]any{"origin_installation_id": identity.InstallationID, "task_public_id": id, "task_type": p.kind, "endpoint": identity.Endpoint, "request_hash": hash, "config_version": config.Version, "request_id": requestID})
	if !writerOne(q.Exec("INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", actor, "system_backup.task_create", string(audit))) {
		return fail()
	}
	if guard.Recheck(q) != nil || !guard.ValidUntil().Equal(until) {
		return fail()
	}
	// No owner callback follows these fixed final guards.
	var finalActive, finalVersion uint64
	var finalEffective bool
	var finalMatrix string
	if q.QueryRow("SELECT active_config_version,row_version,last_effective_enabled,matrix_key FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", identity.InstallationID).Scan(&finalActive, &finalVersion, &finalEffective, &finalMatrix) != nil || finalActive != active || finalVersion != stateVersion || !finalEffective || finalMatrix != matrix {
		return fail()
	}
	finalConfig, err := writerConfig(q, identity.InstallationID, p.kind, active, stateVersion, matrix)
	if err != nil || finalConfig.SHA256 != config.SHA256 || finalConfig.DeadlineSeconds != config.DeadlineSeconds || !bytes.Equal(finalConfig.CanonicalJSON, config.CanonicalJSON) {
		return fail()
	}
	final, err := writerScan(q.QueryRow("SELECT "+writerHeaderColumns+" FROM "+table+" WHERE origin_installation_id=? AND public_id=? FOR UPDATE", identity.InstallationID, id), p.kind)
	if err != nil || final.RequestHash != hash || final.Status != "pending" || final.RowVersion != 1 || final.ConfigVersion != active || final.RequestID != requestID || !final.CreatedAt.Equal(now) || !final.DeadlineAt.Equal(now.Add(time.Duration(config.DeadlineSeconds)*time.Second)) {
		return fail()
	}
	var schedule time.Time
	var snapshot []byte
	var snapshotHash string
	var snapshotSize uint64
	if q.QueryRow("SELECT next_reconcile_at,config_snapshot_json,config_snapshot_sha256,config_snapshot_size_bytes FROM "+table+" WHERE origin_installation_id=? AND public_id=? FOR UPDATE", identity.InstallationID, id).Scan(&schedule, &snapshot, &snapshotHash, &snapshotSize) != nil || !schedule.Equal(now) || !bytes.Equal(snapshot, config.CanonicalJSON) || snapshotHash != config.SHA256 || snapshotSize != uint64(len(config.CanonicalJSON)) {
		return fail()
	}
	if _, err = writerClock(q, now, until); err != nil || p.ctx.Err() != nil {
		return fail()
	}
	return final, nil
}

func writerConfig(q TaskWriteSQL, installation string, kind read.TaskKind, version, stateVersion uint64, matrix string) (TaskConfigSnapshot, error) {
	c := TaskConfigSnapshot{Version: version, InstallationRowVersion: stateVersion, Matrix: matrix}
	column := "backup_task_deadline_seconds"
	if kind == read.PreflightTask {
		column = "preflight_task_deadline_seconds"
	}
	var size uint64
	var enabled bool
	if q.QueryRow("SELECT canonical_config_json,config_sha256,config_size_bytes,enabled,"+column+" FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", installation, version).Scan(&c.CanonicalJSON, &c.SHA256, &size, &enabled, &c.DeadlineSeconds) != nil || !enabled || size != uint64(len(c.CanonicalJSON)) {
		return c, &Error{"not_ready"}
	}
	values, err := security.DecodeConfigValues(c.CanonicalJSON)
	if err != nil || !values.Enabled() || values.SHA256() != c.SHA256 || !bytes.Equal(values.CanonicalJSON(), c.CanonicalJSON) {
		return c, &Error{"not_ready"}
	}
	var document struct {
		Durations map[string]uint64 `json:"durations"`
	}
	if json.Unmarshal(c.CanonicalJSON, &document) != nil || document.Durations[column] != c.DeadlineSeconds || c.DeadlineSeconds == 0 || c.DeadlineSeconds > 43200 {
		return c, &Error{"not_ready"}
	}
	c.CanonicalJSON = append([]byte(nil), c.CanonicalJSON...)
	return c, nil
}

func writerClock(q TaskWriteSQL, notBefore, until time.Time) (time.Time, error) {
	var now time.Time
	var offset int64
	if q.QueryRow("SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || now.IsZero() || offset != 0 || now.Before(notBefore) || !now.Before(until) {
		return time.Time{}, &Error{"not_ready"}
	}
	return now, nil
}
func writerOne(result sql.Result, err error) bool {
	if err != nil || result == nil {
		return false
	}
	n, err := result.RowsAffected()
	return err == nil && n == 1
}
func writerID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s%s-%s-%s-%s-%s", prefix, s[:8], s[8:12], s[12:16], s[16:20], s[20:]), nil
}

func writerCreation(kind read.TaskKind, c TaskConfigSnapshot, creation TaskCreation) ([]string, []any, error) {
	fail := func() ([]string, []any, error) { return nil, nil, &Error{"not_ready"} }
	if kind == read.BackupTask {
		b := creation.Backup
		if b == nil || creation.Preflight != nil || !writerEnum(b.Orchestrator, "kubernetes", "k3s") || !writerEnum(b.Profile, "cluster", "single-node") || !writerEnum(b.Purpose, "acceptance", "functional_test") || !writerEnum(b.TargetClass, "dr-ready-external", "same-cluster-copy") || !taskWriterValue.MatchString(b.FailureDomain) || !taskWriterHash.MatchString(b.ArtifactReadIdentity) || !taskWriterHash.MatchString(b.ArtifactCAIdentity) || !taskWriterValue.MatchString(b.ArtifactReadVersion) || !taskWriterValue.MatchString(b.ArtifactCAVersion) {
			return fail()
		}
		runner := "k8s"
		if b.Orchestrator == "k3s" {
			runner = "k3s"
		}
		if b.Runner != runner || c.Matrix != runner+"-"+b.Profile {
			return fail()
		}
		parts, ok := writerSet(b.Parts, false, "mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle")
		if !ok {
			return fail()
		}
		risks, ok := writerSet(b.TargetRisks, true, "source_overlap", "same_failure_domain", "artifact_credential_source_dependent", "kek_source_dependent", "signing_key_source_dependent", "catalog_source_dependent", "attestation_missing", "attestation_expired", "conditional_commit_unavailable", "transport_unverified", "broad_egress", "provider_capability_degraded")
		if !ok {
			return fail()
		}
		return []string{"source_orchestrator", "source_profile", "matrix_key", "datasource_topology", "runner", "task_purpose", "requested_parts", "target_class", "target_risks", "target_failure_domain_id", "artifact_read_identity_hash", "artifact_read_ref_version", "artifact_ca_identity_hash", "artifact_ca_ref_version"}, []any{b.Orchestrator, b.Profile, c.Matrix, "in_cluster", b.Runner, b.Purpose, parts, b.TargetClass, risks, b.FailureDomain, b.ArtifactReadIdentity, b.ArtifactReadVersion, b.ArtifactCAIdentity, b.ArtifactCAVersion}, nil
	}
	p := creation.Preflight
	if p == nil || creation.Backup != nil || !writerEnum(p.SourceType, "backup", "catalog_import") || !writerEnum(p.Mode, "production_readonly", "functional_test") || !writerEnum(p.TargetProfile, "cluster", "single-node") || !taskWriterValue.MatchString(p.TargetConfigRef) || !taskWriterHash.MatchString(p.TargetConfigHash) || !writerEnum(p.Compatibility, "supported", "compatible_with_warnings", "unsupported") {
		return fail()
	}
	prefix := "sbk_"
	if p.SourceType == "catalog_import" {
		prefix = "sci_"
	}
	if len(p.SourcePublicID) != 40 || !strings.HasPrefix(p.SourcePublicID, prefix) || !uuid.MatchString(p.SourcePublicID[4:]) {
		return fail()
	}
	for _, hash := range []*string{p.SourceManifest, p.SourceAcceptance, p.SourceCatalog} {
		if hash != nil && !taskWriterHash.MatchString(*hash) {
			return fail()
		}
	}
	return []string{"source_artifact_type", "source_public_id", "source_manifest_checksum", "source_acceptance_checksum", "source_catalog_checksum", "preflight_mode", "target_profile", "restore_target_config_ref", "restore_target_config_hash", "artifact_compatibility"}, []any{p.SourceType, p.SourcePublicID, p.SourceManifest, p.SourceAcceptance, p.SourceCatalog, p.Mode, p.TargetProfile, p.TargetConfigRef, p.TargetConfigHash, p.Compatibility}, nil
}
func writerEnum(value string, values ...string) bool {
	for _, v := range values {
		if value == v {
			return true
		}
	}
	return false
}
func writerSet(values []string, empty bool, allowed ...string) (string, bool) {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] || !writerEnum(v, allowed...) {
			return "", false
		}
		seen[v] = true
	}
	if !empty && len(values) == 0 {
		return "", false
	}
	ordered := []string{}
	for _, v := range allowed {
		if seen[v] {
			ordered = append(ordered, v)
		}
	}
	return strings.Join(ordered, ","), true
}
