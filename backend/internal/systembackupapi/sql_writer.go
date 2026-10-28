package systembackupapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	contract "clawreef/internal/systembackupcontract"
	deployment "clawreef/internal/systembackupdeployment"
	read "clawreef/internal/systembackupread"
	uuidlib "github.com/google/uuid"
)

var profileToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var profileHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var installationToken = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var allBackupParts = []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}

// ExecutionProfile is deployment-owned, never accepted as a user request.
// References are immutable identifiers, not paths, credentials or URLs.
type ExecutionProfile deployment.ExecutionProfile

func (p ExecutionProfile) canonical() ([]byte, string, error) {
	raw, digest, e := deployment.ExecutionProfile(p).CanonicalIdentity()
	if e != nil {
		return nil, "", &Error{"validation_failed"}
	}
	return raw, digest, nil
}
func (p ExecutionProfile) CanonicalIdentity() ([]byte, string, error) { return p.canonical() }
func LoadExecutionProfile(path string) (ExecutionProfile, error) {
	p, e := deployment.LoadExecutionProfile(path)
	if e != nil {
		if profileError, ok := e.(*deployment.ProfileError); ok {
			return ExecutionProfile{}, &Error{profileError.Code}
		}
		return ExecutionProfile{}, &Error{"not_ready"}
	}
	return ExecutionProfile(p), nil
}

type BackupCreateRequest struct {
	Purpose string   `json:"task_purpose"`
	Parts   []string `json:"requested_parts"`
}
type PreflightCreateRequest struct {
	SourcePublicID string `json:"source_public_id"`
	Mode           string `json:"preflight_mode"`
}

// SQLTaskWriter has no provider client or Commit method. It only stages a
// durable task inside SQLApplication's current authorized transaction.
type SQLTaskWriter struct {
	profile      ExecutionProfile
	raw          []byte
	hash         string
	capacityFile string
}

func NewSQLTaskWriter(p ExecutionProfile) (*SQLTaskWriter, error) {
	raw, hash, err := p.canonical()
	if err != nil {
		return nil, err
	}
	// Deep-copy via canonical bytes so later caller slice edits cannot change it.
	var immutable ExecutionProfile
	if json.Unmarshal(raw, &immutable) != nil {
		return nil, &Error{"validation_failed"}
	}
	return &SQLTaskWriter{profile: immutable, raw: raw, hash: hash}, nil
}

// WithCapacityReport returns a copy bound to a trusted, read-only DB-side
// capacity report. An absent/stale report rejects new admissions, never replay.
func (w *SQLTaskWriter) WithCapacityReport(path string) *SQLTaskWriter {
	if w == nil {
		return nil
	}
	copy := *w
	copy.capacityFile = path
	return &copy
}

type preparedSQLTask struct {
	writer                        *SQLTaskWriter
	kind                          read.TaskKind
	endpoint, hash, id, requestID string
	body                          []byte
	backup                        BackupCreateRequest
	preflight                     PreflightCreateRequest
}

func (w *SQLTaskWriter) Prepare(ctx context.Context, kind read.TaskKind, endpoint string, raw json.RawMessage) (PreparedTaskWrite, error) {
	_, want, prefix := taskRoute(kind)
	if w == nil || ctx == nil || ctx.Err() != nil || want == "" || endpoint != want {
		return nil, &Error{"not_ready"}
	}
	p := &preparedSQLTask{writer: w, kind: kind, endpoint: endpoint, id: prefix + uuidlib.NewString(), requestID: uuidlib.NewString()}
	if kind == read.BackupTask {
		if closedJSON(raw, &p.backup) != nil {
			return nil, &Error{"validation_failed"}
		}
		if p.backup.Purpose == "" {
			p.backup.Purpose = "acceptance"
		}
		if p.backup.Parts == nil {
			p.backup.Parts = append([]string{}, allBackupParts...)
		}
		if !slices.Contains([]string{"acceptance", "functional_test"}, p.backup.Purpose) || len(p.backup.Parts) == 0 {
			return nil, &Error{"validation_failed"}
		}
		seen := map[string]bool{}
		for _, part := range p.backup.Parts {
			if !slices.Contains(allBackupParts, part) || seen[part] {
				return nil, &Error{"validation_failed"}
			}
			seen[part] = true
		}
		if p.backup.Purpose == "acceptance" && len(seen) != len(allBackupParts) {
			return nil, &Error{"validation_failed"}
		}
		// SET order follows the registry, independent of request array order.
		p.backup.Parts = []string{}
		for _, part := range allBackupParts {
			if seen[part] {
				p.backup.Parts = append(p.backup.Parts, part)
			}
		}
		p.body, _ = json.Marshal(p.backup)
	} else {
		if closedJSON(raw, &p.preflight) != nil || !validSourceBackupID(p.preflight.SourcePublicID) {
			return nil, &Error{"validation_failed"}
		}
		if p.preflight.Mode == "" {
			p.preflight.Mode = "production_readonly"
		}
		if !slices.Contains([]string{"production_readonly", "functional_test"}, p.preflight.Mode) {
			return nil, &Error{"validation_failed"}
		}
		p.body, _ = json.Marshal(p.preflight)
	}
	p.hash = digestJSON(p.body)
	return p, nil
}

func validSourceBackupID(id string) bool {
	return strings.HasPrefix(id, "sbk_") && len(id) == 40 && uuid.MatchString(id[4:])
}
func digestJSON(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Reject duplicate keys as well as unknown fields, null, trailing JSON and
// non-object bodies. encoding/json alone silently accepts duplicate keys.
func closedJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 16384 {
		return &Error{"validation_failed"}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{':
				keys := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					if !ok || keys[key] {
						return errors.New("duplicate")
					}
					keys[key] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("delimiter")
			}
			_, err = d.Token()
			return err
		}
		if t == nil {
			return errors.New("null")
		}
		return nil
	}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 || trim[0] != '{' || walk(0) != nil {
		return &Error{"validation_failed"}
	}
	if _, err := d.Token(); err != io.EOF {
		return &Error{"validation_failed"}
	}
	// encoding/json accepts case-insensitive field aliases even with
	// DisallowUnknownFields. Our request/profile contract has exact keys.
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer || typ.Elem().Kind() != reflect.Struct {
		return &Error{"validation_failed"}
	}
	allowed := map[string]bool{}
	for i := 0; i < typ.Elem().NumField(); i++ {
		allowed[strings.Split(typ.Elem().Field(i).Tag.Get("json"), ",")[0]] = true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return &Error{"validation_failed"}
	}
	for key := range fields {
		if !allowed[key] {
			return &Error{"validation_failed"}
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return &Error{"validation_failed"}
	}
	return nil
}

func (p *preparedSQLTask) Stage(q TaskWriteSQL, identity TaskSubmissionIdentity) (read.TaskHeader, error) {
	var zero read.TaskHeader
	if p == nil || q == nil || identity.InstallationID != p.writer.profile.InstallationID || identity.Endpoint != p.endpoint || !token.MatchString(identity.IdempotencyKey) {
		return zero, &Error{"permission_denied"}
	}
	actor, err := strconv.ParseInt(identity.ActorID, 10, 64)
	if err != nil || actor <= 0 {
		return zero, &Error{"permission_denied"}
	}
	// Same lock order as engine selection and shared gate admission. Replays
	// remain readable when the engine/config/readiness has since changed.
	var engine string
	if q.QueryRow("SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine) != nil {
		return zero, &Error{"not_ready"}
	}
	table := "system_backup_v2_backups"
	if p.kind == read.PreflightTask {
		table = "system_backup_v2_preflights"
	}
	replaySQL := "SELECT " + read.SubmissionTaskColumns() + " FROM " + table + " WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE"
	previous, err := read.ScanSubmissionTask(q.QueryRow(replaySQL, identity.InstallationID, identity.ActorID, identity.Endpoint, identity.IdempotencyKey), p.kind, identity.InstallationID)
	if err == nil {
		if previous.RequestHash != p.hash {
			return zero, &Error{"idempotency_conflict"}
		}
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, &Error{"not_ready"}
	}
	if engine != "v2" {
		return zero, &Error{"not_ready"}
	}
	cfg, err := read.ReadAdmissionConfig(func(s string, args ...any) read.AdmissionRow { return q.QueryRow(s, args...) }, identity.InstallationID)
	if err != nil {
		return zero, &Error{"not_ready"}
	}
	var values contract.ConfigValues
	if json.Unmarshal(cfg.Canonical, &values) != nil || !values.Enabled {
		return zero, &Error{"not_ready"}
	}
	runner := "k8s"
	if p.writer.profile.Orchestrator == "k3s" {
		runner = "k3s"
	}
	matrix := runner + "-" + p.writer.profile.Profile
	var actualMatrix string
	if q.QueryRow("SELECT matrix_key FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", identity.InstallationID).Scan(&actualMatrix) != nil || actualMatrix != matrix {
		return zero, &Error{"not_ready"}
	}
	if p.kind == read.BackupTask && p.backup.Purpose == "acceptance" && (p.writer.profile.TargetClass != "dr-ready-external" || len(p.writer.profile.TargetRisks) != 0) {
		return zero, &Error{"backup_target_risk_rejected"}
	}
	// Read the database clock; neither caller timestamps nor stale process
	// health can make an execution adapter ready.
	var now time.Time
	if q.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return zero, &Error{"not_ready"}
	}
	if err = p.ready(q, identity.InstallationID, cfg.Version); err != nil {
		return zero, err
	}
	var pending uint64
	const countSQL = `SELECT (SELECT COUNT(*) FROM system_backup_v2_backups WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_preflights WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_restore_drills WHERE origin_installation_id=? AND status='pending') + (SELECT COUNT(*) FROM system_backup_v2_artifact_verifications WHERE origin_installation_id=? AND status='pending')`
	if q.QueryRow(countSQL, identity.InstallationID, identity.InstallationID, identity.InstallationID, identity.InstallationID).Scan(&pending) != nil {
		return zero, &Error{"not_ready"}
	}
	if values.Concurrency.MaxPendingTasks < 1 || pending >= uint64(values.Concurrency.MaxPendingTasks) {
		return zero, &Error{"capacity_exceeded"}
	}
	if err = p.reserveCapacity(q, values.Capacity.ControlMetadataCapacityBytes, len(cfg.Canonical)); err != nil {
		return zero, err
	}
	seconds := values.Durations.BackupTaskDeadlineSeconds
	if p.kind == read.PreflightTask {
		seconds = values.Durations.PreflightTaskDeadlineSeconds
	}
	if seconds <= 0 || seconds > 7*24*3600 {
		return zero, &Error{"not_ready"}
	}
	deadline := now.Add(time.Duration(seconds) * time.Second)
	columns := "public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,next_reconcile_at,created_at,updated_at"
	args := []any{p.id, identity.InstallationID, "admin", identity.ActorID, identity.Endpoint, identity.IdempotencyKey, p.hash, p.requestID, cfg.Version, []byte(cfg.Canonical), len(cfg.Canonical), cfg.SHA256, deadline, now, now, now}
	if p.kind == read.BackupTask {
		ref := map[string]contract.ConfigReference{}
		for _, r := range values.References {
			ref[r.Purpose] = r
		}
		columns += ",source_orchestrator,source_profile,matrix_key,runner,task_purpose,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id"
		args = append(args, p.writer.profile.Orchestrator, p.writer.profile.Profile, matrix, runner, p.backup.Purpose, strings.Join(p.backup.Parts, ","), ref["artifact_read"].IdentityHash, ref["artifact_read"].Version, ref["artifact_ca"].IdentityHash, ref["artifact_ca"].Version, p.writer.profile.TargetClass, strings.Join(p.writer.profile.TargetRisks, ","), p.writer.profile.FailureDomain)
	} else {
		var manifest, acceptance sql.NullString
		var usable bool
		if q.QueryRow("SELECT manifest_checksum,acceptance_checksum,artifact_usable FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND status='succeeded' AND artifact_state='committed' FOR SHARE", identity.InstallationID, p.preflight.SourcePublicID).Scan(&manifest, &acceptance, &usable) != nil || !usable || !manifest.Valid {
			return zero, &Error{"artifact_unavailable"}
		}
		columns += ",source_artifact_type,source_public_id,source_manifest_checksum,source_acceptance_checksum,preflight_mode,target_profile,restore_target_config_ref,restore_target_config_hash,artifact_compatibility"
		// Compatibility is only a format capability, never a report success.
		args = append(args, "backup", p.preflight.SourcePublicID, manifest, acceptance, p.preflight.Mode, p.writer.profile.Profile, p.writer.profile.RestoreTargetRef, p.writer.profile.RestoreTargetHash, "supported")
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	if _, err = q.Exec("INSERT INTO "+table+" ("+columns+") VALUES ("+marks+")", args...); err != nil {
		return zero, &Error{"not_ready"}
	}
	if _, err = q.Exec("INSERT INTO system_backup_v2_execution_inputs(origin_installation_id,task_public_id,task_type,profile_json,profile_sha256,request_json) VALUES(?,?,?,?,?,?)", identity.InstallationID, p.id, string(p.kind), p.writer.raw, p.writer.hash, p.body); err != nil {
		return zero, &Error{"not_ready"}
	}
	if _, err = q.Exec("INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id) VALUES(?,?,?,'task_status_changed','info','pending','Task admitted',?)", identity.InstallationID, string(p.kind), p.id, p.requestID); err != nil {
		return zero, &Error{"not_ready"}
	}
	if err = p.ready(q, identity.InstallationID, cfg.Version); err != nil {
		return zero, err
	}
	return read.ScanSubmissionTask(q.QueryRow("SELECT "+read.SubmissionTaskColumns()+" FROM "+table+" WHERE origin_installation_id=? AND public_id=?", identity.InstallationID, p.id), p.kind, identity.InstallationID)
}

func (p *preparedSQLTask) ready(q TaskWriteSQL, installation string, config uint64) error {
	var ready bool
	if q.QueryRow(`SELECT ready AND expires_at>UTC_TIMESTAMP(6) AND checked_at<=UTC_TIMESTAMP(6)
FROM system_backup_v2_execution_readiness WHERE origin_installation_id=? AND task_type=? AND config_version=? AND profile_sha256=? FOR SHARE`, installation, string(p.kind), config, p.writer.hash).Scan(&ready) != nil || !ready {
		return &Error{"not_ready"}
	}
	return nil
}
