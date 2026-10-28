// Package systembackupexecution composes durable execution with the public v2
// task authority. Providers never receive a second writable task store.
package systembackupexecution

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	contract "clawreef/internal/systembackupcontract"
	controller "clawreef/internal/systembackupcontroller"
	dispatch "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

var ErrPlan = errors.New("execution plan unavailable or inconsistent")
var planToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type PlanCipher struct {
	current string
	keys    map[string]cipher.AEAD
}

func (PlanCipher) String() string               { return "PlanCipher[redacted]" }
func (PlanCipher) GoString() string             { return "PlanCipher[redacted]" }
func (PlanCipher) MarshalJSON() ([]byte, error) { return nil, ErrPlan }

func NewPlanCipher(current string, keys map[string][]byte) (*PlanCipher, error) {
	if !planToken.MatchString(current) || len(keys) == 0 || len(keys) > 8 {
		return nil, ErrPlan
	}
	c := &PlanCipher{current: current, keys: map[string]cipher.AEAD{}}
	for version, key := range keys {
		if !planToken.MatchString(version) || len(key) != 32 {
			return nil, ErrPlan
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrPlan
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrPlan
		}
		c.keys[version] = aead
	}
	if c.keys[current] == nil {
		return nil, ErrPlan
	}
	return c, nil
}

type PlanStore struct {
	DB                 *sql.DB
	InstallationID     string
	Cipher             *PlanCipher
	CapacityReportFile string
}
type planRecord struct {
	schema, profile, config, hash, key string
	nonce, body                        []byte
}

func planHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func planAAD(installation, id string, r planRecord) []byte {
	b, _ := json.Marshal([]string{"system-backup-execution-plan.aead.v1", installation, id, r.schema, r.profile, r.config, r.hash, r.key})
	return b
}
func (s PlanStore) open(id string, r planRecord) (dispatch.Plan, error) {
	if s.Cipher == nil {
		return dispatch.Plan{}, ErrPlan
	}
	aead := s.Cipher.keys[r.key]
	if aead == nil || len(r.nonce) != aead.NonceSize() || len(r.body) < 18 || len(r.body) > 65552 {
		return dispatch.Plan{}, ErrPlan
	}
	raw, err := aead.Open(nil, r.nonce, r.body, planAAD(s.InstallationID, id, r))
	if err != nil {
		return dispatch.Plan{}, ErrPlan
	}
	if !json.Valid(raw) || planHash(raw) != r.hash {
		clear(raw)
		return dispatch.Plan{}, ErrPlan
	}
	return dispatch.Plan{SchemaVersion: r.schema, CanonicalJSON: raw, SHA256: r.hash}, nil
}

// lock validates the current claim before exposing any decrypted plan. Plans
// cannot be read via old controller tokens or cross-installation task IDs.
func (s PlanStore) lock(ctx context.Context, tx *sql.Tx, claim controller.ClaimToken) (profile, config string, capacity int64, err error) {
	if s.Cipher == nil || claim.Target.Kind != controller.TargetBackup || claim.Owner == "" || claim.RowVersion == 0 {
		return "", "", 0, ErrPlan
	}
	var engine, status string
	var valid bool
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine)
	if err != nil || engine != "v2" {
		return "", "", 0, ErrPlan
	}
	err = tx.QueryRowContext(ctx, `SELECT b.status,b.config_snapshot_sha256,b.config_snapshot_json,i.profile_sha256,
b.controller_owner=? AND b.row_version=? AND b.controller_lease_expires_at>UTC_TIMESTAMP(6)
FROM system_backup_v2_backups b JOIN system_backup_v2_execution_inputs i ON i.origin_installation_id=b.origin_installation_id AND i.task_public_id=b.public_id AND i.task_type='backup'
WHERE b.origin_installation_id=? AND b.public_id=? FOR UPDATE`, claim.Owner, claim.RowVersion, s.InstallationID, claim.Target.PublicID).Scan(&status, &config, &raw, &profile, &valid)
	if err != nil {
		return "", "", 0, err
	}
	if !valid || status == "pending" || status == "succeeded" || status == "failed" || status == "canceled" {
		return "", "", 0, controller.ErrClaimLost
	}
	var cfg contract.ConfigValues
	if planHash(raw) != config || json.Unmarshal(raw, &cfg) != nil {
		return "", "", 0, ErrPlan
	}
	return profile, config, cfg.Capacity.ControlMetadataCapacityBytes, nil
}

func readPlan(ctx context.Context, tx *sql.Tx, installation, id string) (planRecord, error) {
	var r planRecord
	err := tx.QueryRowContext(ctx, `SELECT schema_version,profile_sha256,config_sha256,plan_sha256,key_version,nonce,ciphertext FROM system_backup_v2_execution_plans WHERE origin_installation_id=? AND task_public_id=?`, installation, id).Scan(&r.schema, &r.profile, &r.config, &r.hash, &r.key, &r.nonce, &r.body)
	return r, err
}

func (s PlanStore) Load(ctx context.Context, claim controller.ClaimToken) (dispatch.Plan, error) {
	if s.DB == nil {
		return dispatch.Plan{}, ErrPlan
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return dispatch.Plan{}, err
	}
	defer tx.Rollback()
	profile, config, _, err := s.lock(ctx, tx, claim)
	if err != nil {
		return dispatch.Plan{}, err
	}
	r, err := readPlan(ctx, tx, s.InstallationID, claim.Target.PublicID)
	if err != nil {
		return dispatch.Plan{}, err
	}
	if profile != r.profile || config != r.config {
		return dispatch.Plan{}, ErrPlan
	}
	p, err := s.open(claim.Target.PublicID, r)
	if err != nil {
		return dispatch.Plan{}, err
	}
	if err = s.checkExecutionEnvelope(claim.Target.PublicID, profile, config, p); err != nil {
		clear(p.CanonicalJSON)
		return dispatch.Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		clear(p.CanonicalJSON)
		return dispatch.Plan{}, err
	}
	return p, nil
}

// Save seals exactly one plan. Response loss/replay returns the original bytes;
// a different plan never overwrites it. Random nonces are persisted, and AAD
// binds the ciphertext to task, installation and admitted config/profile.
func (s PlanStore) Save(ctx context.Context, claim controller.ClaimToken, p dispatch.Plan) (dispatch.Plan, error) {
	if s.DB == nil || s.Cipher == nil || !planToken.MatchString(p.SchemaVersion) || len(p.CanonicalJSON) < 2 || len(p.CanonicalJSON) > 65536 || !json.Valid(p.CanonicalJSON) || planHash(p.CanonicalJSON) != p.SHA256 {
		return dispatch.Plan{}, ErrPlan
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return dispatch.Plan{}, err
	}
	defer tx.Rollback()
	profile, config, capacity, err := s.lock(ctx, tx, claim)
	if err != nil {
		return dispatch.Plan{}, err
	}
	if err = s.checkExecutionEnvelope(claim.Target.PublicID, profile, config, p); err != nil {
		return dispatch.Plan{}, err
	}
	r, err := readPlan(ctx, tx, s.InstallationID, claim.Target.PublicID)
	if err == nil {
		if r.schema != p.SchemaVersion || r.hash != p.SHA256 || r.profile != profile || r.config != config {
			return dispatch.Plan{}, ErrPlan
		}
		original, e := s.open(claim.Target.PublicID, r)
		if e != nil {
			return dispatch.Plan{}, e
		}
		if err = tx.Commit(); err != nil {
			clear(original.CanonicalJSON)
			return dispatch.Plan{}, err
		}
		return original, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return dispatch.Plan{}, err
	}
	var effects int
	var preparing bool
	if err = tx.QueryRowContext(ctx, `SELECT status='preparing' AND deadline_at>UTC_TIMESTAMP(6),
(SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=?) +
(SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?)
FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, claim.Target.PublicID, claim.Target.PublicID, s.InstallationID, claim.Target.PublicID).Scan(&preparing, &effects); err != nil || !preparing || effects != 0 {
		return dispatch.Plan{}, ErrPlan
	}
	// 64 KiB payload plus nonce/tag, indexes and audit fit this reservation;
	// it uses the same monotonic registration ledger as task admission.
	if err = (security.RegistrationCapacity{ReportFile: s.CapacityReportFile}).Reserve(ctx, tx, capacity, 8192); err != nil {
		return dispatch.Plan{}, err
	}
	r = planRecord{schema: p.SchemaVersion, profile: profile, config: config, hash: p.SHA256, key: s.Cipher.current}
	aead := s.Cipher.keys[r.key]
	r.nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(r.nonce); err != nil {
		return dispatch.Plan{}, ErrPlan
	}
	r.body = aead.Seal(nil, r.nonce, p.CanonicalJSON, planAAD(s.InstallationID, claim.Target.PublicID, r))
	if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_plans(origin_installation_id,task_public_id,schema_version,profile_sha256,config_sha256,plan_sha256,key_version,nonce,ciphertext) VALUES(?,?,?,?,?,?,?,?,?)`, s.InstallationID, claim.Target.PublicID, r.schema, r.profile, r.config, r.hash, r.key, r.nonce, r.body); err != nil {
		return dispatch.Plan{}, err
	}
	if err = tx.Commit(); err != nil {
		return dispatch.Plan{}, err
	}
	return dispatch.Plan{SchemaVersion: p.SchemaVersion, SHA256: p.SHA256, CanonicalJSON: append([]byte(nil), p.CanonicalJSON...)}, nil
}

func (s PlanStore) checkExecutionEnvelope(id, profile, config string, p dispatch.Plan) error {
	if p.SchemaVersion != executionPlanSchema {
		return nil
	}
	var execution ExecutionPlan
	if json.Unmarshal(p.CanonicalJSON, &execution) != nil || execution.Validate() != nil || execution.TaskID != id || execution.InstallationID != s.InstallationID || execution.ProfileSHA256 != profile || execution.ConfigSHA256 != config {
		return ErrPlan
	}
	return nil
}
