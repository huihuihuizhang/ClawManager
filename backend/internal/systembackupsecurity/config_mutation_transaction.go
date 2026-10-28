package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"clawreef/internal/systembackupread"
)

var (
	ErrConfigVersionConflict    = errors.New("version_conflict")
	ErrConfigIdempotencyExpired = errors.New("idempotency_expired")
	ErrConfigCommitUnknown      = errors.New("config_commit_unknown")
)

type ConfigMutationRisk struct{ SecurityBoundary, ProtectionReduction bool }

var configMutationOperationID = regexp.MustCompile(`^sop_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r ConfigMutationRisk) StrongAuthRequired() bool {
	return r.SecurityBoundary || r.ProtectionReduction
}

// These are mandatory trusted deployment boundaries, never HTTP fields. All
// tx methods use the caller's transaction and must not commit or do network I/O.
// Authorize checks live session/revocation and configure, plus security_configure
// or destructive from risk. It also forbids self grants, built-in role changes
// and removing the last security_admin. It runs for committed replay and again
// immediately before commit. RedactReason must use A's approved redaction rules.
type ConfigMutationAuthority interface {
	Authorize(context.Context, *sql.Tx, RegistrationActor, string, ConfigValues, ConfigValues, ConfigMutationRisk, time.Time) error
	StrongAuth(context.Context, *sql.Tx, RegistrationActor, string, ConfigValues, []string, time.Time) (VerifyConfig, error)
	Reserve(context.Context, *sql.Tx, ConfigValues, ConfigValues, int, time.Time) (ConfigMutationCapacityReservation, error)
	RedactReason(context.Context, *string) (*string, error)
}

// Prepare resolves all nine registries, twenty refs and cross-resource rules
// BEFORE locks. Recheck pins those observations/current revocation in tx and
// derives registry risks from resolved CONTENTS, not caller flags or hashes.
// Missing adapters/readiness fail closed. DeploymentEnabled is also bound by
// Recheck; it must be the trusted deployment switch, not last_effective_enabled.
type ConfigMutationResolver interface {
	Prepare(context.Context, string, RegistrationActor, ConfigValues, ConfigValues) (ConfigMutationReadiness, error)
}
type ConfigMutationReadiness interface {
	Recheck(context.Context, *sql.Tx, time.Time) (ConfigMutationRisk, error)
	DeploymentEnabled() bool
	ValidUntil() time.Time
}

// Prepare/Read perform any provider I/O without DB locks. Stage atomically
// stages the complete immutable response evidence (inline OR prepared external
// evidence) in the mutation tx. Recheck performs no network I/O. Never truncate
// a large ConfigResource to the existing 8192-byte inline limit.
type ConfigMutationResponses interface {
	Prepare(context.Context, ConfigMutationOperationPreparation) (PreparedConfigMutationOperationResponse, error)
	Read(context.Context, ConfigMutationResponseReplayPreparation) (PreparedConfigMutationResponseRead, error)
}
type PreparedConfigMutationOperationResponse interface {
	Stage(context.Context, *sql.Tx, ConfigOperationResponsePolicy, []byte, time.Time) (int64, error)
	Recheck(context.Context, *sql.Tx, time.Time) error
	ValidUntil() time.Time
}

// Legacy ConfigResource diagnostic helpers are not the public update/rollback
// response adapter. Public success and receipt bytes MUST be Operation.
type ConfigResourceDiagnosticResponses interface {
	Prepare(context.Context, ConfigMutationResponsePreparation) (PreparedConfigMutationResponse, error)
	Read(context.Context, ConfigMutationResponseReplayPreparation) (PreparedConfigMutationResponseRead, error)
}

// A verified body remains bound to its SQL receipt/evidence snapshot and frozen
// read deadline. Recheck is local SQL only, in the caller's final transaction.
type PreparedConfigMutationResponseRead interface {
	Bytes() []byte
	Recheck(context.Context, *sql.Tx, time.Time) error
	ValidUntil() time.Time
}
type PreparedConfigMutationResponse interface {
	Stage(context.Context, *sql.Tx, time.Time) (int64, error)
	Recheck(context.Context, *sql.Tx, time.Time) error
	ValidUntil() time.Time
}

type ConfigMutationService struct {
	DB             *sql.DB
	InstallationID string
	Database       DatabaseIdentity
	Authority      ConfigMutationAuthority
	Resolver       ConfigMutationResolver
	Responses      ConfigMutationResponses
}
type ConfigMutationResult struct {
	OperationPublicID string
	Version           int64
	HTTPStatus        int
	Response          []byte
	Replayed          bool
}
type configMutationRow struct {
	version, rowVersion int64
	values              ConfigValues
}
type configMutationView struct {
	tx              *sql.Tx
	row             configMutationRow
	stateRowVersion int64
	now             time.Time
}
type configMutationReceipt struct {
	publicID, hash, status, responseHash string
	httpStatus                           int
	version, evidenceID                  int64
	risk                                 ConfigMutationRisk
}

func nilConfigMutationBoundary(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func configMutationClock(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || now.IsZero() || offset != 0 {
		return now, ErrProviderEvidenceStorage
	}
	return now, nil
}

// These are authenticated token bounds, not a replacement for the live
// session/revocation/RBAC checks performed by Authority in the same transaction.
func configMutationSessionAt(actor RegistrationActor, now time.Time) bool {
	return !actor.SessionIssuedAt.IsZero() && actor.SessionExpiresAt.After(actor.SessionIssuedAt) &&
		!actor.SessionIssuedAt.After(now) && now.Before(actor.SessionExpiresAt)
}

// The final verifier must still describe the nonce binding actually consumed
// in this transaction. A newly appended config can legitimately add a retained
// nonce key version; every pre-existing version and the active HMAC must remain
// unchanged. Do not discard a successful final verification's returned facts.
func configMutationNonceBindingStable(consumed, final VerificationResult) bool {
	if consumed.NonceHMAC == "" || consumed.NonceHMACKeyVersion == "" || consumed.NonceHMAC != final.NonceHMAC ||
		consumed.NonceHMACKeyVersion != final.NonceHMACKeyVersion || len(consumed.NonceHMACCandidates) == 0 {
		return false
	}
	current := make(map[string]string, len(final.NonceHMACCandidates))
	for _, candidate := range final.NonceHMACCandidates {
		if _, duplicate := current[candidate.KeyVersion]; duplicate || candidate.KeyVersion == "" || candidate.HMAC == "" {
			return false
		}
		current[candidate.KeyVersion] = candidate.HMAC
	}
	for _, candidate := range consumed.NonceHMACCandidates {
		if current[candidate.KeyVersion] != candidate.HMAC {
			return false
		}
	}
	return current[consumed.NonceHMACKeyVersion] == consumed.NonceHMAC
}

func (s ConfigMutationService) valid(ctx context.Context, actor RegistrationActor, key, requestID string) bool {
	return ctx != nil && ctx.Err() == nil && s.DB != nil && configMutationInstallation.MatchString(s.InstallationID) && s.Database.valid() &&
		!nilConfigMutationBoundary(s.Authority) && !nilConfigMutationBoundary(s.Resolver) && !nilConfigMutationBoundary(s.Responses) &&
		actor.UserID > 0 && actor.Subject != "" && actor.Session != "" && utf8.ValidString(actor.Subject) && utf8.ValidString(actor.Session) && len(actor.Subject) <= 256 && len(actor.Session) <= 256 &&
		validIdempotencyKey(key) && bootstrapVersion.MatchString(requestID)
}

// beginView serializes config/nonce admission with existing registration and
// bootstrap writers, then locks state/config and the authenticated user. It
// establishes current configure authority before any idempotent result is read.
func (s ConfigMutationService) beginView(ctx context.Context, actor RegistrationActor) (configMutationView, error) {
	v := configMutationView{}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return v, ErrProviderEvidenceStorage
	}
	v.tx = tx
	fail := func(e error) (configMutationView, error) { tx.Rollback(); return configMutationView{}, e }
	if err = s.Database.check(ctx, tx); err != nil {
		return fail(ErrRegistrationUnavailable)
	}
	if err = lockRegistrationInstallations(ctx, tx); err != nil {
		return fail(err)
	}
	v.now, err = configMutationClock(ctx, tx)
	if err != nil {
		return fail(err)
	}
	if !configMutationSessionAt(actor, v.now) {
		return fail(ErrRegistrationPermission)
	}
	var version int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version,row_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.InstallationID).Scan(&version, &v.stateRowVersion) != nil || v.stateRowVersion < 1 || v.stateRowVersion >= 9007199254740991 {
		return fail(ErrRegistrationUnavailable)
	}
	v.row, err = readConfigMutationRow(ctx, tx, s.InstallationID, version)
	if err != nil {
		return fail(err)
	}
	var role string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT role,is_active FROM users WHERE id=? FOR UPDATE", actor.UserID).Scan(&role, &active) != nil || role != "admin" || !active {
		return fail(ErrRegistrationPermission)
	}
	if err = s.Authority.Authorize(ctx, tx, actor, s.InstallationID, v.row.values, v.row.values, ConfigMutationRisk{}, v.now); err != nil {
		return fail(registrationBoundaryError(err))
	}
	return v, nil
}

func readConfigMutationRow(ctx context.Context, tx *sql.Tx, installation string, version int64) (configMutationRow, error) {
	r := configMutationRow{version: version}
	var raw []byte
	var hash, schema string
	var size int64
	if version < 1 || version > 9007199254740991 {
		return r, ErrRegistrationUnavailable
	}
	err := tx.QueryRowContext(ctx, `SELECT schema_version,version,row_version,canonical_config_json,config_sha256,config_size_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, installation, version).Scan(&schema, &r.version, &r.rowVersion, &raw, &hash, &size)
	if err != nil {
		return r, ErrRegistrationUnavailable
	}
	c, err := DecodeConfigValues(raw)
	if err != nil || schema != "system-backup-config.v1" || r.version != version || r.rowVersion < 1 || r.rowVersion > 9007199254740991 || size != int64(len(raw)) || hash != c.SHA256() || !bytes.Equal(raw, c.CanonicalJSON()) {
		return r, ErrRegistrationUnavailable
	}
	cols, args, _ := c.sqlValues(installation, "unused", "unused", version)
	var selected []string
	var expected []any
	for i, k := range cols {
		if i < 4 || k == "created_by" || k == "change_reason" || k == "canonical_config_json" {
			continue
		}
		selected = append(selected, k)
		expected = append(expected, args[i])
	}
	stored := make([]any, len(selected))
	dest := make([]any, len(stored))
	for i := range stored {
		dest[i] = &stored[i]
	}
	if tx.QueryRowContext(ctx, "SELECT "+strings.Join(selected, ",")+" FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE", installation, version).Scan(dest...) != nil {
		return r, ErrRegistrationUnavailable
	}
	for i, k := range selected {
		if !configMutationCellEqual(k, stored[i], expected[i], c) {
			return r, ErrRegistrationUnavailable
		}
	}
	r.values = c
	return r, nil
}
func configMutationCellEqual(column string, a, b any, c ConfigValues) bool {
	text := func(v any) (string, bool) {
		switch x := v.(type) {
		case string:
			return x, true
		case []byte:
			return string(x), true
		case int64:
			return strconv.FormatInt(x, 10), true
		case int:
			return strconv.Itoa(x), true
		case bool:
			if x {
				return "1", true
			}
			return "0", true
		}
		return "", false
	}
	x, ok := text(a)
	if !ok {
		return false
	}
	y, ok := text(b)
	if !ok {
		return false
	}
	_, numeric := c.snapshot.numbers[column]
	if numeric || column == "minimum_recovery_points" || column == "enabled" {
		left, ok := new(big.Rat).SetString(x)
		if !ok {
			return false
		}
		right, ok := new(big.Rat).SetString(y)
		return ok && left.Cmp(right) == 0
	}
	return x == y
}
func (s ConfigMutationService) lookup(ctx context.Context, tx *sql.Tx, actor RegistrationActor, r ConfigMutationRequest, key, hash string) (*configMutationReceipt, error) {
	p := configMutationReceipt{}
	err := tx.QueryRowContext(ctx, `SELECT public_id,request_hash,status,http_status,result_config_version,redacted_response_evidence_id,redacted_response_sha256 FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, s.InstallationID, strconv.FormatInt(actor.UserID, 10), r.endpoint, key).Scan(&p.publicID, &p.hash, &p.status, &p.httpStatus, &p.version, &p.evidenceID, &p.responseHash)
	if err == nil {
		if p.hash != hash {
			return nil, ErrRegistrationConflict
		}
		if p.status != "succeeded" || p.httpStatus != 200 || p.version < 1 || p.version > 9007199254740991 || p.evidenceID < 1 || !providerHashPattern.MatchString(p.responseHash) || !configMutationOperationID.MatchString(p.publicID) {
			return nil, ErrRegistrationUnavailable
		}
		// The original risk is immutable receipt data. Replays require today's
		// applicable permissions even though they consume no new proof/nonce.
		rows, e := tx.QueryContext(ctx, `SELECT details FROM audit_logs WHERE resource_type='system_backup' AND action='system_backup.config_update.intent' AND JSON_UNQUOTE(JSON_EXTRACT(details,'$.operation_public_id'))=? FOR UPDATE`, p.publicID)
		if e != nil {
			return nil, ErrProviderEvidenceStorage
		}
		count := 0
		for rows.Next() {
			var data []byte
			if rows.Scan(&data) != nil {
				rows.Close()
				return nil, ErrRegistrationUnavailable
			}
			var d map[string]json.RawMessage
			if len(data) > 65536 || !providerJSONUnicode(data) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(data))) || json.Unmarshal(data, &d) != nil {
				rows.Close()
				return nil, ErrRegistrationUnavailable
			}
			// json.Unmarshal(null, *bool) silently produces false. Original risk
			// must be two explicit booleans, never missing/null/coerced defaults.
			for _, name := range []string{"security_boundary", "protection_reduction"} {
				bit := bytes.TrimSpace(d[name])
				if !bytes.Equal(bit, []byte("true")) && !bytes.Equal(bit, []byte("false")) {
					rows.Close()
					return nil, ErrRegistrationUnavailable
				}
			}
			var installation, actorID, endpoint, digest string
			var version int64
			if json.Unmarshal(d["origin_installation_id"], &installation) != nil || json.Unmarshal(d["actor_id"], &actorID) != nil || json.Unmarshal(d["endpoint"], &endpoint) != nil || json.Unmarshal(d["request_hash"], &digest) != nil || json.Unmarshal(d["new_version"], &version) != nil || json.Unmarshal(d["security_boundary"], &p.risk.SecurityBoundary) != nil || json.Unmarshal(d["protection_reduction"], &p.risk.ProtectionReduction) != nil || installation != s.InstallationID || actorID != strconv.FormatInt(actor.UserID, 10) || endpoint != r.endpoint || digest != hash || version != p.version {
				rows.Close()
				return nil, ErrRegistrationUnavailable
			}
			count++
		}
		e = rows.Err()
		rows.Close()
		if e != nil || count != 1 {
			return nil, ErrRegistrationUnavailable
		}
		return &p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProviderEvidenceStorage
	}
	var tombstone string
	err = tx.QueryRowContext(ctx, `SELECT request_hash FROM system_backup_v2_compact_tombstones WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, s.InstallationID, strconv.FormatInt(actor.UserID, 10), r.endpoint, key).Scan(&tombstone)
	if err == nil {
		if tombstone != hash {
			return nil, ErrRegistrationConflict
		}
		return nil, ErrConfigIdempotencyExpired
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProviderEvidenceStorage
	}
	return nil, nil
}

// Mutate never retries an uncertain commit. Use ObserveCommitted, with the SAME
// target/key/hash and current authenticated actor, to determine its outcome.
func (s ConfigMutationService) Mutate(ctx context.Context, actor RegistrationActor, endpoint, key, requestID string, raw []byte, proof *Proof) (ConfigMutationResult, error) {
	zero := ConfigMutationResult{}
	if !s.valid(ctx, actor, key, requestID) {
		return zero, ErrRegistrationUnavailable
	}
	r, err := DecodeConfigMutationRequest(endpoint, raw)
	if err != nil {
		return zero, err
	}
	var frozenProof *Proof
	if proof != nil {
		p := *proof
		p.Payload.AMR = append([]string(nil), proof.Payload.AMR...)
		if p.Payload.ACR != nil {
			x := *p.Payload.ACR
			p.Payload.ACR = &x
		}
		frozenProof = &p
	}
	hash, err := r.RequestHash(s.InstallationID, "admin", strconv.FormatInt(actor.UserID, 10))
	if err != nil {
		return zero, err
	}
	first, err := s.beginView(ctx, actor)
	if err != nil {
		return zero, err
	}
	previous, err := s.lookup(ctx, first.tx, actor, r, key, hash)
	if err != nil {
		first.tx.Rollback()
		return zero, err
	}
	if previous != nil {
		first.tx.Rollback()
		return s.replay(ctx, actor, r, key, hash, *previous)
	}
	if r.expectedVersion != first.row.version {
		first.tx.Rollback()
		return zero, ErrConfigVersionConflict
	}
	proposed := r.config
	if endpoint == ConfigRollbackEndpoint {
		old, e := readConfigMutationRow(ctx, first.tx, s.InstallationID, r.rollbackFromVersion)
		if e != nil {
			first.tx.Rollback()
			return zero, e
		}
		proposed = old.values
	}
	var highest int64
	if first.tx.QueryRowContext(ctx, "SELECT version FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version DESC LIMIT 1 FOR UPDATE", s.InstallationID).Scan(&highest) != nil || highest < first.row.version || highest >= 9007199254740991 {
		first.tx.Rollback()
		return zero, ErrRegistrationUnavailable
	}
	if err = first.tx.Rollback(); err != nil {
		return zero, ErrProviderEvidenceStorage
	} // Release before provider work.
	ready, err := s.Resolver.Prepare(ctx, s.InstallationID, actor, first.row.values, proposed)
	if err != nil || nilConfigMutationBoundary(ready) {
		return zero, ErrRegistrationUnavailable
	}
	readinessUntil := ready.ValidUntil()
	if !first.now.Before(readinessUntil) {
		return zero, ErrRegistrationUnavailable
	}
	reason, err := s.Authority.RedactReason(ctx, r.ChangeReason())
	if err != nil || (reason != nil && (!utf8.ValidString(*reason) || len(*reason) > 512)) {
		return zero, ErrRegistrationUnavailable
	}
	if reason != nil {
		copy := *reason
		reason = &copy
		if copy == "" {
			reason = nil
		}
	}
	op, err := registrationID("sop_")
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	newVersion := highest + 1
	deploymentEnabled := ready.DeploymentEnabled()
	responseInput, err := newConfigMutationOperationPreparation(s.Database, actor, s.InstallationID, op, r, key, first.row.values, proposed, highest, first.now)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	prepared, err := s.Responses.Prepare(ctx, responseInput)
	if err != nil || nilConfigMutationBoundary(prepared) {
		return zero, ErrRegistrationUnavailable
	}
	responseUntil := prepared.ValidUntil()
	if !first.now.Before(responseUntil) {
		return zero, ErrRegistrationUnavailable
	}
	v, err := s.beginView(ctx, actor)
	if err != nil {
		return zero, err
	}
	defer v.tx.Rollback()
	previous, err = s.lookup(ctx, v.tx, actor, r, key, hash)
	if err != nil {
		return zero, err
	}
	if previous != nil {
		v.tx.Rollback()
		return s.replay(ctx, actor, r, key, hash, *previous)
	}
	if v.row.version != first.row.version || v.row.rowVersion != first.row.rowVersion || v.row.values.SHA256() != first.row.values.SHA256() || v.stateRowVersion != first.stateRowVersion {
		return zero, ErrConfigVersionConflict
	}
	var currentHighest int64
	if v.tx.QueryRowContext(ctx, "SELECT version FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version DESC LIMIT 1 FOR UPDATE", s.InstallationID).Scan(&currentHighest) != nil || currentHighest != highest {
		return zero, ErrConfigVersionConflict
	}
	if endpoint == ConfigRollbackEndpoint {
		old, e := readConfigMutationRow(ctx, v.tx, s.InstallationID, r.rollbackFromVersion)
		if e != nil || old.values.SHA256() != proposed.SHA256() {
			return zero, ErrRegistrationUnavailable
		}
	}
	if !v.now.Before(readinessUntil) || !v.now.Before(responseUntil) {
		return zero, ErrRegistrationUnavailable
	}
	extra, err := ready.Recheck(ctx, v.tx, v.now)
	if err != nil || ready.DeploymentEnabled() != deploymentEnabled {
		return zero, ErrRegistrationUnavailable
	}
	risk := configMutationBaseRisk(v.row.values, proposed)
	risk.SecurityBoundary = risk.SecurityBoundary || extra.SecurityBoundary
	risk.ProtectionReduction = risk.ProtectionReduction || extra.ProtectionReduction
	if risk.ProtectionReduction && (r.reason == nil || strings.TrimSpace(*r.reason) == "" || reason == nil || strings.TrimSpace(*reason) == "") {
		return zero, ErrConfigMutation
	}
	if err = s.Authority.Authorize(ctx, v.tx, actor, s.InstallationID, v.row.values, proposed, risk, v.now); err != nil {
		return zero, registrationBoundaryError(err)
	}
	var verified VerificationResult
	if risk.StrongAuthRequired() {
		if frozenProof == nil {
			return zero, &VerificationError{Code: FailureRequired, err: errors.New("required strong-auth absent")}
		}
		verified, err = s.verifyConfigProof(ctx, v.tx, actor, v.row.values, r, key, hash, *frozenProof, v.now)
		if err != nil {
			return zero, err
		}
		for _, candidate := range verified.NonceHMACCandidates {
			var id int64
			e := v.tx.QueryRowContext(ctx, "SELECT id FROM system_backup_v2_strong_auth_nonces WHERE nonce_hmac=? AND nonce_hmac_key_version=? FOR UPDATE", candidate.HMAC, candidate.KeyVersion).Scan(&id)
			if e == nil {
				return zero, &VerificationError{Code: FailureReplayed, err: errors.New("nonce already consumed")}
			}
			if !errors.Is(e, sql.ErrNoRows) {
				return zero, ErrProviderEvidenceStorage
			}
		}
	}
	capacity, err := s.Authority.Reserve(ctx, v.tx, v.row.values, proposed, len(proposed.CanonicalJSON())+MaxConfigOperationResponseBytes+131072, v.now)
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	if nilConfigMutationBoundary(capacity) {
		return zero, ErrRegistrationUnavailable
	}
	capacityUntil := capacity.ValidUntil()
	if !v.now.Before(capacityUntil) {
		return zero, ErrRegistrationUnavailable
	}
	deadline := first.now.Add(time.Duration(v.row.values.snapshot.numbers["operation_deadline_seconds"]) * time.Second)
	if !v.now.Before(deadline) {
		return zero, ErrRegistrationUnavailable
	}
	intent, err := configMutationAudit(ctx, v.tx, s.InstallationID, actor, requestID, r, op, hash, v.row, proposed, newVersion, risk, reason, "intent")
	if err != nil {
		return zero, err
	}
	cols, args, _ := proposed.sqlValues(s.InstallationID, strconv.FormatInt(actor.UserID, 10), "unused", newVersion)
	for i, k := range cols {
		if k == "change_reason" {
			args[i] = reason
		}
	}
	cols = append(cols, "created_at", "copied_from_version")
	args = append(args, first.now, nil)
	if endpoint == ConfigRollbackEndpoint {
		args[len(args)-1] = r.rollbackFromVersion
	}
	if _, err = v.tx.ExecContext(ctx, "INSERT INTO system_backup_v2_configs ("+strings.Join(cols, ",")+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...); err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	cas, err := v.tx.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=?,row_version=row_version+1 WHERE origin_installation_id=? AND active_config_version=? AND row_version=?", newVersion, s.InstallationID, v.row.version, v.stateRowVersion)
	if !configMutationOne(cas, err) {
		return zero, ErrConfigVersionConflict
	}
	terminalNow, err := configMutationClock(ctx, v.tx)
	if err != nil || terminalNow.Before(v.now) {
		return zero, ErrRegistrationUnavailable
	}
	if !configMutationSessionAt(actor, terminalNow) {
		return zero, ErrRegistrationPermission
	}
	operationPolicy, response, retention, err := responseInput.terminal(terminalNow)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	// The response adapter receives its own buffer. Neither Stage nor a later
	// Recheck may rewrite the writer's original public response after its facts
	// were fixed, or redefine the checksum by mutating that borrowed storage.
	responseHash := registrationHash(string(response))
	evidenceID, err := prepared.Stage(ctx, v.tx, operationPolicy, append([]byte(nil), response...), retention)
	if err != nil || evidenceID < 1 {
		return zero, ErrRegistrationUnavailable
	}
	if err = checkConfigResponseEvidence(ctx, v.tx, s.InstallationID, evidenceID, responseHash, len(response), retention); err != nil {
		return zero, err
	}
	operation, err := v.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_operations (public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,result_config_version,http_status,redacted_response_evidence_id,redacted_response_sha256,deadline_at,started_at,finished_at,created_at,updated_at,row_version,result_resource_public_id,retryable,failure_category,failure_message) VALUES (?,?,'config_update','system',?,'admin',?,?,?,?,?,2,?,'succeeded',?,200,?,?,?,?,?,?,?,1,NULL,FALSE,'none',NULL)`, op, s.InstallationID, s.InstallationID, strconv.FormatInt(actor.UserID, 10), endpoint, key, hash, []byte("[]"), registrationHash("[]"), newVersion, evidenceID, responseHash, deadline, first.now, terminalNow, first.now, terminalNow)
	if err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	operationID, err := operation.LastInsertId()
	if err != nil || operationID < 1 {
		return zero, ErrProviderEvidenceStorage
	}
	if risk.StrongAuthRequired() {
		authAt, expiresAt, e := parseTimes(frozenProof.Payload)
		if e != nil {
			return zero, ErrConfigMutation
		}
		// authenticated_at is the SQL verification sample, not signed auth_time.
		// The latter still fixes the original maximum age; it cannot become the
		// lower guard because valid proofs may be ahead within configured skew.
		n, e := v.tx.ExecContext(ctx, `INSERT INTO system_backup_v2_strong_auth_nonces (origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,authenticated_at,expires_at,consumed_at,operation_id,audit_log_id,retain_until) SELECT ?,?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),?,?,? WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<? AND UTC_TIMESTAMP(6)<=?`, s.InstallationID, registrationHash(frozenProof.Payload.Issuer), registrationHash(actor.Subject), registrationHash(actor.Session), verified.NonceHMAC, verified.NonceHMACKeyVersion, endpoint, hash, key, v.now, expiresAt, operationID, intent, expiresAt.Add(time.Duration(v.row.values.snapshot.numbers["control_metadata_retention_seconds"])*time.Second), v.now, expiresAt, authAt.Add(time.Duration(v.row.values.snapshot.numbers["strong_auth_max_age_seconds"])*time.Second).Add(time.Duration(v.row.values.snapshot.numbers["strong_auth_clock_skew_seconds"])*time.Second))
		if !configMutationOne(n, e) {
			return zero, ErrRegistrationUnavailable
		}
	}
	if _, err = configMutationAudit(ctx, v.tx, s.InstallationID, actor, requestID, r, op, hash, v.row, proposed, newVersion, risk, reason, "result"); err != nil {
		return zero, err
	}
	finalNow, err := configMutationClock(ctx, v.tx)
	if err != nil || !finalNow.Before(deadline) {
		return zero, ErrRegistrationUnavailable
	}
	finalRisk, err := ready.Recheck(ctx, v.tx, finalNow)
	if err != nil || finalRisk != extra || ready.DeploymentEnabled() != deploymentEnabled {
		return zero, ErrRegistrationUnavailable
	}
	if err = prepared.Recheck(ctx, v.tx, finalNow); err != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = s.Authority.Authorize(ctx, v.tx, actor, s.InstallationID, v.row.values, proposed, risk, finalNow); err != nil {
		return zero, registrationBoundaryError(err)
	}
	if risk.StrongAuthRequired() {
		finalVerified, e := s.verifyConfigProof(ctx, v.tx, actor, v.row.values, r, key, hash, *frozenProof, finalNow)
		if e != nil {
			return zero, e
		}
		if !configMutationNonceBindingStable(verified, finalVerified) {
			return zero, ErrRegistrationUnavailable
		}
	}
	if err = s.Database.check(ctx, v.tx); err != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = capacity.Recheck(ctx, v.tx, finalNow); err != nil {
		return zero, registrationBoundaryError(err)
	}
	// No more authority/key/provider callbacks after this clock observation.
	// They can legitimately take time even when each returned valid facts for
	// finalNow. Check the immutable temporal bounds again immediately at commit.
	commitNow, err := configMutationClock(ctx, v.tx)
	if err != nil || commitNow.Before(finalNow) {
		return zero, ErrRegistrationUnavailable
	}
	if !configMutationSessionAt(actor, commitNow) {
		return zero, ErrRegistrationPermission
	}
	// The response deadline may itself be capped by session expiry. Preserve
	// the actual authentication/permission failure before generic readiness
	// deadlines, rather than reporting an expired session as dependency outage.
	if !commitNow.Before(deadline) || !commitNow.Before(capacityUntil) || !commitNow.Before(readinessUntil) || !commitNow.Before(responseUntil) {
		return zero, ErrRegistrationUnavailable
	}
	if risk.StrongAuthRequired() {
		if err = verifyProofTimeAt(frozenProof.Payload, commitNow,
			time.Duration(v.row.values.snapshot.numbers["strong_auth_max_age_seconds"])*time.Second,
			time.Duration(v.row.values.snapshot.numbers["strong_auth_clock_skew_seconds"])*time.Second); err != nil {
			return zero, registrationBoundaryError(err)
		}
	}
	if ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = v.tx.Commit(); err != nil {
		return zero, ErrConfigCommitUnknown
	}
	return ConfigMutationResult{op, newVersion, 200, append([]byte(nil), response...), false}, nil
}

func (s ConfigMutationService) verifyConfigProof(ctx context.Context, tx *sql.Tx, actor RegistrationActor, c ConfigValues, r ConfigMutationRequest, key, hash string, proof Proof, now time.Time) (VerificationResult, error) {
	refs := c.References()
	var active string
	for _, ref := range refs {
		if ref.Purpose == "nonce_hmac" {
			active = ref.Version
		}
	}
	versions, err := retainedNonceVersions(ctx, tx, active, now)
	if err != nil {
		return VerificationResult{}, err
	}
	sc, err := s.Authority.StrongAuth(ctx, tx, actor, s.InstallationID, c, append([]string(nil), versions...), now)
	if err != nil {
		return VerificationResult{}, registrationBoundaryError(err)
	}
	if sc.ExpectedAudience == "" || sc.ExpectedSubject != actor.Subject || sc.ExpectedSession != actor.Session || sc.ActiveNonceHMACKeyVersion != active {
		return VerificationResult{}, ErrRegistrationUnavailable
	}
	sc.Now = now
	sc.MaxAge = time.Duration(c.snapshot.numbers["strong_auth_max_age_seconds"]) * time.Second
	sc.ClockSkew = time.Duration(c.snapshot.numbers["strong_auth_clock_skew_seconds"]) * time.Second
	sc.RequiredNonceHMACKeyVersions = versions
	v, err := Verify(proof, RequestBinding{Issuer: proof.Payload.Issuer, Audience: sc.ExpectedAudience, Subject: actor.Subject, Session: actor.Session, Endpoint: r.endpoint, RequestHash: hash, IdempotencyKey: key}, sc)
	if err != nil {
		return v, registrationBoundaryError(err)
	}
	return v, nil
}
func configMutationOne(r sql.Result, err error) bool {
	if err != nil || r == nil {
		return false
	}
	n, e := r.RowsAffected()
	return e == nil && n == 1
}

func configMutationBaseRisk(old, next ConfigValues) ConfigMutationRisk {
	r := ConfigMutationRisk{}
	for _, name := range []string{"retention_seconds", "evidence_retention_seconds", "control_metadata_retention_seconds"} {
		if next.snapshot.numbers[name] < old.snapshot.numbers[name] {
			r.ProtectionReduction = true
		}
	}
	a, _ := strconv.ParseInt(string(old.snapshot.values.MinimumRecoveryPoints), 10, 64)
	b, _ := strconv.ParseInt(string(next.snapshot.values.MinimumRecoveryPoints), 10, 64)
	r.ProtectionReduction = r.ProtectionReduction || b < a || (old.snapshot.values.AlertProfile == "production" && next.snapshot.values.AlertProfile == "development")
	refs := map[string]BootstrapSecretRef{}
	for _, ref := range old.References() {
		refs[ref.Purpose] = ref
	}
	for _, ref := range next.References() {
		if ref != refs[ref.Purpose] {
			r.SecurityBoundary = true
		}
	}
	return r
}

func configMutationResponse(installation string, actor RegistrationActor, version int64, c ConfigValues, reason *string, now time.Time, enabled bool) ([]byte, error) {
	dto := systembackupread.ConfigResourceDTO{SchemaVersion: "system-backup-config.v1", OriginInstallationID: installation, Version: uint64(version), RowVersion: 1, Active: true, EffectiveEnabled: enabled && c.Enabled(), Config: c.CanonicalJSON(), CreatedBy: strconv.FormatInt(actor.UserID, 10), ChangeReason: reason, CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(dto)
	if err != nil {
		return nil, ErrConfigMutation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil, ErrConfigMutation
	}
	var out strings.Builder
	canonicalMutationJSON(&out, value)
	return []byte(out.String()), nil
}
func configMutationAudit(ctx context.Context, tx *sql.Tx, installation string, actor RegistrationActor, requestID string, r ConfigMutationRequest, op, hash string, old configMutationRow, next ConfigValues, version int64, risk ConfigMutationRisk, reason *string, phase string) (int64, error) {
	details := map[string]any{"request_id": requestID, "origin_installation_id": installation, "actor_type": "admin", "actor_id": strconv.FormatInt(actor.UserID, 10), "session_sha256": registrationHash(actor.Session), "operation_public_id": op, "endpoint": r.endpoint, "request_hash": hash, "old_version": old.version, "old_sha256": old.values.SHA256(), "old_size_bytes": len(old.values.CanonicalJSON()), "new_version": version, "new_sha256": next.SHA256(), "new_size_bytes": len(next.CanonicalJSON()), "security_boundary": risk.SecurityBoundary, "protection_reduction": risk.ProtectionReduction, "change_reason": reason, "result": phase}
	if r.endpoint == ConfigRollbackEndpoint {
		details["copied_from_version"] = r.rollbackFromVersion
	}
	payload, err := json.Marshal(details)
	if err != nil || len(payload) > 65536 {
		return 0, ErrRegistrationUnavailable
	}
	res, err := tx.ExecContext(ctx, "INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", actor.UserID, "system_backup.config_update."+phase, string(payload))
	if err != nil {
		return 0, ErrProviderEvidenceStorage
	}
	id, err := res.LastInsertId()
	if err != nil || id < 1 {
		return 0, ErrProviderEvidenceStorage
	}
	return id, nil
}
func checkConfigResponseEvidence(ctx context.Context, tx *sql.Tx, installation string, id int64, hash string, size int, retain time.Time) error {
	var ownerType, owner, checksum, state, health, media string
	var bytes int64
	var expiry time.Time
	if tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id,content_checksum,content_size_bytes,storage_state,observed_health,media_type,expires_at FROM system_backup_v2_evidence WHERE id=? FOR UPDATE", id).Scan(&ownerType, &owner, &checksum, &bytes, &state, &health, &media, &expiry) != nil || ownerType != "system" || owner != installation || checksum != hash || bytes != int64(size) || state != "inline" || size > MaxConfigOperationResponseBytes || health != "healthy" || media != "application/json" || expiry.Before(retain) {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (s ConfigMutationService) replay(ctx context.Context, actor RegistrationActor, r ConfigMutationRequest, key, hash string, p configMutationReceipt) (ConfigMutationResult, error) {
	zero := ConfigMutationResult{}
	initial, err := s.beginView(ctx, actor)
	if err != nil {
		return zero, err
	}
	bound, err := s.lookup(ctx, initial.tx, actor, r, key, hash)
	if err == nil && (bound == nil || *bound != p) {
		err = ErrRegistrationUnavailable
	}
	if err == nil {
		err = s.Authority.Authorize(ctx, initial.tx, actor, s.InstallationID, initial.row.values, initial.row.values, p.risk, initial.now)
	}
	releaseErr := initial.tx.Rollback()
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	if releaseErr != nil {
		return zero, ErrProviderEvidenceStorage
	}
	input, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: s.Database, Installation: s.InstallationID, Actor: actor, Operation: p.publicID, Endpoint: r.endpoint, IdempotencyKey: key, RequestHash: hash, EvidenceID: p.evidenceID, ResponseHash: p.responseHash, Version: p.version, AuthorizedAt: initial.now, ValidUntil: actor.SessionExpiresAt})
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	read, err := s.Responses.Read(ctx, input)
	if err != nil || nilConfigMutationBoundary(read) {
		return zero, ErrRegistrationUnavailable
	}
	readUntil := read.ValidUntil()
	response := read.Bytes()
	operationPolicy, decodeErr := DecodeCanonicalConfigOperationResponse(response)
	if decodeErr != nil || operationPolicy.InstallationID != s.InstallationID || operationPolicy.OperationPublicID != p.publicID || operationPolicy.ActorID != actor.UserID || operationPolicy.Endpoint != r.endpoint || operationPolicy.IdempotencyKey != key || operationPolicy.RequestHash != hash || operationPolicy.Version != p.version || !initial.now.Before(readUntil) || readUntil.After(input.Facts().ValidUntil) || registrationHash(string(response)) != p.responseHash {
		return zero, ErrRegistrationUnavailable
	}
	response = append([]byte(nil), response...)
	v, err := s.beginView(ctx, actor)
	if err != nil {
		return zero, err
	}
	defer v.tx.Rollback()
	again, err := s.lookup(ctx, v.tx, actor, r, key, hash)
	if err != nil {
		return zero, err
	}
	if again == nil || *again != p {
		return zero, ErrRegistrationUnavailable
	}
	finalNow, err := configMutationClock(ctx, v.tx)
	if err != nil {
		return zero, err
	}
	if err = read.Recheck(ctx, v.tx, finalNow); err != nil || !read.ValidUntil().Equal(readUntil) {
		return zero, ErrRegistrationUnavailable
	}
	if err = s.Authority.Authorize(ctx, v.tx, actor, s.InstallationID, v.row.values, v.row.values, p.risk, finalNow); err != nil {
		return zero, registrationBoundaryError(err)
	}
	commitNow, err := configMutationClock(ctx, v.tx)
	if err != nil || commitNow.Before(finalNow) {
		return zero, ErrRegistrationUnavailable
	}
	if !configMutationSessionAt(actor, commitNow) {
		return zero, ErrRegistrationPermission
	}
	if !commitNow.Before(readUntil) {
		return zero, ErrRegistrationUnavailable
	}
	if ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = v.tx.Commit(); err != nil {
		return zero, ErrConfigCommitUnknown
	}
	return ConfigMutationResult{p.publicID, p.version, p.httpStatus, response, true}, nil
}

// ObserveCommitted performs only authenticated reads. A missing receipt is
// unavailable, never permission to blindly repeat a write after unknown commit.
func (s ConfigMutationService) ObserveCommitted(ctx context.Context, actor RegistrationActor, endpoint, key, requestID string, raw []byte) (ConfigMutationResult, error) {
	zero := ConfigMutationResult{}
	if !s.valid(ctx, actor, key, requestID) {
		return zero, ErrRegistrationUnavailable
	}
	r, err := DecodeConfigMutationRequest(endpoint, raw)
	if err != nil {
		return zero, err
	}
	hash, err := r.RequestHash(s.InstallationID, "admin", strconv.FormatInt(actor.UserID, 10))
	if err != nil {
		return zero, err
	}
	v, err := s.beginView(ctx, actor)
	if err != nil {
		return zero, err
	}
	p, err := s.lookup(ctx, v.tx, actor, r, key, hash)
	v.tx.Rollback()
	if err != nil {
		return zero, err
	}
	if p == nil {
		return zero, ErrRegistrationUnavailable
	}
	return s.replay(ctx, actor, r, key, hash, *p)
}
