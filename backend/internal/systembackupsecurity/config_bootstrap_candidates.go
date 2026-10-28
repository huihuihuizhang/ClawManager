package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// BootstrapCandidateAuthority is fixed trusted deployment composition, never a
// request-provided Policy. It must independently authenticate the ORIGINAL
// offline/deployment/purpose mapping and prepare resource observations outside
// locks. Matching constructor data, hashes or a healthy result is insufficient.
// Prepare must also support exact historical retries without demanding a fresh
// old observation or an open producer domain before the operation-key lookup.
type BootstrapCandidateAuthority interface {
	PrepareBootstrapCandidates(context.Context, OfflineBootstrapGrant, BootstrapConfig, pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error)
}

type PreparedBootstrapCandidateAuthority struct {
	Session            BootstrapCandidateAuthoritySession
	CapacityObservedAt *time.Time
}

// All SQL-time observations use the supplied SampleTime. No raw transaction,
// network/provider I/O, Commit/Rollback or execution handle is available here.
// Reviewed controlled local-file checks retain their original pins/windows at
// the Work-end callback, before the fixed SQL-only final guard. They must not
// renew observations or introduce a new business lock range.
// These mandatory methods retain current mapping, RBAC, resources, retention,
// capacity and evidence authority; there is deliberately no default adapter.
type BootstrapCandidateAuthoritySession interface {
	Authorize(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.DomainRecord, time.Time) (pd.BootstrapConsumptionAdmission, error)
	LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error
	LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error
	Reserve(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error
	LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error)
	Recheck(context.Context, pd.BootstrapReadSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts, time.Time) error
}

// ConfigBootstrapCandidates is immutable selection/composition, not authority.
// Only the mandatory constructor-fixed authority can authenticate its data.
// The service prepares a fresh one-shot D consumer for each same-key attempt.
type ConfigBootstrapCandidates struct {
	db        *sql.DB
	grant     OfflineBootstrapGrant
	config    BootstrapConfig
	request   pd.BootstrapConsumptionRequest
	authority BootstrapCandidateAuthority
}

func (ConfigBootstrapCandidates) String() string   { return "ConfigBootstrapCandidates" }
func (ConfigBootstrapCandidates) GoString() string { return "ConfigBootstrapCandidates" }
func (ConfigBootstrapCandidates) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}

func candidateAuthorityNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func NewConfigBootstrapCandidates(db *sql.DB, g OfflineBootstrapGrant, raw []byte, candidates []pd.BootstrapCandidateSelection, authority BootstrapCandidateAuthority) (*ConfigBootstrapCandidates, error) {
	if db == nil {
		return nil, ErrRegistrationUnavailable
	}
	return newConfigBootstrapCandidatePlan(db, g, raw, candidates, authority)
}

// A deployment may prepare real authority/resources before opening its DSN.
// A nil database is permitted only in this private immutable comparison plan;
// neither a plan nor a matching hash establishes authority or opens SQL.
func newConfigBootstrapCandidatePlan(db *sql.DB, g OfflineBootstrapGrant, raw []byte, candidates []pd.BootstrapCandidateSelection, authority BootstrapCandidateAuthority) (*ConfigBootstrapCandidates, error) {
	c, err := DecodeBootstrapConfig(raw)
	if err != nil || candidateAuthorityNil(authority) || !validBootstrapGrant(g) || g.ConfigSHA256 != c.SHA256() {
		return nil, ErrRegistrationUnavailable
	}
	// Existing canonical spans, with original array order and no newline. This
	// describes one explicit digest profile; the original deployment authority
	// must prove its admission selected that profile, not reinterpret an old one.
	var fields map[string]json.RawMessage
	if json.Unmarshal(c.CanonicalJSON(), &fields) != nil || len(fields["registries"]) == 0 || len(fields["references"]) == 0 {
		return nil, ErrRegistrationUnavailable
	}
	grantBytes, err := json.Marshal(g)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	r := pd.BootstrapConsumptionRequest{
		Scope:            pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)},
		OfflineGrantHash: pd.Hash(registrationHash(string(grantBytes))), ConfigHash: pd.Hash(c.SHA256()),
		RegistrySetHash: pd.Hash(registrationHash(string(fields["registries"]))), RefSetHash: pd.Hash(registrationHash(string(fields["references"]))),
		ActorID: pd.Counter(strconv.FormatInt(g.UserID, 10)), Username: g.Username, MatrixKey: g.MatrixKey,
		Endpoint: BootstrapConfigEndpoint, IdempotencyKey: g.IdempotencyKey, Candidates: candidates,
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	// Detach all caller-owned nested requests/arrays. Sealing this comparison
	// data does not establish independent deployment or resource permission.
	b, err := json.Marshal(r)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	var owned pd.BootstrapConsumptionRequest
	if json.Unmarshal(b, &owned) != nil {
		return nil, ErrRegistrationUnavailable
	}
	if copied, e := pd.BootstrapConsumptionHash(owned); e != nil || copied != hash {
		return nil, ErrRegistrationUnavailable
	}
	return &ConfigBootstrapCandidates{db: db, grant: g, config: c, request: owned, authority: authority}, nil
}

func (p *ConfigBootstrapCandidates) bootstrap(ctx context.Context, db *sql.DB, g OfflineBootstrapGrant, c BootstrapConfig, canonical bool) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if p == nil || candidateAuthorityNil(ctx) || ctx.Err() != nil || db == nil || db != p.db || g != p.grant || !bytes.Equal(c.CanonicalJSON(), p.config.CanonicalJSON()) || candidateAuthorityNil(p.authority) {
		return zero, ErrRegistrationUnavailable
	}
	// One bounded attempt includes ALL preparation and SQL lock waits. Never
	// replace this context after a one-shot authority/capacity has bound it, or
	// use a fresh attempt to extend any original grant/resource observation.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.numbers["operation_deadline_seconds"])*time.Second)
	defer cancel()
	env := &configBootstrapCandidateEnvironment{plan: p, canonical: canonical}
	consumer, err := pd.NewBootstrapCandidateConsumer(db, p.request.Scope, env)
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	prepared, err := consumer.PrepareBootstrapConsumption(ctx, p.request)
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	return consumePreparedConfigBootstrap(ctx, db, g, consumer, prepared)
}

// Both the existing caller-provided DB path and the deployment's prepare-before-
// DSN path use this sole transaction owner. There is no alternate commit path.
func consumePreparedConfigBootstrap(ctx context.Context, db *sql.DB, g OfflineBootstrapGrant, consumer *pd.BootstrapCandidateConsumer, prepared *pd.PreparedBootstrapConsumption) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	defer tx.Rollback()
	result, err := consumer.ConsumeBootstrapInTx(ctx, tx, prepared)
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	if ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = tx.Commit(); err != nil {
		return zero, ErrRegistrationCommitUnknown
	}
	return ConfigBootstrapResult{OperationPublicID: result.OperationPublicID, Version: 1, ConfigSHA256: g.ConfigSHA256, Replayed: result.Replayed}, nil
}

func candidateBootstrapError(err error) error {
	switch err {
	case pd.ErrConflict:
		return ErrRegistrationConflict
	case pd.ErrUnavailable:
		return ErrProviderEvidenceStorage
	default:
		return ErrRegistrationUnavailable
	}
}

type configBootstrapCandidateEnvironment struct {
	plan      *ConfigBootstrapCandidates
	canonical bool
}

func (e *configBootstrapCandidateEnvironment) PrepareBootstrapConsumption(ctx context.Context, r pd.BootstrapConsumptionRequest) (pd.PreparedBootstrapAuthority, error) {
	var zero pd.PreparedBootstrapAuthority
	want, err := pd.BootstrapConsumptionHash(e.plan.request)
	got, incomingErr := pd.BootstrapConsumptionHash(r)
	if err != nil || incomingErr != nil || got != want {
		return zero, pd.ErrConflict
	}
	a, err := e.plan.authority.PrepareBootstrapCandidates(ctx, e.plan.grant, e.plan.config, r)
	if err != nil || candidateAuthorityNil(a.Session) {
		return zero, pd.ErrGuardRequired
	}
	op, err := registrationID("sop_")
	if err != nil {
		return zero, pd.ErrUnavailable
	}
	s := &configBootstrapCandidateSession{plan: e.plan, authority: a.Session, canonical: e.canonical, operationID: op, hash: want}
	return pd.PreparedBootstrapAuthority{Session: s, OperationPublicID: op, CapacityObservedAt: a.CapacityObservedAt}, nil
}

type configBootstrapCandidateSession struct {
	plan          *ConfigBootstrapCandidates
	authority     BootstrapCandidateAuthoritySession
	canonical     bool
	operationID   string
	hash          pd.Hash
	stateFound    bool
	stateVersion  int64
	stateMatrix   string
	configCount   int
	configVersion int64
	configHash    string
	configEnabled bool
	intentAudit   int64
}

const bootstrapCandidateGlobalConfigSQL = "SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE"

func (s *configBootstrapCandidateSession) LockInstallation(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest) error {
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return pd.ErrUnavailable
	}
	count := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			rows.Close()
			return pd.ErrUnavailable
		}
		count++
		if count > 10000 {
			rows.Close()
			return pd.ErrGuardRequired
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return pd.ErrUnavailable
	}
	if rows.Close() != nil {
		return pd.ErrUnavailable
	}
	// Do not demand absence/open state yet: L3 must admit exact old success.
	g := s.plan.grant
	err = tx.QueryRowContext(ctx, "SELECT active_config_version,matrix_key FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", g.InstallationID).Scan(&s.stateVersion, &s.stateMatrix)
	if err == nil {
		s.stateFound = true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return pd.ErrUnavailable
	}
	// Original nonce admission observes ALL installations' config bindings.
	// Hold the complete existing unique index and its insertion gaps at L1,
	// before D locks the producer domain. Later resource checks may only read
	// this already-held global range; target-only locks cannot establish it.
	rows, err = tx.QueryContext(ctx, bootstrapCandidateGlobalConfigSQL)
	if err != nil {
		return pd.ErrUnavailable
	}
	for rows.Next() {
		var id, nonceVersion, nonceIdentity any
		var installation, version, configHash string
		var enabled bool
		if ctx.Err() != nil || rows.Scan(&id, &installation, &version, &configHash, &enabled, &nonceVersion, &nonceIdentity) != nil {
			rows.Close()
			return pd.ErrUnavailable
		}
		// Do not validate foreign resource facts before L3's historical branch.
		// Stream all raw rows without imposing a new row limit on the original
		// UNION-distinct nonce requirements. Only the target decides L3 state.
		if installation == g.InstallationID {
			s.configCount++
			s.configVersion, _ = strconv.ParseInt(version, 10, 64)
			s.configHash, s.configEnabled = configHash, enabled
		}
	}
	if rows.Err() != nil {
		rows.Close()
		return pd.ErrUnavailable
	}
	if rows.Close() != nil {
		return pd.ErrUnavailable
	}
	return nil
}

func (s *configBootstrapCandidateSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, domain pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	if err := s.checkAdmin(ctx, tx); err != nil {
		return zero, err
	}
	return s.authority.Authorize(ctx, tx, r, domain, now)
}

func (s *configBootstrapCandidateSession) checkAdmin(ctx context.Context, tx pd.ReadSQL) error {
	var username, role, provider string
	var active bool
	g := s.plan.grant
	if err := tx.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR UPDATE", g.UserID).Scan(&username, &role, &active, &provider); err != nil {
		return pd.ErrGuardRequired
	}
	if username != g.Username || role != "admin" || !active || provider != "local" {
		return pd.ErrGuardRequired
	}
	return nil
}

func (s *configBootstrapCandidateSession) LockOperation(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, hash pd.Hash, op string) (pd.BootstrapOperation, error) {
	var out pd.BootstrapOperation
	if hash != s.hash || op != s.operationID {
		return out, pd.ErrConflict
	}
	g := s.plan.grant
	err := tx.QueryRowContext(ctx, `SELECT public_id,result_config_version,request_hash,status,http_status FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, g.InstallationID, strconv.FormatInt(g.UserID, 10), BootstrapConfigEndpoint, g.IdempotencyKey).Scan(&out.PublicID, &out.Version, &out.RequestHash, &out.Status, &out.HTTPStatus)
	if err == nil {
		out.Found = true
		if !s.stateFound || s.stateVersion != 1 || s.stateMatrix != g.MatrixKey || s.configCount != 1 || s.configVersion != 1 || s.configHash != g.ConfigSHA256 || s.configEnabled {
			return out, pd.ErrConflict
		}
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, pd.ErrUnavailable
	}
	if s.stateFound || s.configCount != 0 {
		return out, pd.ErrConflict
	}
	var collision string
	err = tx.QueryRowContext(ctx, "SELECT public_id FROM system_backup_v2_operations WHERE public_id=? FOR UPDATE", op).Scan(&collision)
	if !errors.Is(err, sql.ErrNoRows) {
		if err != nil {
			return out, pd.ErrUnavailable
		}
		return out, pd.ErrConflict
	}
	return out, nil
}

func (s *configBootstrapCandidateSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	return s.authority.LockHosts(ctx, tx, r, f)
}
func (s *configBootstrapCandidateSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	return s.authority.LockReferences(ctx, tx, r, f)
}
func (s *configBootstrapCandidateSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	return s.authority.Reserve(ctx, tx, r, f)
}
func (s *configBootstrapCandidateSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	return s.authority.LockEvidence(ctx, tx, r, f)
}

func (s *configBootstrapCandidateSession) AuditIntent(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	result, err := insertBootstrapAudit(ctx, tx, s.plan.grant, s.operationID, string(s.hash), "intent")
	if err != nil || result == nil {
		return pd.ErrUnavailable
	}
	s.intentAudit, err = result.LastInsertId()
	if err != nil || s.intentAudit <= 0 {
		return pd.ErrUnavailable
	}
	return nil
}

func (s *configBootstrapCandidateSession) WriteBootstrap(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts, op string, hash pd.Hash, now time.Time) (pd.BootstrapWriteResult, error) {
	var zero pd.BootstrapWriteResult
	if s.intentAudit <= 0 || op != s.operationID || hash != s.hash {
		return zero, pd.ErrGuardRequired
	}
	if err := writeBootstrapConfigData(ctx, tx, s.plan.grant, s.plan.config, op, string(hash), now, s.canonical); err != nil {
		return zero, pd.ErrUnavailable
	}
	result, err := insertBootstrapAudit(ctx, tx, s.plan.grant, op, string(hash), "result")
	if err != nil || result == nil {
		return zero, pd.ErrUnavailable
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 || id == s.intentAudit {
		return zero, pd.ErrUnavailable
	}
	return pd.BootstrapWriteResult{IntentAuditID: s.intentAudit, ResultAuditID: id}, nil
}

func (s *configBootstrapCandidateSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if err := s.authority.Recheck(ctx, tx, r, f, now); err != nil {
		return err
	}
	if err := s.checkAdmin(ctx, tx); err != nil {
		return err
	}
	// Independently verify every original flattened value, not just a caller's
	// stored config hash. The complete installation/config range was locked L1.
	return verifyBootstrapConfigValues(ctx, tx, s.plan.grant, s.plan.config, s.canonical)
}

func verifyBootstrapConfigValues(ctx context.Context, tx pd.ReadSQL, g OfflineBootstrapGrant, c BootstrapConfig, canonical bool) error {
	columns, expected := c.sqlValues(g.InstallationID, strconv.FormatInt(g.UserID, 10), g.ChangeReason)
	if canonical {
		columns, expected = c.sqlValuesWithCanonical(g.InstallationID, strconv.FormatInt(g.UserID, 10), g.ChangeReason)
	}
	actual := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range actual {
		dest[i] = &actual[i]
	}
	if err := tx.QueryRowContext(ctx, "SELECT "+strings.Join(columns, ",")+" FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1 FOR UPDATE", g.InstallationID).Scan(dest...); err != nil {
		return pd.ErrUnavailable
	}
	for i, column := range columns {
		if !configMutationCellEqual(column, actual[i], expected[i], ConfigValues{snapshot: c}) {
			return pd.ErrConflict
		}
	}
	return nil
}
