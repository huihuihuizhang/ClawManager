package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Model driver verifies orchestration/rollback and exact SQL arguments, not
// InnoDB locks or real database constraints. Those require the tagged MySQL gate.
type mutationTestData struct {
	rows                 map[int64]ConfigValues
	active, stateVersion int64
	receipt              *configMutationReceipt
	audit                []byte
	response             []byte
	evidenceHash         string
	expires              time.Time
	operationPolicy      ConfigOperationResponsePolicy
	evidenceID           int64
	evidencePublicID     string
	evidenceCreated      time.Time
	writes               []string
}
type mutationTestState struct {
	data, working                                                                                                                                                    mutationTestData
	now                                                                                                                                                              time.Time
	db                                                                                                                                                               DatabaseIdentity
	activeTx                                                                                                                                                         bool
	tx                                                                                                                                                               *sql.Tx
	begins, commits, rollbacks, authCalls, prepares, reads, strongCalls, checks                                                                                      int
	failWrite                                                                                                                                                        int
	zeroCAS, zeroNonce, commitUnknown, denied, inactive, consumed, drift, expiredFinal, denyFinal, missingCanonical, materializedDrift, wrongDatabase, wrongEvidence bool
	risk, extraRisk                                                                                                                                                  ConfigMutationRisk
	permissions                                                                                                                                                      map[string]bool
	callback                                                                                                                                                         func()
	afterCAS                                                                                                                                                         func()
}
type mutationTestConnector struct{ s *mutationTestState }

func (c mutationTestConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mutationTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &mutationTestConn{c.s}, nil
}

type mutationTestConn struct{ s *mutationTestState }

func (*mutationTestConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*mutationTestConn) Close() error                        { return nil }
func (c *mutationTestConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (c *mutationTestConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.s.activeTx {
		return nil, errors.New("bad isolation/nested tx")
	}
	s := c.s
	s.activeTx = true
	s.begins++
	s.tx = nil
	s.working = s.data
	s.working.rows = map[int64]ConfigValues{}
	for k, v := range s.data.rows {
		s.working.rows[k] = v
	}
	s.working.writes = nil
	return &mutationTestTx{s}, nil
}

type mutationTestTx struct{ s *mutationTestState }

func (t *mutationTestTx) Commit() error {
	s := t.s
	s.activeTx = false
	s.commits++
	s.working.writes = append(append([]string(nil), s.data.writes...), s.working.writes...)
	s.data = s.working
	if s.commitUnknown {
		return errors.New("PRIVATE unknown commit")
	}
	return nil
}
func (t *mutationTestTx) Rollback() error { t.s.activeTx = false; t.s.rollbacks++; return nil }
func (c *mutationTestConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if !s.activeTx {
		return nil, errors.New("query requires active tx")
	}
	d := s.working
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		if s.wrongDatabase {
			return registrationRow("foreign", s.db.Database), nil
		}
		return registrationRow(s.db.ServerUUID, s.db.Database), nil
	case strings.Contains(q, "SELECT origin_installation_id"):
		return registrationRow("installation_synthetic"), nil
	case strings.Contains(q, "SELECT UTC_TIMESTAMP"):
		now := s.now
		if s.expiredFinal && len(d.writes) > 0 {
			now = now.Add(24 * time.Hour)
		}
		return registrationRow(now, int64(0)), nil
	case strings.Contains(q, "SELECT active_config_version,row_version"):
		return registrationRow(d.active, d.stateVersion), nil
	case strings.Contains(q, "SELECT schema_version,version,row_version,canonical_config_json"):
		version := args[1].Value.(int64)
		v, ok := d.rows[version]
		if !ok {
			return &registrationTestRows{width: 6}, nil
		}
		raw := v.CanonicalJSON()
		if s.missingCanonical {
			raw = nil
		}
		return registrationRow("system-backup-config.v1", version, int64(1), raw, v.SHA256(), int64(len(v.CanonicalJSON()))), nil
	case strings.Contains(q, "SELECT role,is_active"):
		return registrationRow("admin", !s.inactive), nil
	case strings.Contains(q, "SELECT public_id,request_hash,status,http_status"):
		if d.receipt == nil || len(args) != 4 || args[0].Value != d.operationPolicy.InstallationID || args[1].Value != strconv.FormatInt(d.operationPolicy.ActorID, 10) || args[2].Value != d.operationPolicy.Endpoint || args[3].Value != d.operationPolicy.IdempotencyKey {
			return &registrationTestRows{width: 7}, nil
		}
		p := d.receipt
		return registrationRow(p.publicID, p.hash, p.status, int64(p.httpStatus), p.version, p.evidenceID, p.responseHash), nil
	case strings.Contains(q, "SELECT details FROM audit_logs"):
		return registrationRow(d.audit), nil
	case strings.Contains(q, "SELECT request_hash FROM system_backup_v2_compact_tombstones"):
		return &registrationTestRows{width: 1}, nil
	case strings.Contains(q, "ORDER BY version DESC"):
		var highest int64
		for k := range d.rows {
			if k > highest {
				highest = k
			}
		}
		return registrationRow(highest), nil
	case strings.Contains(q, "SELECT nonce_hmac_ref_version"):
		return &registrationTestRows{data: [][]driver.Value{{"old"}, {"synthetic-v1"}}, width: 1}, nil
	case strings.Contains(q, "SELECT id FROM system_backup_v2_strong_auth_nonces"):
		if s.consumed && args[1].Value == "old" {
			return registrationRow(int64(9)), nil
		}
		return &registrationTestRows{width: 1}, nil
	case strings.Contains(q, "SELECT owner_target_type,owner_target_public_id"):
		checksum := d.evidenceHash
		if s.wrongEvidence {
			checksum = strings.Repeat("f", 64)
		}
		return registrationRow("system", "installation_synthetic", checksum, int64(len(d.response)), "inline", "healthy", "application/json", d.expires), nil
	case strings.Contains(q, "FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?"):
		version := args[1].Value.(int64)
		v, ok := d.rows[version]
		if !ok {
			return nil, errors.New("missing config")
		}
		cols, values, _ := v.sqlValues("unused", "unused", "unused", version)
		lookup := map[string]any{}
		for i, k := range cols {
			lookup[k] = values[i]
		}
		selectCols := strings.Split(strings.TrimPrefix(strings.Split(q, " FROM ")[0], "SELECT "), ",")
		row := make([]driver.Value, len(selectCols))
		for i, k := range selectCols {
			value := lookup[k]
			converted, e := driver.DefaultParameterConverter.ConvertValue(value)
			if e != nil {
				return nil, e
			}
			row[i] = converted
		}
		if s.materializedDrift {
			row[0] = !v.Enabled()
		}
		return registrationRow(row...), nil
	}
	return nil, errors.New("unexpected query: " + q)
}

type mutationTestResult struct{ id, affected int64 }

func (r mutationTestResult) LastInsertId() (int64, error) { return r.id, nil }
func (r mutationTestResult) RowsAffected() (int64, error) { return r.affected, nil }
func (c *mutationTestConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if !s.activeTx {
		return nil, errors.New("write outside tx")
	}
	d := &s.working
	if s.failWrite == len(d.writes)+1 {
		return nil, errors.New("PRIVATE write failure")
	}
	if strings.Count(q, "?") != len(args) {
		return nil, errors.New("SQL placeholder mismatch")
	}
	kind := ""
	switch {
	case strings.Contains(q, "INSERT INTO audit_logs"):
		kind = "audit"
		var details map[string]any
		if json.Unmarshal([]byte(args[2].Value.(string)), &details) != nil {
			return nil, errors.New("bad audit")
		}
		if strings.Contains(args[1].Value.(string), "intent") {
			d.audit = []byte(args[2].Value.(string))
		}
		if _, ok := details["config"]; ok {
			return nil, errors.New("canonical in audit")
		}
		if strings.Contains(string(d.audit), `"nonce"`) {
			return nil, errors.New("nonce in audit")
		}
	case strings.Contains(q, "INSERT INTO system_backup_v2_configs"):
		kind = "config"
		cols := strings.Split(strings.Split(strings.Split(q, "(")[1], ")")[0], ",")
		values := map[string]any{}
		for i, k := range cols {
			values[k] = args[i].Value
		}
		version := values["version"].(int64)
		v, e := DecodeConfigValues(values["canonical_config_json"].([]byte))
		if e != nil {
			return nil, e
		}
		if values["config_sha256"] != v.SHA256() || values["enabled"] != v.Enabled() {
			return nil, errors.New("snapshot identity")
		}
		if _, exists := d.rows[version]; exists {
			return nil, errors.New("version overwritten")
		}
		if copied := values["copied_from_version"]; copied != nil {
			if _, ok := d.rows[copied.(int64)]; !ok || copied.(int64) >= version {
				return nil, errors.New("bad copied version")
			}
		}
		d.rows[version] = v
	case strings.Contains(q, "UPDATE system_backup_v2_installation_state"):
		kind = "cas"
		if s.zeroCAS {
			return mutationTestResult{0, 0}, nil
		}
		if strings.Contains(q, "first_enabled") || strings.Contains(q, "monitoring") || strings.Contains(q, "last_effective") {
			return nil, errors.New("history reset")
		}
		if args[2].Value != d.active || args[3].Value != d.stateVersion {
			return mutationTestResult{0, 0}, nil
		}
		d.active = args[0].Value.(int64)
		d.stateVersion++
		if s.afterCAS != nil {
			s.afterCAS()
		}
	case strings.Contains(q, "INSERT INTO system_backup_v2_evidence"):
		kind = "evidence"
		if len(args) == 9 {
			d.response = append([]byte(nil), args[2].Value.([]byte)...)
			d.expires = args[5].Value.(time.Time)
			d.evidenceCreated = args[6].Value.(time.Time)
			d.evidencePublicID = args[0].Value.(string)
		} else {
			d.response = append([]byte(nil), args[0].Value.([]byte)...)
			d.expires = args[1].Value.(time.Time)
			policy, err := DecodeCanonicalConfigOperationResponse(d.response)
			if err != nil {
				return nil, err
			}
			d.evidenceCreated = policy.FinishedAt
			d.evidencePublicID = "sev_12345678-1234-1234-1234-123456789abc"
		}
		d.evidenceHash = registrationHash(string(d.response))
		d.evidenceID = int64(100 + len(d.writes) + 1)
	case strings.Contains(q, "INSERT INTO system_backup_v2_operations"):
		kind = "operation"
		d.receipt = &configMutationReceipt{publicID: args[0].Value.(string), hash: args[6].Value.(string), status: "succeeded", httpStatus: 200, version: args[9].Value.(int64), evidenceID: args[10].Value.(int64), responseHash: args[11].Value.(string)}
		if !strings.Contains(q, "updated_at,row_version,result_resource_public_id,retryable,failure_category,failure_message") || len(args) != 17 {
			return nil, errors.New("operation must bind every public time/default explicitly")
		}
		actorID, _ := strconv.ParseInt(args[3].Value.(string), 10, 64)
		d.operationPolicy = ConfigOperationResponsePolicy{InstallationID: args[1].Value.(string), OperationPublicID: args[0].Value.(string), ActorID: actorID, Endpoint: args[4].Value.(string), IdempotencyKey: args[5].Value.(string), RequestHash: args[6].Value.(string), Version: args[9].Value.(int64), RowVersion: 1, DeadlineAt: args[12].Value.(time.Time), StartedAt: args[13].Value.(time.Time), FinishedAt: args[14].Value.(time.Time), CreatedAt: args[15].Value.(time.Time), UpdatedAt: args[16].Value.(time.Time)}
	case strings.Contains(q, "INSERT INTO system_backup_v2_strong_auth_nonces"):
		kind = "nonce"
		if s.zeroNonce {
			return mutationTestResult{0, 0}, nil
		}
		if args[12].Value != int64(102) {
			return nil, errors.New("nonce FK is not actual intent ID")
		}
		if args[11].Value != int64(106) {
			return nil, errors.New("nonce FK is not actual operation ID")
		}
	default:
		return nil, errors.New("unexpected write")
	}
	d.writes = append(d.writes, kind)
	return mutationTestResult{int64(100 + len(d.writes)), 1}, nil
}

type mutationTestAuthority struct {
	s  *mutationTestState
	sc VerifyConfig
}

func (a mutationTestAuthority) Authorize(_ context.Context, tx *sql.Tx, _ RegistrationActor, _ string, _ ConfigValues, _ ConfigValues, risk ConfigMutationRisk, _ time.Time) error {
	s := a.s
	s.authCalls++
	if s.tx == nil {
		s.tx = tx
	}
	if s.tx != tx || !s.activeTx {
		return errors.New("authority wrong tx")
	}
	s.risk = risk
	if s.denied || !s.permissions["configure"] || risk.SecurityBoundary && !s.permissions["security_configure"] || risk.ProtectionReduction && !s.permissions["destructive"] || s.denyFinal && len(s.working.writes) > 0 {
		return ErrRegistrationPermission
	}
	return nil
}
func (a mutationTestAuthority) StrongAuth(_ context.Context, tx *sql.Tx, actor RegistrationActor, _ string, _ ConfigValues, versions []string, _ time.Time) (VerifyConfig, error) {
	a.s.strongCalls++
	if tx != a.s.tx {
		return VerifyConfig{}, errors.New("different tx")
	}
	sc := a.sc
	sc.ExpectedSubject = actor.Subject
	sc.ExpectedSession = actor.Session
	return sc, nil
}
func (a mutationTestAuthority) Reserve(_ context.Context, tx *sql.Tx, _, _ ConfigValues, _ int, now time.Time) (ConfigMutationCapacityReservation, error) {
	if tx != a.s.tx {
		return nil, errors.New("different tx")
	}
	_, e := tx.Exec("INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", int64(42), "capacity-fixture", "{}")
	return &mutationTestCapacity{tx: tx, until: now.Add(48 * time.Hour)}, e
}
func (a mutationTestAuthority) RedactReason(_ context.Context, r *string) (*string, error) {
	if a.s.activeTx {
		return nil, errors.New("redaction under lock")
	}
	return r, nil
}

type mutationTestResolver struct{ s *mutationTestState }

func (a mutationTestResolver) Prepare(_ context.Context, _ string, _ RegistrationActor, _, _ ConfigValues) (ConfigMutationReadiness, error) {
	if a.s.activeTx {
		return nil, errors.New("network under lock")
	}
	a.s.prepares++
	if a.s.callback != nil {
		a.s.callback()
	}
	if a.s.drift {
		a.s.data.stateVersion++
	}
	return mutationTestReadiness{a.s, a.s.now.Add(48 * time.Hour)}, nil
}

type mutationTestReadiness struct {
	s     *mutationTestState
	until time.Time
}

func (a mutationTestReadiness) Recheck(_ context.Context, tx *sql.Tx, _ time.Time) (ConfigMutationRisk, error) {
	a.s.checks++
	if a.s.tx != tx {
		return ConfigMutationRisk{}, errors.New("wrong tx")
	}
	return a.s.extraRisk, nil
}
func (mutationTestReadiness) DeploymentEnabled() bool { return true }
func (a mutationTestReadiness) ValidUntil() time.Time { return a.until }

type mutationTestResponses struct{ s *mutationTestState }

func (a mutationTestResponses) Prepare(_ context.Context, input ConfigMutationOperationPreparation) (PreparedConfigMutationOperationResponse, error) {
	if input.hash == "" || input.operation == "" || input.version < 2 {
		return nil, ErrRegistrationUnavailable
	}
	if a.s.activeTx {
		return nil, errors.New("provider under lock")
	}
	return mutationTestPreparedResponse{s: a.s, expires: input.ValidUntil()}, nil
}
func (a mutationTestResponses) Read(_ context.Context, input ConfigMutationResponseReplayPreparation) (PreparedConfigMutationResponseRead, error) {
	a.s.reads++
	if a.s.activeTx {
		return nil, errors.New("provider read under lock")
	}
	return mutationTestReadResponse{a.s, append([]byte(nil), a.s.data.response...), input.Facts().ValidUntil}, nil
}

type mutationTestReadResponse struct {
	s     *mutationTestState
	raw   []byte
	until time.Time
}

func (r mutationTestReadResponse) Bytes() []byte         { return append([]byte(nil), r.raw...) }
func (r mutationTestReadResponse) ValidUntil() time.Time { return r.until }
func (r mutationTestReadResponse) Recheck(_ context.Context, tx *sql.Tx, _ time.Time) error {
	if tx != r.s.tx || !r.s.activeTx {
		return ErrRegistrationUnavailable
	}
	return nil
}

type mutationTestPreparedResponse struct {
	s       *mutationTestState
	payload []byte
	expires time.Time
}

func (a mutationTestPreparedResponse) ValidUntil() time.Time { return a.expires }

func (a mutationTestPreparedResponse) Stage(ctx context.Context, tx *sql.Tx, _ ConfigOperationResponsePolicy, raw []byte, retain time.Time) (int64, error) {
	a.payload = append([]byte(nil), raw...)
	a.expires = retain
	if a.s.tx != tx {
		return 0, errors.New("wrong tx")
	}
	r, e := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_evidence (inline_payload,expires_at) VALUES (?,?)", a.payload, a.expires)
	if e != nil {
		return 0, e
	}
	return r.LastInsertId()
}
func (a mutationTestPreparedResponse) Recheck(_ context.Context, tx *sql.Tx, _ time.Time) error {
	if a.s.tx != tx {
		return errors.New("wrong tx")
	}
	return nil
}

func mutationTransactionFixture(t *testing.T) (ConfigMutationService, RegistrationActor, []byte, *mutationTestState, VerifyConfig) {
	t.Helper()
	c, e := DecodeConfigValues(bootstrapFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	s := &mutationTestState{data: mutationTestData{rows: map[int64]ConfigValues{1: c}, active: 1, stateVersion: 1}, now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), db: DatabaseIdentity{"12345678-1234-1234-1234-123456789abc", "synthetic_db"}, permissions: map[string]bool{"configure": true, "security_configure": true, "destructive": true}}
	db := sql.OpenDB(mutationTestConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	sc := testConfig(SignatureVerifierFunc(func([]byte, ProofSignature) error { return nil }))
	sc.ActiveNonceHMACKeyVersion = "synthetic-v1"
	sc.NonceHMACKeys = map[string][]byte{"old": []byte(strings.Repeat("o", 32)), "synthetic-v1": []byte(strings.Repeat("n", 32))}
	actor := RegistrationActor{UserID: 42, Subject: "user:42", Session: "session42", SessionIssuedAt: s.now.Add(-time.Hour), SessionExpiresAt: s.now.Add(time.Hour)}
	svc := ConfigMutationService{DB: db, InstallationID: "installation_synthetic", Database: s.db, Authority: mutationTestAuthority{s, sc}, Resolver: mutationTestResolver{s}, Responses: mutationTestResponses{s}}
	var doc map[string]any
	json.Unmarshal(mutationFixture(t), &doc)
	doc["expected_version"] = 1
	raw, _ := json.Marshal(doc)
	return svc, actor, raw, s, sc
}
func mutationTransactionProof(t *testing.T, r ConfigMutationRequest, actor RegistrationActor, now time.Time, sc *VerifyConfig) Proof {
	t.Helper()
	p := testProof()
	p.Payload.Subject = actor.Subject
	p.Payload.Session = actor.Session
	p.Payload.Endpoint = r.endpoint
	p.Payload.IdempotencyKey = "mutation_key_0123456789"
	p.Payload.RequestHash, _ = r.RequestHash("installation_synthetic", "admin", strconv.FormatInt(actor.UserID, 10))
	p.Payload.AuthTime = now.Add(-time.Minute).Format(time.RFC3339Nano)
	p.Payload.ExpiresAt = now.Add(3 * time.Minute).Format(time.RFC3339Nano)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	p.Signature.Algorithm = "EdDSA"
	p.Signature.KeyVersion = "v1"
	p.Signature.KeyID = "strong-key"
	p.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","key_version":"v1","kid":"strong-key","purpose":"strong_auth_issuer","typ":"` + DomainSeparator + `"}`))
	payload, _ := CanonicalPayload(p.Payload)
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	sc.TrustedSigners[p.Payload.Issuer] = map[string]SignatureVerifier{"v1": Ed25519JWSVerifier{PublicKey: key.Public().(ed25519.PublicKey), KeyID: "strong-key", KeyVersion: "v1", Purpose: "strong_auth_issuer"}}
	return p
}

func TestConfigMutationTransactionOrdinaryReplayAndCurrentAuthority(t *testing.T) {
	svc, actor, raw, s, _ := mutationTransactionFixture(t)
	r, e := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-1", raw, nil)
	if e != nil || r.Version != 2 || r.Replayed || s.data.active != 2 || len(s.data.rows) != 2 {
		t.Fatal("mutation", r, e, s.data.writes)
	}
	initialWrites := len(s.data.writes)
	initialPrepares := s.prepares
	r2, e := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-2", raw, &Proof{})
	if e != nil || !r2.Replayed || !bytes.Equal(r.Response, r2.Response) || len(s.data.writes) != initialWrites || s.prepares != initialPrepares || s.strongCalls != 0 {
		t.Fatal("replay reexecuted stale expected version/proof", e, s.data.writes)
	}
	s.denied = true
	if _, e = svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-3", raw, nil); e != ErrRegistrationPermission {
		t.Fatal("revoked replay", e)
	}
}
func TestConfigMutationTransactionFaultsRollbackEverything(t *testing.T) {
	for _, fault := range []string{"capacity", "intent", "config", "cas-write", "evidence", "operation", "result", "cas-count", "evidence-hash", "final-revoke", "final-expiry", "preparation-drift", "canonical-missing", "materialized", "foreign-db", "stale", "denied"} {
		t.Run(fault, func(t *testing.T) {
			svc, actor, raw, s, _ := mutationTransactionFixture(t)
			switch fault {
			case "capacity":
				s.failWrite = 1
			case "intent":
				s.failWrite = 2
			case "config":
				s.failWrite = 3
			case "cas-write":
				s.failWrite = 4
			case "evidence":
				s.failWrite = 5
			case "operation":
				s.failWrite = 6
			case "result":
				s.failWrite = 7
			case "cas-count":
				s.zeroCAS = true
			case "evidence-hash":
				s.wrongEvidence = true
			case "final-revoke":
				s.denyFinal = true
			case "final-expiry":
				s.expiredFinal = true
			case "preparation-drift":
				s.drift = true
			case "canonical-missing":
				s.missingCanonical = true
			case "materialized":
				s.materializedDrift = true
			case "foreign-db":
				s.wrongDatabase = true
			case "stale":
				raw = bytes.Replace(raw, []byte(`"expected_version":1`), []byte(`"expected_version":2`), 1)
			case "denied":
				s.denied = true
			}
			result, e := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-1", raw, nil)
			if e == nil || result.HTTPStatus != 0 || s.data.active != 1 || len(s.data.rows) != 1 || s.data.receipt != nil || len(s.data.writes) != 0 || s.activeTx {
				t.Fatal("failed mutation committed", e, result.HTTPStatus, result.Version, s.data.writes)
			}
		})
	}
}
func TestConfigMutationTransactionUnknownCommitIsObservedWithoutWrites(t *testing.T) {
	svc, actor, raw, s, _ := mutationTransactionFixture(t)
	s.commitUnknown = true
	result, e := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-1", raw, nil)
	if e != ErrConfigCommitUnknown || result.HTTPStatus != 0 || s.data.active != 2 {
		t.Fatal("unknown commit", e, result)
	}
	count := len(s.data.writes)
	s.commitUnknown = false
	observed, e := svc.ObserveCommitted(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "observe-1", raw)
	if e != nil || observed.Version != 2 || !observed.Replayed || len(s.data.writes) != count {
		t.Fatal("observation rewrote", e)
	}
}
func TestConfigMutationTransactionStrongAuthNonceAndRisk(t *testing.T) {
	for _, fault := range []string{"success", "missing-proof", "old-nonce", "zero-nonce", "nonce-write", "no-destructive", "no-security", "final-revoke"} {
		t.Run(fault, func(t *testing.T) {
			svc, actor, raw, s, sc := mutationTransactionFixture(t)
			raw = bytes.Replace(raw, []byte(`"retention_seconds":2592000`), []byte(`"retention_seconds":86400`), 1)
			raw = bytes.Replace(raw, []byte(`"change_reason":null`), []byte(`"change_reason":"reviewed retention change"`), 1)
			if fault == "no-security" {
				s.extraRisk.SecurityBoundary = true
				s.permissions["security_configure"] = false
			}
			r, _ := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
			proof := mutationTransactionProof(t, r, actor, s.now, &sc)
			svc.Authority = mutationTestAuthority{s, sc}
			p := &proof
			switch fault {
			case "missing-proof":
				p = nil
			case "old-nonce":
				s.consumed = true
			case "zero-nonce":
				s.zeroNonce = true
			case "nonce-write":
				s.failWrite = 7
			case "no-destructive":
				s.permissions["destructive"] = false
			case "final-revoke":
				s.denyFinal = true
			}
			result, e := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-1", raw, p)
			if fault == "success" {
				if e != nil || result.Version != 2 || !s.risk.ProtectionReduction || s.strongCalls != 2 {
					t.Fatal("strong mutation", e, s.data.writes, s.strongCalls)
				}
				s.permissions["destructive"] = false
				if _, e = svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "request-2", raw, nil); e != ErrRegistrationPermission {
					t.Fatal("replay omitted original destructive permission", e)
				}
			} else if e == nil || result.HTTPStatus != 0 || s.data.active != 1 || len(s.data.writes) != 0 {
				t.Fatal("nonce/risk failure committed", fault, e, s.data.writes)
			}
		})
	}
}
func TestConfigMutationTransactionRollbackAppendsAndPreservesHistory(t *testing.T) {
	svc, actor, _, s, _ := mutationTransactionFixture(t)
	old := s.data.rows[1]
	otherRaw := bytes.Replace(old.CanonicalJSON(), []byte(`"enabled":false`), []byte(`"enabled":true`), 1)
	other, e := DecodeConfigValues(otherRaw)
	if e != nil {
		t.Fatal(e)
	}
	s.data.rows[2] = other
	s.data.active = 2
	raw := []byte(`{"rollback_from_version":1,"expected_version":2,"change_reason":null}`)
	result, e := svc.Mutate(context.Background(), actor, ConfigRollbackEndpoint, "mutation_key_0123456789", "request-1", raw, nil)
	if e != nil || result.Version != 3 || s.data.active != 3 || len(s.data.rows) != 3 || s.data.rows[2].SHA256() != other.SHA256() || s.data.rows[3].SHA256() != old.SHA256() {
		t.Fatal("rollback overwrote history", e, s.data.writes)
	}
}
