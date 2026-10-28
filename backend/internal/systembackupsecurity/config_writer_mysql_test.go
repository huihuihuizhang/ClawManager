//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// This isolated candidate executes the real writer, JWT/session/RBAC checks,
// Operation evidence adapter, FKs and transactions. Resource readiness and
// capacity are explicitly synthetic; this is not a deployment admission test.
const configWriterCandidateSHA256 = "14db3b88263f0ab3e31e293aa0351bb08da23464d4a0fee8854263d56354cce1"

type configWriterProbeInputs struct {
	Kind            string          `json:"kind"`
	MigrationInputs json.RawMessage `json:"migration_inputs"`
	CandidateDDL    string          `json:"candidate_ddl"`
	CandidateSHA256 string          `json:"candidate_sha256"`
}

func decodeConfigWriterProbeInputs(raw []byte, digest string) (configWriterProbeInputs, configProofProbeInputs, error) {
	var input configWriterProbeInputs
	var fields map[string]json.RawMessage
	if len(raw) > 65536 || registrationHash(string(raw)) != digest || !providerJSONUnicode(raw) ||
		!providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) || json.Unmarshal(raw, &fields) != nil ||
		!providerFieldSet(fields, "kind", "migration_inputs", "candidate_ddl", "candidate_sha256") || json.Unmarshal(raw, &input) != nil ||
		input.Kind != "d_config_writer_probe_inputs.v1" || input.CandidateSHA256 != configWriterCandidateSHA256 || registrationHash(input.CandidateDDL) != input.CandidateSHA256 {
		return input, configProofProbeInputs{}, ErrConfigMutation
	}
	base, err := decodeConfigProofProbeInputs(input.MigrationInputs, registrationHash(string(input.MigrationInputs)))
	return input, base, err
}

type configWriterSyntheticReadiness struct {
	identity DatabaseIdentity
	until    time.Time
	risk     ConfigMutationRisk
}

func (r configWriterSyntheticReadiness) ValidUntil() time.Time { return r.until }
func (configWriterSyntheticReadiness) DeploymentEnabled() bool { return false }
func (r configWriterSyntheticReadiness) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) (ConfigMutationRisk, error) {
	if !now.Before(r.until) {
		return ConfigMutationRisk{}, ErrRegistrationUnavailable
	}
	return r.risk, r.identity.check(ctx, tx)
}

type configWriterSyntheticResolver struct {
	readiness configWriterSyntheticReadiness
	prepare   func()
}

func (r configWriterSyntheticResolver) Prepare(context.Context, string, RegistrationActor, ConfigValues, ConfigValues) (ConfigMutationReadiness, error) {
	if r.prepare != nil {
		r.prepare()
	}
	return r.readiness, nil
}

type configWriterSyntheticCapacity struct {
	tx       *sql.Tx
	identity DatabaseIdentity
	until    time.Time
}

func (r configWriterSyntheticCapacity) ValidUntil() time.Time { return r.until }
func (r configWriterSyntheticCapacity) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if tx != r.tx || !now.Before(r.until) {
		return ErrRegistrationUnavailable
	}
	return r.identity.check(ctx, tx)
}

type configWriterMySQLFixture struct {
	proof     *configProofMySQLFixture
	svc       ConfigMutationService
	current   ConfigValues
	proposed  ConfigValues
	readiness configWriterSyntheticReadiness
}

func newConfigWriterMySQLFixture(t *testing.T, proof *configProofMySQLFixture) *configWriterMySQLFixture {
	t.Helper()
	db, ctx := proof.db, proof.ctx
	// Bootstrap inserted this fixture in this fresh, run-owned schema. Fill only
	// its synthetic original bytes; never discover or modify historical configs.
	var document map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(bootstrapFixture(t), &document))
	var pins []BootstrapRegistryRef
	mysqlMust(t, json.Unmarshal(document["registries"], &pins))
	for i := range pins {
		switch pins[i].Kind {
		case "rbac_bindings":
			pins[i].Version, pins[i].SHA256 = proof.current.RBACRegistryVersion, proof.current.RBACRegistrySHA256
		case "strong_auth_issuers":
			pins[i].Version, pins[i].SHA256 = proof.current.StrongAuthRegistryVersion, proof.current.StrongAuthRegistrySHA256
		}
	}
	var err error
	document["registries"], err = json.Marshal(pins)
	mysqlMust(t, err)
	raw, err := json.Marshal(document)
	mysqlMust(t, err)
	current, err := DecodeConfigValues(raw)
	mysqlMust(t, err)
	filled, err := db.ExecContext(ctx, "UPDATE system_backup_v2_configs SET canonical_config_json=? WHERE origin_installation_id=? AND version=1 AND canonical_config_json IS NULL AND config_sha256=? AND config_size_bytes=?", current.CanonicalJSON(), proof.installation, current.SHA256(), len(current.CanonicalJSON()))
	mysqlMust(t, err)
	if !configMutationOne(filled, nil) {
		t.Fatal("synthetic fixture original canonical bytes were not installed exactly once")
	}
	// Register after A's fixture cleanup so receipt/nonce FKs are removed first.
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var uuid string
		if db.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != proof.identity.ServerUUID {
			t.Error("CLEANUP_PENDING config-writer identity")
			return
		}
		for _, q := range []string{
			"DELETE FROM system_backup_v2_strong_auth_nonces WHERE origin_installation_id=?",
			"DELETE FROM system_backup_v2_operations WHERE origin_installation_id=?",
			"DELETE FROM system_backup_v2_evidence WHERE owner_target_type='system' AND owner_target_public_id=?",
			"DELETE FROM system_backup_v2_installation_state WHERE origin_installation_id=?",
			// MySQL checks the self-FK immediately. Remove copied versions first.
			"DELETE FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version DESC",
		} {
			if _, e := db.ExecContext(cleanup, q, proof.installation); e != nil {
				t.Error("CLEANUP_PENDING config-writer FK rows")
				return
			}
		}
		var count int
		if db.QueryRowContext(cleanup, "SELECT (SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=?)+(SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='system' AND owner_target_public_id=?)+(SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=?)+(SELECT COUNT(*) FROM system_backup_v2_installation_state WHERE origin_installation_id=?)+(SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces WHERE origin_installation_id=?)", proof.installation, proof.installation, proof.installation, proof.installation, proof.installation).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING writer row absence")
			return
		}
		t.Log("CLEANED config-writer owned nonce/operation/evidence/state/config rows")
	})
	root := t.TempDir()
	t.Logf("LOCAL_WRITER_RBAC_TEMP path=%s", root)
	var rbac []byte
	for _, pin := range pins {
		if pin.Kind == "rbac_bindings" {
			rbac, err = json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": pin.Version, "installation_id": proof.installation, "bindings": []map[string]string{{"actor_id": strconv.FormatInt(proof.userID, 10), "subject": proof.actor.Subject, "role": "security_admin"}}})
			mysqlMust(t, err)
			if registrationHash(string(rbac)) != pin.SHA256 {
				t.Fatal("synthetic RBAC bytes differ from SQL pin")
			}
			replayWriteRBAC(t, root, rbac, pin.Version)
		}
	}
	sessions, err := NewSQLLoginSessions(db, proof.identity, proof.installation, proof.jwtSecret)
	mysqlMust(t, err)
	responses, err := NewSQLOperationResponses(db, proof.identity, proof.installation, sessions, root)
	mysqlMust(t, err)
	files := RegistrationFiles{RegistryDirectory: root}
	authority, err := NewPinnedConfigMutationAuthority(proof.installation, ConfigMutationAuthoritySources{
		CheckSession: sessions.CheckConfigMutationSession, RegistryBytes: files.RegistryBytes,
		StrongAuth: func(_ context.Context, _ *sql.Tx, actor RegistrationActor, _ string, _ ConfigValues, versions []string, _ time.Time) (VerifyConfig, error) {
			if !reflect.DeepEqual(versions, []string{proof.current.NonceKeyVersion}) {
				return VerifyConfig{}, ErrRegistrationUnavailable
			}
			key := proof.svc.Issuer.Key
			return VerifyConfig{MaxAge: 5 * time.Minute, ClockSkew: time.Second, ExpectedAudience: proof.svc.Issuer.Audience, ExpectedSubject: actor.Subject, ExpectedSession: actor.Session, TrustedSigners: map[string]map[string]SignatureVerifier{key.Issuer: {key.KeyVersion: Ed25519JWSVerifier{PublicKey: key.PublicKey, KeyID: key.KeyID, KeyVersion: key.KeyVersion, Purpose: key.Purpose}}}, TrustedIssuerPolicies: map[string]IssuerPolicy{key.Issuer: key.Policy}, NonceHMACKeys: map[string][]byte{proof.current.NonceKeyVersion: bytes.Repeat([]byte{4}, 32)}, ActiveNonceHMACKeyVersion: proof.current.NonceKeyVersion, RequiredNonceHMACKeyVersions: []string{proof.current.NonceKeyVersion}}, nil
		},
		ReserveMetadata: func(_ context.Context, tx *sql.Tx, _, _ ConfigValues, size int, now time.Time) (ConfigMutationCapacityReservation, error) {
			if size < MaxConfigOperationResponseBytes {
				return nil, ErrRegistrationUnavailable
			}
			return configWriterSyntheticCapacity{tx, proof.identity, now.Add(time.Minute)}, nil
		},
		RedactReason: func(_ context.Context, reason *string) (*string, error) {
			if reason == nil {
				return nil, nil
			}
			out := "synthetic writer reason"
			return &out, nil
		},
	})
	mysqlMust(t, err)
	ready := configWriterSyntheticReadiness{identity: proof.identity, until: configProofDBNow(t, ctx, db).Add(2 * time.Minute)}
	return &configWriterMySQLFixture{proof: proof, current: current, proposed: configWriterProposed(t, current), readiness: ready, svc: ConfigMutationService{DB: db, InstallationID: proof.installation, Database: proof.identity, Authority: authority, Resolver: configWriterSyntheticResolver{readiness: ready}, Responses: responses}}
}

func configWriterProposed(t *testing.T, current ConfigValues) ConfigValues {
	t.Helper()
	var doc map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(current.CanonicalJSON(), &doc))
	doc["enabled"] = json.RawMessage(`true`)
	raw, err := json.Marshal(doc)
	mysqlMust(t, err)
	proposed, err := DecodeConfigValues(raw)
	mysqlMust(t, err)
	if current.Enabled() || !proposed.Enabled() || current.SHA256() == proposed.SHA256() {
		t.Fatal("fixture must change enabled false to true")
	}
	return proposed
}

func (f *configWriterMySQLFixture) request(t *testing.T, endpoint string, expected int64) []byte {
	t.Helper()
	doc := map[string]any{"expected_version": expected, "change_reason": "synthetic writer reason"}
	if endpoint == ConfigUpdateEndpoint {
		doc["config"] = json.RawMessage(f.proposed.CanonicalJSON())
	} else {
		doc["rollback_from_version"] = 1
	}
	raw, err := json.Marshal(doc)
	mysqlMust(t, err)
	_, err = DecodeConfigMutationRequest(endpoint, raw)
	mysqlMust(t, err)
	return raw
}
func (f *configWriterMySQLFixture) counts(t *testing.T) []int64 {
	t.Helper()
	p := f.proof
	out := make([]int64, 7)
	for i, q := range []string{
		"SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=?",
		"SELECT row_version FROM system_backup_v2_installation_state WHERE origin_installation_id=?",
		"SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=?",
		"SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=?",
		"SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='system' AND owner_target_public_id=?",
		"SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces WHERE origin_installation_id=?",
		"SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action LIKE 'system_backup.config_update.%'",
	} {
		var arg any = p.installation
		if i == 6 {
			arg = p.userID
		}
		mysqlMust(t, p.db.QueryRowContext(p.ctx, q, arg).Scan(&out[i]))
	}
	return out
}
func (f *configWriterMySQLFixture) checkCommitted(t *testing.T, result ConfigMutationResult, endpoint, key string, raw []byte, version int64) {
	t.Helper()
	p := f.proof
	policy, err := DecodeCanonicalConfigOperationResponse(result.Response)
	mysqlMust(t, err)
	r, err := DecodeConfigMutationRequest(endpoint, raw)
	mysqlMust(t, err)
	hash, err := r.RequestHash(p.installation, "admin", strconv.FormatInt(p.userID, 10))
	mysqlMust(t, err)
	if result.Version != version || result.HTTPStatus != 200 || policy.Version != version || policy.Endpoint != endpoint || policy.IdempotencyKey != key || policy.RequestHash != hash || policy.ActorID != p.userID || policy.OperationPublicID != result.OperationPublicID || policy.InstallationID != p.installation {
		t.Fatal("wrong closed Operation scope")
	}
	tx, err := p.db.BeginTx(p.ctx, nil)
	mysqlMust(t, err)
	defer tx.Rollback()
	row, err := readConfigMutationRow(p.ctx, tx, p.installation, version)
	mysqlMust(t, err)
	expected := f.current
	if endpoint == ConfigUpdateEndpoint {
		expected = f.proposed
	}
	if !bytes.Equal(row.values.CanonicalJSON(), expected.CanonicalJSON()) {
		t.Fatal("SQL materialized/canonical identity mismatch")
	}
	original, err := readConfigMutationRow(p.ctx, tx, p.installation, 1)
	mysqlMust(t, err)
	if original.rowVersion != 1 || !bytes.Equal(original.values.CanonicalJSON(), f.current.CanonicalJSON()) {
		t.Fatal("writer overwrote historical original")
	}
	var body []byte
	var sha string
	var created, finished, updated time.Time
	var copied sql.NullInt64
	mysqlMust(t, tx.QueryRowContext(p.ctx, "SELECT e.inline_payload,e.content_checksum,o.created_at,o.finished_at,o.updated_at FROM system_backup_v2_operations o JOIN system_backup_v2_evidence e ON e.id=o.redacted_response_evidence_id WHERE o.origin_installation_id=? AND o.public_id=?", p.installation, result.OperationPublicID).Scan(&body, &sha, &created, &finished, &updated))
	if !bytes.Equal(body, result.Response) || sha != registrationHash(string(body)) || !created.Equal(policy.CreatedAt) || !finished.Equal(policy.FinishedAt) || !updated.Equal(policy.UpdatedAt) {
		t.Fatal("original Operation bytes/times/checksum diverged from SQL")
	}
	mysqlMust(t, tx.QueryRowContext(p.ctx, "SELECT copied_from_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", p.installation, version).Scan(&copied))
	if endpoint == ConfigRollbackEndpoint && (!copied.Valid || copied.Int64 != 1) || endpoint == ConfigUpdateEndpoint && copied.Valid {
		t.Fatal("rollback provenance differs")
	}
}

func configWriterMySQLDatabase(t *testing.T) (context.Context, *sql.DB, *mysql.Config, DatabaseIdentity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	t.Cleanup(cancel)
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	cfg, err := sessionProbeConfig(run, uid, os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD"))
	mysqlMust(t, err)
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(12)
	var gotRun, gotUID, pinnedUUID, actualUUID string
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinnedUUID))
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID))
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("writer requires fresh run-owned database")
	}
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mysqlMust(t, err)
	inputs, base, err := decodeConfigWriterProbeInputs(raw, os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256"))
	mysqlMust(t, err)
	rows, err := db.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	mysqlMust(t, err)
	var names []string
	for rows.Next() {
		var name string
		mysqlMust(t, rows.Scan(&name))
		names = append(names, name)
	}
	mysqlMust(t, rows.Err())
	mysqlMust(t, rows.Close())
	if !reflect.DeepEqual(names, base.Filenames) {
		t.Fatal("full migration ledger differs")
	}
	for _, table := range []string{"users", "audit_logs", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_strong_auth_nonces", "system_backup_v2_admin_sessions", "system_backup_v2_admin_revocations"} {
		var engine string
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&engine))
		if engine != "InnoDB" {
			t.Fatal("real InnoDB required")
		}
	}
	var exists int
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' AND COLUMN_NAME='canonical_config_json'").Scan(&exists))
	if exists != 0 {
		t.Fatal("candidate column unexpectedly preinstalled")
	}
	_, err = db.ExecContext(ctx, inputs.CandidateDDL)
	mysqlMust(t, err)
	identity := DatabaseIdentity{ServerUUID: actualUUID, Database: cfg.DBName}
	return ctx, db, cfg, identity
}

func TestDConfigWriterMySQL(t *testing.T) {
	ctx, db, cfg, identity := configWriterMySQLDatabase(t)
	for _, name := range []string{"http_update_replay_rollback", "operation_failure_atomic_rollback", "result_audit_failure_nonce_rollback", "same_key_concurrent_once", "same_version_concurrent_cas", "lost_commit_observe_only", "revoked_session_denies_replay", "corrupt_receipt_denies_replay"} {
		if !t.Run(name, func(t *testing.T) {
			p := newConfigProofMySQLFixture(t, ctx, db, cfg, identity)
			f := newConfigWriterMySQLFixture(t, p)
			key := "writer_mysql_key_0123456789"
			raw := f.request(t, ConfigUpdateEndpoint, 1)
			switch name {
			case "http_update_replay_rollback":
				handler, e := NewConfigMutationHTTP(p.installation, JWTRegistrationAuthenticator{Secret: p.jwtSecret}, f.svc)
				mysqlMust(t, e)
				server := httptest.NewTLSServer(handler)
				defer server.Close()
				do := func(method, path, key string, body []byte) (int, []byte) {
					r, e := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
					mysqlMust(t, e)
					r.Header.Set("Authorization", "Bearer "+p.token)
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Idempotency-Key", key)
					response, e := server.Client().Do(r)
					mysqlMust(t, e)
					defer response.Body.Close()
					out, e := io.ReadAll(io.LimitReader(response.Body, MaxConfigOperationResponseBytes+1))
					mysqlMust(t, e)
					return response.StatusCode, out
				}
				status, body := do("PUT", ConfigMutationPath, key, raw)
				if status != 200 {
					t.Fatalf("writer HTTP status=%d body=%s", status, body)
				}
				policy, e := DecodeCanonicalConfigOperationResponse(body)
				mysqlMust(t, e)
				f.checkCommitted(t, ConfigMutationResult{OperationPublicID: policy.OperationPublicID, Version: 2, HTTPStatus: 200, Response: body}, ConfigUpdateEndpoint, key, raw, 2)
				before := f.counts(t)
				status, replay := do("PUT", ConfigMutationPath, key, raw)
				if status != 200 || !bytes.Equal(replay, body) || !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("replay changed original receipt or wrote SQL")
				}
				changed := f.request(t, ConfigUpdateEndpoint, 2)
				status, _ = do("PUT", ConfigMutationPath, key, changed)
				if status != 409 {
					t.Fatal("same key different request not rejected")
				}
				status, _ = do("PUT", ConfigMutationPath, key+"_stale", raw)
				if status != 409 {
					t.Fatal("stale version not rejected")
				}
				rollback := f.request(t, ConfigRollbackEndpoint, 2)
				status, body = do("POST", ConfigRollbackPath, key+"_rollback", rollback)
				if status != 200 {
					t.Fatalf("rollback status=%d body=%s", status, body)
				}
				policy, e = DecodeCanonicalConfigOperationResponse(body)
				mysqlMust(t, e)
				f.checkCommitted(t, ConfigMutationResult{OperationPublicID: policy.OperationPublicID, Version: 3, HTTPStatus: 200, Response: body}, ConfigRollbackEndpoint, key+"_rollback", rollback, 3)
				if !reflect.DeepEqual(f.counts(t), []int64{3, 3, 3, 2, 2, 0, 4}) {
					t.Fatal("append/receipt/audit cardinality mismatch")
				}
			case "operation_failure_atomic_rollback", "result_audit_failure_nonce_rollback":
				var proof *Proof
				if strings.HasPrefix(name, "result_") {
					f.readiness.risk.SecurityBoundary = true
					f.svc.Resolver = configWriterSyntheticResolver{readiness: f.readiness}
					request, e := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
					mysqlMust(t, e)
					issued, e := p.svc.VerifyConfigMutationAndIssue(ctx, p.actor, p.password, p.code(t), request, key)
					mysqlMust(t, e)
					proof = &issued
				}
				trigger := "d_writer_" + p.installation[len(p.installation)-24:]
				table, condition := "system_backup_v2_operations", "NEW.origin_installation_id='"+p.installation+"'"
				if proof != nil {
					table = "audit_logs"
					condition = "NEW.user_id=" + strconv.FormatInt(p.userID, 10) + " AND NEW.action='system_backup.config_update.result'"
				}
				_, e := db.ExecContext(ctx, "CREATE TRIGGER "+trigger+" BEFORE INSERT ON "+table+" FOR EACH ROW BEGIN IF "+condition+" THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic writer atomicity fault'; END IF; END")
				mysqlMust(t, e)
				triggerInstalled := true
				defer func() {
					if !triggerInstalled {
						return
					}
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					var uuid string
					if db.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != identity.ServerUUID {
						t.Error("CLEANUP_PENDING writer trigger identity")
						return
					}
					if _, e := db.ExecContext(cleanup, "DROP TRIGGER "+trigger); e != nil {
						t.Error("CLEANUP_PENDING writer trigger")
					}
				}()
				before := f.counts(t)
				_, e = f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-fault", raw, proof)
				if !errors.Is(e, ErrProviderEvidenceStorage) || !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatalf("fault failed to roll back all writer rows: %v", e)
				}
				_, e = db.ExecContext(ctx, "DROP TRIGGER "+trigger)
				mysqlMust(t, e)
				triggerInstalled = false
				// Retry only the explicitly failed transaction with the SAME proof.
				// This must commit and proves that rollback did not consume its nonce.
				success, e := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-after-fault", raw, proof)
				mysqlMust(t, e)
				f.checkCommitted(t, success, ConfigUpdateEndpoint, key, raw, 2)
				expected := []int64{2, 2, 2, 1, 1, 0, 2}
				if proof != nil {
					expected[5] = 1
				}
				if !reflect.DeepEqual(expected, f.counts(t)) {
					t.Fatal("retry duplicated effects or failed to consume nonce")
				}
				if proof != nil {
					var anchors int
					mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces n JOIN system_backup_v2_operations o ON o.id=n.operation_id JOIN audit_logs a ON a.id=n.audit_log_id WHERE n.origin_installation_id=? AND o.public_id=? AND a.user_id=? AND a.action='system_backup.config_update.intent'", p.installation, success.OperationPublicID, p.userID).Scan(&anchors))
					if anchors != 1 {
						t.Fatal("nonce does not bind real operation/audit FK")
					}
					before = f.counts(t)
					replay, e := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-proof-replay", raw, nil)
					mysqlMust(t, e)
					if !replay.Replayed || !bytes.Equal(replay.Response, success.Response) || !reflect.DeepEqual(before, f.counts(t)) {
						t.Fatal("committed proof receipt was not replayable without a new proof")
					}
				}
			case "same_key_concurrent_once", "same_version_concurrent_cas":
				workersCtx, cancelWorkers := context.WithTimeout(ctx, 20*time.Second)
				var workers sync.WaitGroup
				entered, release := make(chan struct{}, 2), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				defer func() { unblock(); cancelWorkers(); workers.Wait() }()
				f.svc.Resolver = configWriterSyntheticResolver{readiness: f.readiness, prepare: func() {
					entered <- struct{}{}
					select {
					case <-release:
					case <-workersCtx.Done():
					}
				}}
				type outcome struct {
					result ConfigMutationResult
					err    error
				}
				out := make(chan outcome, 2)
				for i := 0; i < 2; i++ {
					requestKey := key
					if name == "same_version_concurrent_cas" {
						requestKey += strconv.Itoa(i)
					}
					workers.Add(1)
					go func(k string) {
						defer workers.Done()
						result, e := f.svc.Mutate(workersCtx, p.actor, ConfigUpdateEndpoint, k, "writer-concurrent", raw, nil)
						out <- outcome{result, e}
					}(requestKey)
				}
				for i := 0; i < 2; i++ {
					select {
					case <-entered:
					case <-time.After(8 * time.Second):
						t.Fatal("both lock-free preparations did not arrive")
					}
				}
				unblock()
				first, second := <-out, <-out
				if name == "same_key_concurrent_once" {
					if first.err != nil || second.err != nil || first.result.Replayed == second.result.Replayed || !bytes.Equal(first.result.Response, second.result.Response) {
						t.Fatalf("one commit/original replay required: %v %v", first.err, second.err)
					}
				} else {
					if (first.err == nil) == (second.err == nil) || first.err != nil && !errors.Is(first.err, ErrConfigVersionConflict) || second.err != nil && !errors.Is(second.err, ErrConfigVersionConflict) {
						t.Fatalf("one CAS winner required: %v %v", first.err, second.err)
					}
				}
				if !reflect.DeepEqual(f.counts(t), []int64{2, 2, 2, 1, 1, 0, 2}) {
					t.Fatal("concurrent writer duplicated effects")
				}
			case "lost_commit_observe_only":
				connector, e := mysql.NewConnector(p.cfg)
				mysqlMust(t, e)
				lost := &configProofLostCommitConnector{base: connector}
				lostDB := sql.OpenDB(lost)
				defer lostDB.Close()
				f.svc.DB = lostDB
				_, e = f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-lost-ack", raw, nil)
				if !errors.Is(e, ErrConfigCommitUnknown) || !lost.lost.Load() {
					t.Fatalf("expected lost reply after actual commit: %v", e)
				}
				before := f.counts(t)
				observed, e := f.svc.ObserveCommitted(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-observe", raw)
				mysqlMust(t, e)
				if !observed.Replayed || !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("observation rewrote committed transaction")
				}
				f.checkCommitted(t, observed, ConfigUpdateEndpoint, key, raw, 2)
			default:
				first, e := f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-replay-guard", raw, nil)
				mysqlMust(t, e)
				if name == "revoked_session_denies_replay" {
					_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=?", p.installation, p.actor.Session)
				} else {
					_, e = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence e JOIN system_backup_v2_operations o ON o.redacted_response_evidence_id=e.id SET e.inline_payload=? WHERE o.origin_installation_id=? AND o.public_id=?", bytes.Repeat([]byte{' '}, len(first.Response)), p.installation, first.OperationPublicID)
				}
				mysqlMust(t, e)
				before := f.counts(t)
				_, e = f.svc.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "writer-denied-replay", raw, nil)
				if e == nil || !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("invalid replay was accepted or wrote SQL")
				}
				if name == "revoked_session_denies_replay" && !errors.Is(e, ErrRegistrationPermission) {
					t.Fatalf("revocation classification: %v", e)
				}
			}
		}) {
			return
		}
	}
	if !t.Run("a_security", func(t *testing.T) { runAConfigWriterSecurityCases(t, ctx, db, cfg, identity) }) {
		return
	}
	t.Log("PASS real MySQL writer candidate: TLS/JWT update+rollback, original receipt, conflict, atomic rollback incl nonce, concurrent idempotency/CAS, lost-commit observation, revocation/corruption guards, A observed-lock/final-expiry/protected-rollback cases; synthetic_readiness=yes synthetic_capacity=yes production_approval=no")
}
