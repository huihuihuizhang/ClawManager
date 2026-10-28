//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// These deployment-shaped owner rows, reports and provider objects are test
// inputs. Every SQL statement/row/clock/transaction is actual MySQL, including
// the admission, current-authority and independent result implementations.
type aAdmissionMySQLOwners struct {
	f         *aDownloadMFAFixture
	registry  SQLRegistry
	onRecheck func(context.Context, *sql.Tx) error
	checks    atomic.Int64
}

func (o *aAdmissionMySQLOwners) owner(ctx context.Context, tx *sql.Tx, i Identity, lock, visible bool) (time.Time, error) {
	query := "SELECT installation,owner_type,deadline,visible FROM synthetic_download_mfa_owner WHERE owner_id=?"
	if lock {
		query += " FOR UPDATE"
	}
	var installation, kind string
	var until time.Time
	var allowed bool
	if tx.QueryRowContext(ctx, query, i.OwnerID).Scan(&installation, &kind, &until, &allowed) != nil || installation != i.Installation || kind != i.OwnerType || visible && !allowed {
		return time.Time{}, ErrDenied
	}
	return until, nil
}
func (o *aAdmissionMySQLOwners) Preview(ctx context.Context, tx *sql.Tx, installation string, actor sec.RegistrationActor, id string) (Record, error) {
	if installation != o.registry.Installation || !sameDownloadAdmissionActor(actor, o.f.env.actor) {
		return Record{}, ErrDenied
	}
	return o.registry.PreviewDownloadEvidence(ctx, tx, id, func(ctx context.Context, tx *sql.Tx, i Identity) (time.Time, error) {
		return o.owner(ctx, tx, i, false, true)
	})
}
func (o *aAdmissionMySQLOwners) LockOwnerReferences(ctx context.Context, tx *sql.Tx, r Record) error {
	// Locking is also needed to record an already interrupted/revoked result;
	// current visibility is checked by Preview/Recheck/SQLPolicy authorization.
	_, err := o.owner(ctx, tx, r.Manifest.Identity, true, false)
	return err
}
func (o *aAdmissionMySQLOwners) Recheck(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, r Record) error {
	o.checks.Add(1)
	if o.onRecheck != nil {
		if err := o.onRecheck(ctx, tx); err != nil {
			return err
		}
	}
	until, err := o.owner(ctx, tx, r.Manifest.Identity, false, true)
	if err != nil || !sameDownloadAdmissionActor(actor, o.f.env.actor) || !until.Equal(r.OwnerDeadline) {
		return ErrDenied
	}
	return nil
}

type aAdmissionMySQLPolicy struct{ owners *aAdmissionMySQLOwners }

func (p aAdmissionMySQLPolicy) LockScope(ctx context.Context, tx *sql.Tx, installation string, i Identity) error {
	if installation != p.owners.registry.Installation {
		return ErrDenied
	}
	_, err := p.owners.owner(ctx, tx, i, true, false)
	return err
}
func (aAdmissionMySQLPolicy) Admit(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (p aAdmissionMySQLPolicy) Authorize(ctx context.Context, tx *sql.Tx, a Actor, r Record, permissions []string) error {
	if a != downloadActor(p.owners.f.env.actor) || len(permissions) == 0 {
		return ErrDenied
	}
	_, err := p.owners.owner(ctx, tx, r.Manifest.Identity, false, true)
	return err
}
func (aAdmissionMySQLPolicy) Deletable(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (aAdmissionMySQLPolicy) Audit(context.Context, *sql.Tx, Audit) error { return ErrDenied }
func (p aAdmissionMySQLPolicy) OwnerDeadline(ctx context.Context, tx *sql.Tx, i Identity) (time.Time, error) {
	return p.owners.owner(ctx, tx, i, false, true)
}

type aAdmissionMySQLFixture struct {
	*aDownloadMFAFixture
	registry      SQLRegistry
	owners        *aAdmissionMySQLOwners
	admission     *DownloadAdmissionService
	authority     *SQLDownloadAuthority
	results       *SQLDownloadResults
	store         *committedScopedReadStore
	plain, object []byte
	keys          testKeys
	proof         sec.Proof
}

// Seed uses the exact existing full-catalog/canonical/ownership capsule. The
// ownership candidate already includes operation/receipt/nonce constraints.
func TestADownloadAdmissionMySQLSeed(t *testing.T) {
	input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
	mustSQL(t, err)
	for _, part := range []string{"CREATE TABLE system_backup_v2_download_admission_receipts", "CREATE TABLE system_backup_v2_download_result_receipts", "sbv2_fk_sb_download_result_group", "sbv2_fk_sb_download_result_audit", "sbv2_fk_sb_auth_nonce_operation_installation", "sbv2_chk_sb_operation_download_admission", "retain_until > claim_expires_at"} {
		if !strings.Contains(input.OwnershipDDL, part) {
			t.Fatal("full admission DDL absent from pinned capsule", part)
		}
	}
	t.Run("detached_embedded_config", func(t *testing.T) {
		p := aDownloadMFAPinnedFixture(t, input)
		if p.db.configCells["nonce_hmac_ref_version"] != "v2" || len(p.noncePaths) != 2 {
			t.Fatal("historical input keys missing")
		}
	})
	t.Run("historical_config_projection", func(t *testing.T) {
		p := aDownloadMFAPinnedFixture(t, input)
		old := aAdmissionHistoricalConfig(t, p.db.config)
		found := false
		for _, pin := range old.References() {
			if pin.Purpose == "nonce_hmac" {
				found = pin.Version == "v1" && pin.IdentityHash == hash([]byte("old-nonce-identity"))
			}
		}
		if !found || old.SHA256() == p.db.config.SHA256() {
			t.Fatal("old key config did not change canonical/projected identity")
		}
	})
	t.Run("independent_encrypted_object", func(t *testing.T) {
		p, plain, object, keys := fixture(t, 8193)
		store := &testStore{data: object, present: true, info: ObjectInfo{Version: "v1", SHA256: hash(object), Size: int64(len(object))}}
		got, err := OpenRange(context.Background(), p.Manifest(), Ref{Identity: strings.Repeat("a", 64), Version: "v1", RelativeKey: "evidence/test", ImmutableVersion: "v1"}, store, keys, 0, 8192)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("encrypted fixture cannot be opened", err)
		}
		wipe(got)
	})
}

func aAdmissionHistoricalConfig(t *testing.T, current sec.ConfigValues) sec.ConfigValues {
	t.Helper()
	var doc map[string]any
	d := json.NewDecoder(bytes.NewReader(current.CanonicalJSON()))
	d.UseNumber()
	mustSQL(t, d.Decode(&doc))
	for _, value := range doc["references"].([]any) {
		pin := value.(map[string]any)
		if pin["purpose"] == "nonce_hmac" {
			pin["version"], pin["identity_hash"] = "v1", hash([]byte("old-nonce-identity"))
		}
	}
	old, _ := admissionConfigDocument(t, doc)
	return old
}

func newAAdmissionMySQLFixture(t *testing.T, input aDownloadMFAInputs) *aAdmissionMySQLFixture {
	t.Helper()
	f := newADownloadMFAFixture(t, input)
	x := &aAdmissionMySQLFixture{aDownloadMFAFixture: f}
	// Keep an actual old v1 config and current v2 config so L0/L1 history and
	// every historical HMAC candidate are exercised by all admission cases.
	values := aDownloadMFAConfigCells(f.admissionPinnedFixture)
	values["version"] = 2
	rows, err := f.db.QueryContext(f.ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' ORDER BY ORDINAL_POSITION")
	mustSQL(t, err)
	var columns []string
	var args []any
	for rows.Next() {
		var column string
		mustSQL(t, rows.Scan(&column))
		if value, ok := values[column]; ok {
			columns = append(columns, column)
			args = append(args, value)
		}
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	_, err = f.db.ExecContext(f.ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	mustSQL(t, err)
	oldIdentity := hash([]byte("old-nonce-identity"))
	oldConfig := aAdmissionHistoricalConfig(t, f.admissionPinnedFixture.db.config)
	_, err = f.db.ExecContext(f.ctx, "UPDATE system_backup_v2_configs SET nonce_hmac_ref_version='v1',nonce_hmac_identity_hash=?,canonical_config_json=?,config_sha256=?,config_size_bytes=? WHERE origin_installation_id=? AND version=1", oldIdentity, oldConfig.CanonicalJSON(), oldConfig.SHA256(), len(oldConfig.CanonicalJSON()), f.svc.InstallationID)
	mustSQL(t, err)
	_, err = f.db.ExecContext(f.ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=2 WHERE origin_installation_id=?", f.svc.InstallationID)
	mustSQL(t, err)
	// Replace the independent vector's metadata with an actually encrypted
	// object, before requesting a fresh proof for this exact SQL Manifest.
	prepared, plain, object, keys := fixture(t, 8193)
	m := prepared.Manifest()
	r := f.initial
	if m.Identity.ID != r.Manifest.Identity.ID || m.Identity.Installation != r.Manifest.Identity.Installation || m.Identity.OwnerID != r.Manifest.Identity.OwnerID {
		t.Fatal("encrypted object identity mismatch")
	}
	r.Manifest = m
	r.Ref.Identity = f.admissionPinnedFixture.db.configCells["evidence_store_identity_hash"].(string)
	r.Ref.Version = f.admissionPinnedFixture.db.configCells["evidence_store_ref_version"].(string)
	r.Ref.RelativeKey, err = keyFor("evidence", m.Identity)
	mustSQL(t, err)
	_, err = f.db.ExecContext(f.ctx, `UPDATE system_backup_v2_evidence SET storage_identity_hash=?,storage_ref_version=?,storage_relative_key=?,storage_relative_key_hash=?,content_checksum=?,content_size_bytes=?,object_checksum=?,object_size_bytes=?,chunk_count=?,chunk_list_root=?,kek_identity_hash=?,kek_version=?,envelope_hash=? WHERE public_id=?`, r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), m.Identity.ContentHash, m.Identity.ContentSize, m.ObjectHash, m.ObjectSize, len(m.Chunks), m.ChunkRoot, m.Key.Identity, m.Key.Version, m.EnvelopeHash, m.Identity.ID)
	mustSQL(t, err)
	var evidenceID int64
	mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=?", m.Identity.ID).Scan(&evidenceID))
	_, err = f.db.ExecContext(f.ctx, "DELETE FROM system_backup_v2_evidence_chunks WHERE evidence_id=?", evidenceID)
	mustSQL(t, err)
	for _, chunk := range m.Chunks {
		nonce, err := base64.RawURLEncoding.DecodeString(chunk.Nonce)
		mustSQL(t, err)
		tag, err := base64.RawURLEncoding.DecodeString(chunk.Tag)
		mustSQL(t, err)
		_, err = f.db.ExecContext(f.ctx, "INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) VALUES(?,?,?,?,?,?,?,?,?,?)", evidenceID, chunk.Index, chunk.PlainOffset, chunk.PlainLength, chunk.PlainHash, chunk.FrameOffset, chunk.FrameLength, chunk.CipherHash, nonce, tag)
		mustSQL(t, err)
	}
	f.initial = r
	x.plain, x.object, x.keys = plain, object, keys
	x.registry = SQLRegistry{DB: f.db, Installation: f.svc.InstallationID, ServerUUID: f.identity.ServerUUID, Database: f.identity.Database}
	x.owners = &aAdmissionMySQLOwners{f: f, registry: x.registry}
	x.registry.Policy = aAdmissionMySQLPolicy{x.owners}
	x.owners.registry = x.registry
	f.report.ServerUUID, f.report.Database = f.identity.ServerUUID, f.identity.Database
	x.refreshReport(t)
	capacity, err := sec.NewConfigMutationCapacity(f.identity, f.reportPath, 1)
	mustSQL(t, err)
	c := f.environment.config
	c.Owners, c.Capacity = x.owners, capacity
	f.environment, err = NewPinnedDownloadAdmissionEnvironment(c)
	mustSQL(t, err)
	f.targets, err = NewPinnedSensitiveDownloadProofTargets(x.registry, f.environment)
	mustSQL(t, err)
	x.admission, err = NewDownloadAdmissionService(x.registry, f.secret, f.environment)
	mustSQL(t, err)
	x.results, err = NewSQLDownloadResults(SQLDownloadResultsConfig{Registry: x.registry, Owners: x.owners, Capacity: capacity, MeasuredReservationBytes: 8192})
	mustSQL(t, err)
	now := aDownloadMFANow(t, f.ctx, f.db)
	tokenPath := filepath.Join(t.TempDir(), "synthetic-admission-provider-token")
	x.authority, err = NewSQLDownloadAuthority(DownloadAuthorityConfig{Registry: x.registry, JWTSecret: f.secret, ConfigVersion: 2, ConfigSHA256: f.admissionPinnedFixture.db.config.SHA256(), RBACVersion: "v1", RBACSHA256: f.env.rbacHash, RegistryDirectory: c.RegistryDirectory, Root: "evidence", Store: KeyRef{r.Ref.Identity, r.Ref.Version}, Read: KeyRef{f.admissionPinnedFixture.db.configCells["evidence_read_identity_hash"].(string), f.admissionPinnedFixture.db.configCells["evidence_read_ref_version"].(string)}, Issuer: "https://issuer.local", Audience: "download-provider", Subject: "system:download", TokenFile: tokenPath, ExpiresAt: now.Add(2 * time.Minute)})
	mustSQL(t, err)
	writeCommittedProviderToken(t, x.authority)
	x.store = &committedScopedReadStore{authority: x.authority, testStore: &testStore{data: object, present: true, info: ObjectInfo{Version: r.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}}
	step := now.Unix() / 30
	if step <= f.step {
		step = f.step + 1
	}
	status, proof := f.http(aDownloadMFACode(f.seed, step))
	if status != 200 {
		t.Fatal("actual fresh MFA issuance failed", status)
	}
	x.proof = proof
	x.setProof(t, proof)
	x.refreshReport(t)
	return x
}
func (x *aAdmissionMySQLFixture) refreshReport(t *testing.T) {
	t.Helper()
	x.report.ObservedAt = aDownloadMFANow(t, x.ctx, x.aDownloadMFAFixture.db)
	x.writeReport(t)
}
func (x *aAdmissionMySQLFixture) setProof(t *testing.T, p sec.Proof) {
	t.Helper()
	raw, err := json.Marshal(p)
	mustSQL(t, err)
	x.request.Header.Set(sec.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
}
func (x *aAdmissionMySQLFixture) requireRows(t *testing.T, admitted, results int, released bool) {
	t.Helper()
	for table, want := range map[string]int{"system_backup_v2_operations": admitted, "system_backup_v2_download_admission_receipts": admitted, "system_backup_v2_download_result_receipts": results, "system_backup_v2_strong_auth_nonces": admitted, "system_backup_v2_metadata_reservations": admitted} {
		var got int
		mustSQL(t, x.aDownloadMFAFixture.db.QueryRowContext(x.ctx, "SELECT COUNT(*) FROM "+table).Scan(&got))
		if got != want {
			t.Fatal("actual atomic row count", table, got, want)
		}
	}
	for action, want := range map[string]int{"system_backup.evidence_download.intent": admitted, "system_backup.evidence_download.result": results} {
		var got int
		mustSQL(t, x.aDownloadMFAFixture.db.QueryRowContext(x.ctx, "SELECT COUNT(*) FROM audit_logs WHERE action=?", action).Scan(&got))
		if got != want {
			t.Fatal("actual audit count", action, got, want)
		}
	}
	var claim sql.NullString
	var until sql.NullTime
	var version int64
	mustSQL(t, x.aDownloadMFAFixture.db.QueryRowContext(x.ctx, "SELECT claim_owner,claim_expires_at,row_version FROM system_backup_v2_evidence WHERE public_id=?", x.initial.Manifest.Identity.ID).Scan(&claim, &until, &version))
	wantVersion := x.initial.RowVersion + int64(admitted)
	if released {
		wantVersion++
	}
	if version != wantVersion || claim.Valid != (admitted > 0 && !released) || until.Valid != claim.Valid {
		t.Fatal("actual claim/release/version", version, wantVersion, claim.Valid, until.Valid)
	}
	if admitted > 0 {
		var reserved int64
		mustSQL(t, x.aDownloadMFAFixture.db.QueryRowContext(x.ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&reserved))
		if reserved != 65536+int64(results)*8192 {
			t.Fatal("actual reservation accounting", reserved)
		}
	}
}
func (x *aAdmissionMySQLFixture) admitted(t *testing.T) *CommittedDownloadAdmission {
	t.Helper()
	c, err := x.admission.Admit(x.request)
	if err != nil || c == nil {
		t.Fatal("actual admission", err)
	}
	x.requireRows(t, 1, 0, false)
	return c
}
func (x *aAdmissionMySQLFixture) result(t *testing.T, c *CommittedDownloadAdmission) {
	t.Helper()
	if err := x.results.Finish(x.ctx, c, DownloadResultObservation{Outcome: "interrupted"}); err != nil {
		t.Fatal("actual result", err)
	}
	x.requireRows(t, 1, 1, true)
}

func TestADownloadAdmissionMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("actual admission capsule pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, name := range []string{"http_admit_provider_result", "concurrent_key_once", "retained_hmac_replay", "final_owner_rollback", "final_manifest_rollback", "final_nonce_rollback", "intent_insert_rollback", "unknown_actual_commit", "late_actual_commit", "observed_L0_wait_original_expiry", "result_after_revocation", "result_insert_rollback", "result_unknown_actual_commit"} {
		t.Run(name, func(t *testing.T) {
			x := newAAdmissionMySQLFixture(t, input)
			db := x.aDownloadMFAFixture.db
			switch name {
			case "http_admit_provider_result":
				failures := 0
				service := Service{Registry: x.registry, Store: x.store, Keys: DownloadKeys{Authority: x.authority, Keys: x.keys}, Failure: func(context.Context, string, string) { failures++ }}
				h, err := newAdmittedDownloadHandler(x.admission, x.authority, x.results, service, Handler{Auth: x.authority, Service: service})
				mustSQL(t, err)
				w := admittedWriter()
				h.ServeHTTP(w, x.request)
				var operation string
				mustSQL(t, db.QueryRowContext(x.ctx, "SELECT public_id FROM system_backup_v2_operations").Scan(&operation))
				if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), x.plain) || w.Header().Get("X-System-Backup-Operation-Id") != operation || len(x.store.scopes) != 3 || failures != 0 {
					t.Fatal("actual SQL/HTTP/provider/result chain", w.Code, len(x.store.scopes), failures)
				}
				x.requireRows(t, 1, 1, true)
			case "concurrent_key_once":
				type outcome struct {
					c   *CommittedDownloadAdmission
					err error
				}
				out := make(chan outcome, 2)
				for i := 0; i < 2; i++ {
					go func() { c, err := x.admission.Admit(x.request.Clone(x.ctx)); out <- outcome{c, err} }()
				}
				one, two := <-out, <-out
				if one.err != nil {
					one, two = two, one
				}
				if one.c == nil || one.err != nil || two.c != nil || !errors.Is(two.err, ErrDownloadAdmissionKeyConflict) {
					t.Fatal("actual concurrent admission", one.err, two.err)
				}
				x.requireRows(t, 1, 0, false)
				x.result(t, one.c)
			case "retained_hmac_replay":
				_, err := db.ExecContext(x.ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=1 WHERE origin_installation_id=?", x.registry.Installation)
				mustSQL(t, err)
				x.admitted(t)
				var version string
				mustSQL(t, db.QueryRowContext(x.ctx, "SELECT nonce_hmac_key_version FROM system_backup_v2_strong_auth_nonces").Scan(&version))
				if version != "v1" {
					t.Fatal("first actual historical consumption did not use v1")
				}
				_, err = db.ExecContext(x.ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=2 WHERE origin_installation_id=?", x.registry.Installation)
				mustSQL(t, err)
				key := "new-key-same-actual-nonce"
				x.request.Header.Set("Idempotency-Key", key)
				bound, err := BindSensitiveDownloadRequest(x.env.actor, x.initial.Manifest, x.request.Header)
				mustSQL(t, err)
				binding, err := bound.ProofBinding("issuer-transaction")
				mustSQL(t, err)
				p := x.proof
				p.Payload.RequestHash, p.Payload.IdempotencyKey = binding.RequestHash, binding.IdempotencyKey
				payload, err := sec.CanonicalPayload(p.Payload)
				mustSQL(t, err)
				p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(x.signer.key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
				x.setProof(t, p)
				x.refreshReport(t)
				c, err := x.admission.Admit(x.request)
				var proof *sec.VerificationError
				if c != nil || !errors.As(err, &proof) || proof.Code != sec.FailureReplayed {
					t.Fatal("actual retained global HMAC replay escaped", err)
				}
				x.requireRows(t, 1, 0, false)
			case "final_owner_rollback", "final_manifest_rollback", "final_nonce_rollback":
				var once sync.Once
				var injected error
				x.owners.onRecheck = func(ctx context.Context, tx *sql.Tx) error {
					once.Do(func() {
						query := "UPDATE synthetic_download_mfa_owner SET visible=FALSE"
						if name == "final_manifest_rollback" {
							query = "UPDATE system_backup_v2_evidence SET content_checksum=REPEAT('c',64)"
						}
						if name == "final_nonce_rollback" {
							query = "UPDATE system_backup_v2_strong_auth_nonces SET session_sha256=REPEAT('c',64)"
						}
						result, err := tx.ExecContext(ctx, query)
						injected = err
						if err == nil {
							n, e := result.RowsAffected()
							injected = e
							if n != 1 {
								injected = errors.New("injection did not affect original row")
							}
						}
					})
					return injected
				}
				c, err := x.admission.Admit(x.request)
				if c != nil || err == nil || injected != nil || x.owners.checks.Load() == 0 {
					t.Fatal("actual late mutation accepted or did not execute", err, injected)
				}
				x.requireRows(t, 0, 0, false)
				var visible bool
				var checksum string
				mustSQL(t, db.QueryRowContext(x.ctx, "SELECT visible FROM synthetic_download_mfa_owner").Scan(&visible))
				mustSQL(t, db.QueryRowContext(x.ctx, "SELECT content_checksum FROM system_backup_v2_evidence").Scan(&checksum))
				if !visible || checksum != x.initial.Manifest.Identity.ContentHash {
					t.Fatal("actual injected write survived rollback")
				}
				x.owners.onRecheck = nil
				x.refreshReport(t)
				x.result(t, x.admitted(t))
			case "intent_insert_rollback", "result_insert_rollback":
				var c *CommittedDownloadAdmission
				action := "system_backup.evidence_download.intent"
				if name == "result_insert_rollback" {
					c = x.admitted(t)
					action = "system_backup.evidence_download.result"
				}
				_, err := db.ExecContext(x.ctx, fmt.Sprintf("CREATE TRIGGER synthetic_admission_audit_reject BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='%s' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit rejection'; END IF; END", action))
				mustSQL(t, err)
				if c == nil {
					c, err = x.admission.Admit(x.request)
					if c != nil || err == nil {
						t.Fatal("actual failed intent accepted")
					}
					x.requireRows(t, 0, 0, false)
				} else {
					if x.results.Finish(x.ctx, c, DownloadResultObservation{Outcome: "rejected"}) == nil {
						t.Fatal("actual failed result accepted")
					}
					x.requireRows(t, 1, 0, false)
					if x.results.Finish(x.ctx, c, DownloadResultObservation{Outcome: "rejected"}) == nil {
						t.Fatal("failed result was reusable")
					}
				}
			case "unknown_actual_commit", "late_actual_commit", "result_unknown_actual_commit":
				connector, err := mysql.NewConnector(x.cfg)
				mustSQL(t, err)
				tap := &aMFACommitConnector{Connector: connector, clock: db}
				wrapped := sql.OpenDB(tap)
				defer wrapped.Close()
				registry := x.registry
				registry.DB = wrapped
				if name == "result_unknown_actual_commit" {
					s, err := NewDownloadAdmissionService(registry, x.secret, x.environment)
					mustSQL(t, err)
					c, err := s.Admit(x.request)
					mustSQL(t, err)
					if c == nil {
						t.Fatal("actual admission before unknown result returned no authority")
					}
					x.requireRows(t, 1, 0, false)
					r, err := NewSQLDownloadResults(SQLDownloadResultsConfig{Registry: registry, Owners: x.owners, Capacity: x.environment.config.Capacity, MeasuredReservationBytes: 8192})
					mustSQL(t, err)
					tap.lost.Store(true)
					if r.Finish(x.ctx, c, DownloadResultObservation{Outcome: "interrupted"}) != ErrDownloadResultCommitUnknown {
						t.Fatal("actual lost result acknowledgement not terminal")
					}
					x.requireRows(t, 1, 1, true)
					if r.Finish(x.ctx, c, DownloadResultObservation{Outcome: "interrupted"}) == nil {
						t.Fatal("actual unknown result retried")
					}
					break
				}
				if name == "late_actual_commit" {
					c := x.environment.config
					c.MaterialsUntil = aDownloadMFANow(t, x.ctx, db).Add(2 * time.Second)
					env, err := NewPinnedDownloadAdmissionEnvironment(c)
					mustSQL(t, err)
					x.environment = env
					tap.until = c.MaterialsUntil
					tap.delay.Store(true)
				} else {
					tap.lost.Store(true)
				}
				s, err := NewDownloadAdmissionService(registry, x.secret, x.environment)
				mustSQL(t, err)
				c, err := s.Admit(x.request)
				want := ErrDownloadAdmissionCommitUnknown
				if name == "late_actual_commit" {
					want = ErrDownloadAdmissionCommittedExpired
				}
				if c != nil || !errors.Is(err, want) || len(x.store.scopes) != 0 {
					t.Fatal("actual unknown/late admission released authority", err)
				}
				x.requireRows(t, 1, 0, false)
			case "observed_L0_wait_original_expiry":
				config := x.environment.config
				config.MaterialsUntil = aDownloadMFANow(t, x.ctx, db).Add(2 * time.Second)
				env, err := NewPinnedDownloadAdmissionEnvironment(config)
				mustSQL(t, err)
				s, err := NewDownloadAdmissionService(x.registry, x.secret, env)
				mustSQL(t, err)
				hold, err := db.BeginTx(x.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				mustSQL(t, err)
				defer hold.Rollback()
				rows, err := hold.QueryContext(x.ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
				mustSQL(t, err)
				for rows.Next() {
					var id string
					mustSQL(t, rows.Scan(&id))
				}
				mustSQL(t, rows.Err())
				mustSQL(t, rows.Close())
				done := make(chan error, 1)
				go func() {
					c, err := s.Admit(x.request.Clone(x.ctx))
					if c != nil {
						done <- errors.New("waiter emitted authority")
						return
					}
					done <- err
				}()
				observed := false
				limit := time.Now().Add(time.Second)
				for time.Now().Before(limit) {
					var count int
					mustSQL(t, db.QueryRowContext(x.ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_installation_state'`, x.identity.Database).Scan(&count))
					if count > 0 {
						observed = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !observed {
					hold.Rollback()
					<-done
					t.Fatal("actual installation lock wait not observed")
				}
				mustSQL(t, aMFAWaitSQL(x.ctx, db, config.MaterialsUntil))
				mustSQL(t, hold.Rollback())
				if err := <-done; err == nil {
					t.Fatal("actual waited original expiry admitted")
				}
				x.requireRows(t, 0, 0, false)
				t.Log("OBSERVED actual admission L0 wait and original material expiry")
			case "result_after_revocation":
				c := x.admitted(t)
				ctx, cancel, err := x.authority.BindCommittedDownload(x.ctx, c)
				mustSQL(t, err)
				defer cancel()
				mustSQL(t, x.authority.CheckCommittedDownload(ctx, c))
				_, err = db.ExecContext(x.ctx, "UPDATE users SET is_active=FALSE WHERE id=42")
				mustSQL(t, err)
				_, err = db.ExecContext(x.ctx, "UPDATE synthetic_download_mfa_owner SET visible=FALSE")
				mustSQL(t, err)
				if x.authority.CheckCommittedDownload(ctx, c) == nil || len(x.store.scopes) != 0 {
					t.Fatal("actual revoked authority escaped")
				}
				x.result(t, c)
			}
		})
	}
}
