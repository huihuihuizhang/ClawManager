//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

//go:embed testdata/download_mfa_probe_inputs.json
var aDownloadMFASeed []byte

type aDownloadMFAInputs struct {
	Kind            string          `json:"kind"`
	Catalog         string          `json:"catalog_sha256"`
	Files           []string        `json:"migration_files"`
	CanonicalDDL    string          `json:"canonical_ddl"`
	CanonicalSHA    string          `json:"canonical_sha256"`
	OwnershipDDL    string          `json:"ownership_ddl"`
	OwnershipSHA    string          `json:"ownership_sha256"`
	ConfigSchema    string          `json:"config_schema_ddl"`
	EffectiveConfig json.RawMessage `json:"effective_config"`
}

func decodeADownloadMFAInputs(raw []byte) (aDownloadMFAInputs, error) {
	var out aDownloadMFAInputs
	if len(raw) > 65536 {
		return out, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, ErrInvalid
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"kind": true, "catalog_sha256": true, "migration_files": true, "canonical_ddl": true, "canonical_sha256": true, "ownership_ddl": true, "ownership_sha256": true, "config_schema_ddl": true, "effective_config": true}
	for d.More() {
		k, e := d.Token()
		if e != nil {
			return out, ErrInvalid
		}
		name, ok := k.(string)
		if !ok || seen[name] || !allowed[name] {
			return out, ErrInvalid
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return out, ErrInvalid
		}
	}
	if _, err = d.Token(); err != nil {
		return out, ErrInvalid
	}
	var extra any
	if len(seen) != 9 || d.Decode(&extra) != io.EOF || json.Unmarshal(raw, &out) != nil || out.Kind != "a_download_mfa_probe_inputs.v1" || out.Catalog != "0a2fc9ee709ffe6935679ed0923414f0607b2d34bf55ba615e7f431f8411bffe" || len(out.Files) != 96 || out.CanonicalSHA != "14db3b88263f0ab3e31e293aa0351bb08da23464d4a0fee8854263d56354cce1" || hash([]byte(out.CanonicalDDL)) != out.CanonicalSHA || out.OwnershipSHA != "dc0687839ce07646688b7a53d3c7ddda20ea5b269999d499a0730e2d2e0f50a9" || hash([]byte(out.OwnershipDDL)) != out.OwnershipSHA || !strings.HasPrefix(out.ConfigSchema, "CREATE TABLE IF NOT EXISTS system_backup_v2_configs (") {
		return aDownloadMFAInputs{}, ErrInvalid
	}
	for i, name := range out.Files {
		if !regexp.MustCompile(`^[0-9]{3}_[A-Za-z0-9_]+\.sql$`).MatchString(name) || i > 0 && name <= out.Files[i-1] {
			return aDownloadMFAInputs{}, ErrInvalid
		}
	}
	if _, err := sec.DecodeConfigValues(out.EffectiveConfig); err != nil {
		return aDownloadMFAInputs{}, ErrInvalid
	}
	return out, nil
}
func TestASensitiveDownloadMFAMySQLSeed(t *testing.T) {
	input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("actual_config_required_cells", func(t *testing.T) {
		p := aDownloadMFAPinnedFixture(t, input)
		values := aDownloadMFAConfigCells(p)
		for _, line := range strings.Split(input.ConfigSchema, "\n") {
			if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name := fields[0]
			if strings.Contains(line, "NOT NULL") && !strings.Contains(line, "DEFAULT") && !strings.Contains(line, "AUTO_INCREMENT") && !strings.Contains(line, "CONSTRAINT") && !strings.Contains(line, "CHECK") {
				if _, ok := values[name]; !ok {
					t.Errorf("missing actual required config column %s", name)
				}
			}
		}
		if aDownloadMFACode([]byte("12345678901234567890"), 1) != "287082" {
			t.Fatal("independent RFC 6238 test code is wrong")
		}
	})
	for _, name := range []string{"duplicate", "unknown", "trailing", "catalog", "ddl", "budget"} {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Clone(aDownloadMFASeed)
			switch name {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"kind":`), []byte(`"kind":"duplicate","kind":`), 1)
			case "unknown":
				raw = append([]byte(`{"extra":1,`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "catalog":
				raw = bytes.Replace(raw, []byte("0a2fc9ee709ffe6935679ed0923414f0607b2d34bf55ba615e7f431f8411bffe"), []byte(strings.Repeat("0", 64)), 1)
			case "ddl":
				raw = bytes.Replace(raw, []byte("ALTER TABLE system_backup_v2_configs"), []byte("ALTER TABLE wrong_config_table"), 1)
			case "budget":
				raw = make([]byte, 65537)
			}
			if _, err := decodeADownloadMFAInputs(raw); err == nil {
				t.Fatal("invalid capsule accepted")
			}
		})
	}
	t.Log("PASS download MFA seed; real_mysql=not_run human_mfa=no production_approval=no")
}

// This clone contains schema only. FK checks are disabled ONLY while copying
// empty SHOW CREATE statements, then restored and verified before any fixture
// row or test operation. All actual test SQL retains InnoDB CHECKs/FKs.
func aDownloadMFADatabase(t *testing.T, input aDownloadMFAInputs) (context.Context, *sql.DB, *mysql.Config, sec.DatabaseIdentity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	parent := downloadAuditProbeDatabase(t, ctx)
	var mysqlVersion, sqlMode string
	var globalFK int
	mustSQL(t, parent.QueryRowContext(ctx, "SELECT VERSION(),@@session.sql_mode,@@global.foreign_key_checks").Scan(&mysqlVersion, &sqlMode, &globalFK))
	if !strings.HasPrefix(mysqlVersion, "8.") || globalFK != 1 || (!strings.Contains(sqlMode, "STRICT_TRANS_TABLES") && !strings.Contains(sqlMode, "STRICT_ALL_TABLES")) {
		t.Fatal("MFA requires MySQL 8 strict mode and globally enabled FK checks")
	}
	rows, err := parent.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	mustSQL(t, err)
	var names []string
	for rows.Next() {
		var name string
		mustSQL(t, rows.Scan(&name))
		names = append(names, name)
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	if !reflect.DeepEqual(names, input.Files) {
		t.Fatal("MFA requires exact fresh full catalog")
	}
	var uuid string
	mustSQL(t, parent.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid))
	var entropy [16]byte
	_, err = rand.Read(entropy[:])
	mustSQL(t, err)
	name := "amfa_" + hex.EncodeToString(entropy[:])
	_, err = parent.ExecContext(ctx, "CREATE DATABASE "+name)
	mustSQL(t, err)
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var current string
		if parent.QueryRowContext(c, "SELECT @@server_uuid").Scan(&current) != nil || current != uuid {
			t.Error("CLEANUP_PENDING download MFA database identity")
			return
		}
		if _, e := parent.ExecContext(c, "DROP DATABASE "+name); e != nil {
			t.Error("CLEANUP_PENDING download MFA database")
			return
		}
		var count int
		if parent.QueryRowContext(c, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING download MFA database absence")
			return
		}
		t.Log("CLEANED download MFA owned database", name)
	})
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	cfg.Addr = host + ":3306"
	cfg.DBName = name
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = true
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "10"}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, err)
	db.SetMaxOpenConns(12)
	t.Cleanup(func() { db.Close() })
	clone, err := db.Conn(ctx)
	mustSQL(t, err)
	defer clone.Close()
	_, err = clone.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
	mustSQL(t, err)
	rows, err = parent.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
	mustSQL(t, err)
	var tables []string
	for rows.Next() {
		var table string
		mustSQL(t, rows.Scan(&table))
		if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(table) {
			t.Fatal("unsafe catalog table")
		}
		tables = append(tables, table)
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	for _, table := range tables {
		var got, ddl string
		mustSQL(t, parent.QueryRowContext(ctx, "SHOW CREATE TABLE `"+table+"`").Scan(&got, &ddl))
		if got != table {
			t.Fatal("schema clone identity")
		}
		_, err = clone.ExecContext(ctx, ddl)
		mustSQL(t, err)
	}
	_, err = clone.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
	mustSQL(t, err)
	var fk int
	mustSQL(t, clone.QueryRowContext(ctx, "SELECT @@session.foreign_key_checks").Scan(&fk))
	if fk != 1 {
		t.Fatal("FK checks not restored")
	}
	_, err = db.ExecContext(ctx, input.CanonicalDDL)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, input.OwnershipDDL)
	mustSQL(t, err)
	for _, table := range []string{"users", "audit_logs", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_admin_sessions", "system_backup_v2_admin_revocations", "system_backup_v2_totp_credentials", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_strong_auth_nonces"} {
		var engine string
		mustSQL(t, db.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&engine))
		if engine != "InnoDB" {
			t.Fatal("MFA requires actual InnoDB")
		}
	}
	return ctx, db, cfg, sec.DatabaseIdentity{ServerUUID: uuid, Database: name}
}

type aDownloadMFAOwners struct {
	registry SQLRegistry
	actor    sec.RegistrationActor
	tx       *sql.Tx
	calls    int
}

func (o *aDownloadMFAOwners) Preview(ctx context.Context, tx *sql.Tx, installation string, actor sec.RegistrationActor, id string) (Record, error) {
	if actor.UserID != o.actor.UserID || actor.Subject != o.actor.Subject || actor.Session != o.actor.Session || installation != o.registry.Installation {
		return Record{}, ErrDenied
	}
	o.tx = tx
	o.calls++
	return o.registry.PreviewDownloadEvidence(ctx, tx, id, func(ctx context.Context, borrowed *sql.Tx, i Identity) (time.Time, error) {
		var deadline time.Time
		var visible bool
		var storedInstallation, kind string
		err := borrowed.QueryRowContext(ctx, "SELECT installation,owner_type,deadline,visible FROM synthetic_download_mfa_owner WHERE owner_id=?", i.OwnerID).Scan(&storedInstallation, &kind, &deadline, &visible)
		if err != nil || !visible || storedInstallation != installation || kind != i.OwnerType {
			return time.Time{}, ErrDenied
		}
		return deadline, nil
	})
}
func (*aDownloadMFAOwners) LockOwnerReferences(context.Context, *sql.Tx, Record) error {
	return errors.New("MFA must not acquire L4")
}
func (*aDownloadMFAOwners) Recheck(context.Context, *sql.Tx, sec.RegistrationActor, Record) error {
	return errors.New("MFA must use current preview, not a fake L4 guard")
}

type aDownloadMFASigner struct {
	key    ed25519.PrivateKey
	before func(context.Context) error
}

func (s *aDownloadMFASigner) Sign(ctx context.Context, raw []byte) ([]byte, error) {
	if s.before != nil {
		if err := s.before(ctx); err != nil {
			return nil, err
		}
	}
	return ed25519.Sign(s.key, raw), nil
}

type aDownloadMFAFixture struct {
	*admissionPinnedFixture
	ctx      context.Context
	db       *sql.DB
	cfg      *mysql.Config
	identity sec.DatabaseIdentity
	svc      sec.SQLTOTPService
	targets  *PinnedSensitiveDownloadProofTargets
	owners   *aDownloadMFAOwners
	signer   *aDownloadMFASigner
	seed     []byte
	password string
	step     int64
	audits   int
	lost     *atomic.Bool
}

func aDownloadMFANow(t *testing.T, ctx context.Context, db *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	return now
}
func aDownloadMFACode(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, seed)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func aDownloadMFAPinnedFixture(t *testing.T, input aDownloadMFAInputs) *admissionPinnedFixture {
	t.Helper()
	return newAdmissionPinnedFixtureFromBase(t, newAdmissionTxFixtureWithConfig(t, func(t *testing.T, rbac string) (sec.ConfigValues, map[string]driver.Value) {
		return admissionConfigBytes(t, input.EffectiveConfig, rbac)
	}))
}

func aDownloadMFAConfigCells(p *admissionPinnedFixture) map[string]any {
	values := map[string]any{}
	for key, value := range p.db.configCells {
		values[key] = value
	}
	values["schema_version"] = "system-backup-config.v1"
	values["origin_installation_id"] = p.initial.Manifest.Identity.Installation
	values["version"] = 1
	values["config_sha256"] = p.db.config.SHA256()
	values["config_size_bytes"] = len(p.db.config.CanonicalJSON())
	values["canonical_config_json"] = p.db.config.CanonicalJSON()
	values["created_by"] = "42"
	values["change_reason"] = "synthetic new MFA fixture, not historical backfill"
	return values
}

func newADownloadMFAFixture(t *testing.T, input aDownloadMFAInputs) *aDownloadMFAFixture {
	t.Helper()
	ctx, db, cfg, identity := aDownloadMFADatabase(t, input)
	p := aDownloadMFAPinnedFixture(t, input)
	f := &aDownloadMFAFixture{admissionPinnedFixture: p, ctx: ctx, db: db, cfg: cfg, identity: identity, password: "synthetic-download-mfa-password", lost: &atomic.Bool{}}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(f.password), bcrypt.MinCost)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'synthetic-download-mfa','download-mfa@example.invalid',?,'admin',TRUE)", string(passwordHash))
	mustSQL(t, err)
	values := aDownloadMFAConfigCells(p)
	rows, err := db.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' ORDER BY ORDINAL_POSITION")
	mustSQL(t, err)
	var columns []string
	var args []any
	for rows.Next() {
		var name string
		mustSQL(t, rows.Scan(&name))
		if value, ok := values[name]; ok {
			columns = append(columns, name)
			args = append(args, value)
		}
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	mustSQL(t, err)
	now := aDownloadMFANow(t, ctx, db)
	_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key) VALUES (?,1,?,'k8s-cluster')", p.initial.Manifest.Identity.Installation, now)
	mustSQL(t, err)
	r := p.initial
	m := r.Manifest
	i := m.Identity
	result, err := db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,origin_installation_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,content_checksum,content_size_bytes,object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_count,chunk_list_root,media_type,encryption,envelope_framing_version,kek_identity_hash,kek_version,envelope_hash,redaction_classification,observed_health,expires_at,protected_until,row_version,created_at) VALUES(?,?,?,?,?,'ready','none','evidence',?,?,?,?,?,?,?,?,?,?,?,?,?,'envelope_v1',?,?,?,?,?,'unknown',?,?,?,?)`, i.ID, i.Installation, i.OwnerType, i.OwnerID, i.Type, r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), r.Ref.ImmutableVersion, i.ContentHash, i.ContentSize, m.ObjectHash, m.ObjectSize, ChunkSize, len(m.Chunks), m.ChunkRoot, i.Media, Framing, m.Key.Identity, m.Key.Version, m.EnvelopeHash, i.Classification, r.ExpiresAt, r.ProtectedUntil, r.RowVersion, r.CreatedAt)
	mustSQL(t, err)
	evidenceID, err := result.LastInsertId()
	mustSQL(t, err)
	for _, chunk := range m.Chunks {
		nonce, e := base64.RawURLEncoding.DecodeString(chunk.Nonce)
		mustSQL(t, e)
		tag, e := base64.RawURLEncoding.DecodeString(chunk.Tag)
		mustSQL(t, e)
		_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) VALUES(?,?,?,?,?,?,?,?,?,?)", evidenceID, chunk.Index, chunk.PlainOffset, chunk.PlainLength, chunk.PlainHash, chunk.FrameOffset, chunk.FrameLength, chunk.CipherHash, nonce, tag)
		mustSQL(t, err)
	}
	_, err = db.ExecContext(ctx, "CREATE TABLE synthetic_download_mfa_owner(owner_id VARCHAR(128) PRIMARY KEY,installation VARCHAR(128) NOT NULL,owner_type VARCHAR(32) NOT NULL,deadline DATETIME(6) NOT NULL,visible BOOLEAN NOT NULL) ENGINE=InnoDB")
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO synthetic_download_mfa_owner VALUES(?,?,?,?,TRUE)", i.OwnerID, i.Installation, i.OwnerType, r.OwnerDeadline)
	mustSQL(t, err)
	sessions, err := sec.NewSQLLoginSessions(db, identity, i.Installation, p.secret)
	mustSQL(t, err)
	refresh, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "refresh", "jti": "synthetic-download-mfa-refresh", "iat": p.env.actor.SessionIssuedAt.Unix(), "exp": p.env.actor.SessionExpiresAt.Add(time.Hour).Unix()}).SignedString(p.secret)
	mustSQL(t, err)
	access := strings.TrimPrefix(p.request.Header.Get("Authorization"), "Bearer ")
	mustSQL(t, sessions.RecordPair(ctx, sec.LoginSessionPair{UserID: 42, CredentialSHA256: hash(passwordHash), AccessToken: access, RefreshToken: refresh}))
	box, err := sec.NewTOTPSecretBox(bytes.Repeat([]byte{0x61}, 32))
	mustSQL(t, err)
	f.signer = &aDownloadMFASigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))}
	f.svc = sec.SQLTOTPService{DB: db, DatabaseIdentity: &f.identity, InstallationID: i.Installation, Box: box, Issuer: sec.StrongAuthProofIssuer{Key: sec.StrongAuthRegistryKey{Issuer: "issuer-transaction", KeyID: "admission-key", KeyVersion: "v1", Purpose: "strong_auth_issuer", PublicKey: f.signer.key.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, Audience: i.Installation, Signer: f.signer, Lifetime: time.Minute}, Authorize: func(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor) error {
		if actor.Subject != p.env.actor.Subject || actor.Session != p.env.actor.Session {
			return sec.ErrRegistrationPermission
		}
		return p.environment.authorizeRBAC(actor, p.db.config, r)
	}}
	uri, err := f.svc.BeginEnrollment(ctx, p.env.actor, f.password)
	mustSQL(t, err)
	parsed, err := url.Parse(uri)
	mustSQL(t, err)
	f.seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	mustSQL(t, err)
	t.Cleanup(func() { wipe(f.seed) })
	stamp := aDownloadMFANow(t, ctx, db)
	_, err = f.svc.VerifyAndIssue(ctx, p.env.actor, f.password, aDownloadMFACode(f.seed, stamp.Unix()/30), nil)
	mustSQL(t, err)
	mustSQL(t, db.QueryRowContext(ctx, "SELECT last_step FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=42", i.Installation).Scan(&f.step))
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE user_id=42").Scan(&f.audits))
	materials, err := sec.NewConfigMutationSecurityFiles(i.Installation, identity, p.configuration.RegistryDirectory, filepath.Dir(filepath.Dir(p.noncePaths["v2"])))
	mustSQL(t, err)
	registry := SQLRegistry{DB: db, Installation: i.Installation, ServerUUID: identity.ServerUUID, Database: identity.Database}
	f.owners = &aDownloadMFAOwners{registry: registry, actor: p.env.actor}
	configuration := p.configuration
	configuration.Sessions = sessions
	configuration.Materials = materials
	configuration.Owners = f.owners
	configuration.MaterialsUntil = aDownloadMFANow(t, ctx, db).Add(2 * time.Minute)
	f.environment, err = NewPinnedDownloadAdmissionEnvironment(configuration)
	mustSQL(t, err)
	f.targets, err = NewPinnedSensitiveDownloadProofTargets(registry, f.environment)
	mustSQL(t, err)
	return f
}

func (f *aDownloadMFAFixture) http(code string) (int, sec.Proof) {
	body, _ := json.Marshal(map[string]any{"password": f.password, "code": code, "endpoint": sec.SensitiveDownloadEndpoint, "idempotency_key": f.request.Header.Get("Idempotency-Key"), "request": map[string]string{"evidence_id": f.initial.Manifest.Identity.ID}})
	r := httptest.NewRequest("POST", "https://probe.invalid/api/v1/admin/system-backup-strong-auth/proof", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", f.request.Header.Get("Authorization"))
	w := httptest.NewRecorder()
	(sec.RegistrationAPI{Registration: sec.ProviderRegistrationHTTP{Auth: sec.JWTRegistrationAuthenticator{Secret: f.secret}}, TOTP: f.svc, DownloadProofTargets: f.targets}).ServeHTTP(w, r)
	var proof sec.Proof
	if w.Code == 200 {
		var result struct {
			HeaderName  string `json:"header_name"`
			HeaderValue string `json:"header_value"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.HeaderName != sec.StrongAuthProofHeader {
			return 500, proof
		}
		decoded, err := sec.DecodeStrongAuthHeader(result.HeaderValue)
		if err != nil {
			return 500, proof
		}
		proof = decoded
	}
	return w.Code, proof
}
func (f *aDownloadMFAFixture) checkRows(t *testing.T, step int64, auditDelta int) {
	t.Helper()
	var gotStep int64
	mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT last_step FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=42", f.svc.InstallationID).Scan(&gotStep))
	var audits int
	mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM audit_logs WHERE user_id=42").Scan(&audits))
	if gotStep != step || audits != f.audits+auditDelta {
		t.Fatal("actual TOTP/audit transaction differs", gotStep, step, audits, f.audits+auditDelta)
	}
	for _, table := range []string{"system_backup_v2_strong_auth_nonces", "system_backup_v2_operations", "system_backup_v2_download_admission_receipts", "system_backup_v2_metadata_reservations"} {
		var count int
		mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&count))
		if count != 0 {
			t.Fatal("MFA performed download admission writes", table)
		}
	}
	var claim sql.NullString
	var version int64
	var checksum string
	mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT claim_owner,row_version,content_checksum FROM system_backup_v2_evidence WHERE public_id=?", f.initial.Manifest.Identity.ID).Scan(&claim, &version, &checksum))
	if claim.Valid || version != f.initial.RowVersion || checksum != f.initial.Manifest.Identity.ContentHash {
		t.Fatal("MFA changed immutable evidence/claim")
	}
	var visible bool
	mustSQL(t, f.db.QueryRowContext(f.ctx, "SELECT visible FROM synthetic_download_mfa_owner WHERE owner_id=?", f.initial.Manifest.Identity.OwnerID).Scan(&visible))
	if !visible {
		t.Fatal("rejected owner mutation was not rolled back")
	}
}
func (f *aDownloadMFAFixture) verify(t *testing.T, proof sec.Proof) {
	t.Helper()
	ctx := f.ctx
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer tx.Rollback()
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, f.identity, f.svc.InstallationID)
	mustSQL(t, err)
	config, err := scope.LoadConfig(ctx, tx)
	mustSQL(t, err)
	prepared, err := f.environment.Prepare(ctx, tx, f.env.actor, config, f.initial.Manifest.Identity.ID, scope.RequiredVersions())
	mustSQL(t, err)
	defer prepared.Close()
	r, err := BindSensitiveDownloadRequest(f.env.actor, prepared.Preview().Manifest, f.request.Header)
	mustSQL(t, err)
	cfg := prepared.ProofConfig()
	cfg.Now = aDownloadMFANow(t, ctx, f.db)
	if _, err = r.VerifyProof(proof, prepared.Issuer(), cfg); err != nil {
		t.Fatal("actual SQL Manifest/registry rejected issued proof", err)
	}
	if proof.Payload.AuthTime == "" || proof.Payload.Endpoint != sec.SensitiveDownloadEndpoint || proof.Payload.RequestHash != r.RequestHash() {
		t.Fatal("wrong actual signed binding")
	}
}

type aMFACommitConnector struct {
	driver.Connector
	lost, delay atomic.Bool
	clock       *sql.DB
	until       time.Time
}

func (c *aMFACommitConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aMFACommitConn{Conn: conn, tap: c}, nil
}

type aMFACommitConn struct {
	driver.Conn
	tap *aMFACommitConnector
}

func (c *aMFACommitConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return aMFACommitTx{Tx: tx, tap: c.tap}, nil
}
func (c *aMFACommitConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *aMFACommitConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *aMFACommitConn) CheckNamedValue(v *driver.NamedValue) error {
	return c.Conn.(driver.NamedValueChecker).CheckNamedValue(v)
}

type aMFACommitTx struct {
	driver.Tx
	tap *aMFACommitConnector
}

func (t aMFACommitTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if t.tap.lost.Swap(false) {
		return errors.New("synthetic lost actual COMMIT acknowledgement")
	}
	if t.tap.delay.Swap(false) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := aMFAWaitSQL(ctx, t.tap.clock, t.tap.until); err != nil {
			return err
		}
	}
	return nil
}
func aMFAWaitSQL(ctx context.Context, db *sql.DB, until time.Time) error {
	for {
		var now time.Time
		if err := db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
			return err
		}
		if !now.Before(until) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Full actual SQL issuance, not a person-MFA or production-owner acceptance.
// Candidate DDL and owner/issuer/material inputs are explicitly synthetic. No
// modeled SQL rows, affected counts or clock samples are substituted.
func TestASensitiveDownloadMFAMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("MFA capsule hash differs")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, name := range []string{"http_issue_step_replay", "concurrent_step_once", "final_owner_revocation_rollback", "final_manifest_change_rollback", "audit_failure_rollback", "unknown_actual_commit_no_proof", "late_actual_commit_no_proof", "original_material_expiry", "observed_L0_wait_original_expiry"} {
		if !t.Run(name, func(t *testing.T) {
			f := newADownloadMFAFixture(t, input)
			code := aDownloadMFACode(f.seed, f.step+1)
			switch name {
			case "http_issue_step_replay":
				status, proof := f.http(code)
				if status != 200 {
					t.Fatal("actual MFA issuance status", status)
				}
				f.verify(t, proof)
				f.checkRows(t, f.step+1, 1)
				status, proof = f.http(code)
				if status != 401 || proof.SchemaVersion != "" {
					t.Fatal("actual step replay returned proof", status)
				}
				f.checkRows(t, f.step+1, 2)
			case "concurrent_step_once":
				results := make(chan int, 2)
				for i := 0; i < 2; i++ {
					go func() { status, _ := f.http(code); results <- status }()
				}
				a, b := <-results, <-results
				if !(a == 200 && b == 401 || a == 401 && b == 200) {
					t.Fatal("concurrent step results", a, b)
				}
				f.checkRows(t, f.step+1, 2)
			case "final_owner_revocation_rollback", "final_manifest_change_rollback":
				hit := false
				f.signer.before = func(ctx context.Context) error {
					hit = true
					q := "UPDATE synthetic_download_mfa_owner SET visible=FALSE"
					if name == "final_manifest_change_rollback" {
						q = "UPDATE system_backup_v2_evidence SET content_checksum='" + strings.Repeat("c", 64) + "'"
					}
					r, e := f.owners.tx.ExecContext(ctx, q)
					if e != nil {
						return e
					}
					n, e := r.RowsAffected()
					if e != nil || n != 1 {
						return errors.New("fault did not update original SQL row")
					}
					return nil
				}
				status, proof := f.http(code)
				if !hit || status == 200 || proof.SchemaVersion != "" {
					t.Fatal("late current-source change issued proof", status)
				}
				f.checkRows(t, f.step, 0)
			case "audit_failure_rollback":
				_, err = f.db.ExecContext(f.ctx, `CREATE TRIGGER synthetic_mfa_audit_failure BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='system_backup.strong_auth.verified' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic audit failure'; END IF; END`)
				mustSQL(t, err)
				status, proof := f.http(code)
				if status == 200 || proof.SchemaVersion != "" {
					t.Fatal("actual audit failure released proof")
				}
				f.checkRows(t, f.step, 0)
			case "unknown_actual_commit_no_proof", "late_actual_commit_no_proof":
				base, e := mysql.NewConnector(f.cfg)
				mustSQL(t, e)
				tap := &aMFACommitConnector{Connector: base, clock: f.db}
				wrapped := sql.OpenDB(tap)
				wrapped.SetMaxOpenConns(2)
				defer wrapped.Close()
				f.svc.DB = wrapped
				if name == "unknown_actual_commit_no_proof" {
					tap.lost.Store(true)
				} else {
					f.environment.config.MaterialsUntil = aDownloadMFANow(t, f.ctx, f.db).Add(2 * time.Second)
					tap.until = f.environment.config.MaterialsUntil
					tap.delay.Store(true)
				}
				status, proof := f.http(code)
				if status != 503 || proof.SchemaVersion != "" {
					t.Fatal("unknown/late actual commit returned proof", status)
				}
				f.checkRows(t, f.step+1, 1)
			case "original_material_expiry":
				f.environment.config.MaterialsUntil = aDownloadMFANow(t, f.ctx, f.db).Add(2 * time.Second)
				hit := false
				f.signer.before = func(ctx context.Context) error {
					hit = true
					return aMFAWaitSQL(ctx, f.db, f.environment.config.MaterialsUntil)
				}
				status, proof := f.http(code)
				if !hit || status != 503 || proof.SchemaVersion != "" {
					t.Fatal("expired original source released proof", status)
				}
				f.checkRows(t, f.step, 0)
			case "observed_L0_wait_original_expiry":
				f.environment.config.MaterialsUntil = aDownloadMFANow(t, f.ctx, f.db).Add(2 * time.Second)
				blocker, e := f.db.BeginTx(f.ctx, nil)
				mustSQL(t, e)
				defer blocker.Rollback()
				var installation string
				mustSQL(t, blocker.QueryRowContext(f.ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", f.svc.InstallationID).Scan(&installation))
				result := make(chan int, 1)
				go func() { status, _ := f.http(code); result <- status }()
				observed := false
				limit := time.Now().Add(5 * time.Second)
				for time.Now().Before(limit) {
					var waits int
					mustSQL(t, f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_installation_state'`, f.identity.Database).Scan(&waits))
					if waits > 0 {
						observed = true
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				mustSQL(t, aMFAWaitSQL(f.ctx, f.db, f.environment.config.MaterialsUntil))
				mustSQL(t, blocker.Rollback())
				status := <-result
				if !observed || status != 503 {
					t.Fatal("actual L0 wait not observed or original expiry refreshed", observed, status)
				}
				f.checkRows(t, f.step, 0)
			}
		}) {
			return
		}
	}
	t.Log("PASS actual download MFA MySQL cases=9 synthetic_owner_issuer_material=yes human_mfa=no provider_read=no admission_nonce_consumed=no production_approval=no")
}
