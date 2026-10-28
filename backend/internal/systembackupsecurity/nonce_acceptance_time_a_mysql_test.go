//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Every SQL statement and UTC sample reaches the isolated real MySQL server.
// Only the optional delay is injected, before the original nonce INSERT. No
// timestamps/rows/affected counts or SQL predicates are replaced by a model.
type aRealNonceTimeConnector struct {
	base     driver.Connector
	before   func(context.Context) error
	called   bool
	accepted time.Time
}

func (c *aRealNonceTimeConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *aRealNonceTimeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aRealNonceTimeConn{Conn: conn, tap: c}, nil
}

type aRealNonceTimeConn struct {
	driver.Conn
	tap *aRealNonceTimeConnector
}

func (c *aRealNonceTimeConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *aRealNonceTimeConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *aRealNonceTimeConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(q, "INSERT INTO system_backup_v2_strong_auth_nonces") {
		if c.tap.called || len(args) != 17 {
			return nil, errors.New("nonce time probe requires one exact INSERT")
		}
		c.tap.called = true
		var ok bool
		c.tap.accepted, ok = args[9].Value.(time.Time)
		if !ok {
			return nil, errors.New("nonce acceptance is not a bound SQL time")
		}
		if c.tap.before != nil {
			if err := c.tap.before(ctx); err != nil {
				return nil, err
			}
		}
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func aRealNonceTimeDB(t *testing.T, cfg *mysql.Config) (*sql.DB, *aRealNonceTimeConnector) {
	t.Helper()
	base, err := mysql.NewConnector(cfg)
	mysqlMust(t, err)
	tap := &aRealNonceTimeConnector{base: base}
	db := sql.OpenDB(tap)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db, tap
}

func aRealNonceResign(t *testing.T, p *Proof, key ed25519.PrivateKey, auth, expiry time.Time) {
	t.Helper()
	p.Payload.AuthTime, p.Payload.ExpiresAt = auth.Format(time.RFC3339Nano), expiry.Format(time.RFC3339Nano)
	payload, err := CanonicalPayload(p.Payload)
	mysqlMust(t, err)
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
}

func aRealNonceTimes(t *testing.T, ctx context.Context, db *sql.DB, installation, key string, before, auth, expiry time.Time, future bool, tap *aRealNonceTimeConnector) {
	t.Helper()
	var accepted, consumed, expires, retain time.Time
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT authenticated_at,consumed_at,expires_at,retain_until FROM system_backup_v2_strong_auth_nonces WHERE origin_installation_id=? AND idempotency_key=?", installation, key).Scan(&accepted, &consumed, &expires, &retain))
	after := configProofDBNow(t, ctx, db)
	if !tap.called || !accepted.Equal(tap.accepted) || accepted.Equal(auth) || accepted.Before(before) || consumed.Before(accepted) || consumed.After(after) || !expires.Equal(expiry) || !retain.After(expires) {
		t.Fatal("real ledger did not preserve SQL acceptance and original expiry")
	}
	if future && (!before.Before(auth) || !accepted.Before(auth)) {
		t.Fatal("slow setup did not exercise a future auth_time")
	}
}

// Clone the three exact SHOW CREATE statements from the verified full-catalog
// disposable database. Minimal synthetic user/config/target/capacity tables are
// the existing provider probe dependencies. No source data is copied; real
// nonce/operation/evidence CHECKs and FKs remain active inside this owned DB.
func aNonceProviderDatabase(t *testing.T, ctx context.Context, parent *sql.DB, cfg *mysql.Config, identity DatabaseIdentity) (*sql.DB, *mysql.Config) {
	t.Helper()
	var entropy [16]byte
	_, err := rand.Read(entropy[:])
	mysqlMust(t, err)
	name := "ant_" + hex.EncodeToString(entropy[:])
	var sourceUUID string
	mysqlMust(t, parent.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&sourceUUID))
	if sourceUUID != identity.ServerUUID {
		t.Fatal("provider clone server identity changed")
	}
	_, err = parent.ExecContext(ctx, "CREATE DATABASE "+name+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	mysqlMust(t, err)
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var current string
		if parent.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&current) != nil || current != sourceUUID {
			t.Error("CLEANUP_PENDING nonce provider server identity")
			return
		}
		if _, e := parent.ExecContext(clean, "DROP DATABASE "+name); e != nil {
			t.Errorf("CLEANUP_PENDING nonce provider database %s", name)
			return
		}
		var remaining int
		if parent.QueryRowContext(clean, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&remaining) != nil || remaining != 0 {
			t.Error("CLEANUP_PENDING nonce provider database absence")
			return
		}
		t.Log("CLEANED nonce-time owned provider database")
	})
	childCfg := cfg.Clone()
	childCfg.DBName = name
	childCfg.MultiStatements = true
	db, err := sql.Open("mysql", childCfg.FormatDSN())
	mysqlMust(t, err)
	t.Cleanup(func() { db.Close() })
	childIdentity := DatabaseIdentity{ServerUUID: sourceUUID, Database: name}
	mysqlMust(t, childIdentity.check(ctx, db))
	_, err = db.ExecContext(ctx, registrationMySQLDependencies)
	mysqlMust(t, err)
	for _, table := range []string{"system_backup_v2_evidence", "system_backup_v2_operations", "system_backup_v2_strong_auth_nonces"} {
		var got, ddl string
		mysqlMust(t, parent.QueryRowContext(ctx, "SHOW CREATE TABLE "+table).Scan(&got, &ddl))
		if got != table || !strings.HasPrefix(ddl, "CREATE TABLE `"+table+"`") || len(ddl) > 131072 || strings.Contains(ddl, "`"+cfg.DBName+"`.") || strings.Contains(ddl, "DEFINER") {
			t.Fatal("unexpected or cross-database provider DDL")
		}
		_, err = db.ExecContext(ctx, ddl)
		mysqlMust(t, err)
	}
	return db, childCfg
}

type aNonceProviderAuthority struct {
	mysqlRegistrationAuthority
	identity DatabaseIdentity
}

func (a aNonceProviderAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, target ProviderProofTarget, cfg RegistrationConfig) error {
	if err := a.identity.check(ctx, tx); err != nil {
		return err
	}
	return a.mysqlRegistrationAuthority.Authorize(ctx, tx, actor, target, cfg)
}

func runANonceProviderTimes(t *testing.T, ctx context.Context, parent *sql.DB, cfg *mysql.Config, identity DatabaseIdentity) {
	for _, name := range []string{"past_auth", "future_within_skew", "future_outside_skew", "expiry_during_insert"} {
		if !t.Run(name, func(t *testing.T) {
			db, childCfg := aNonceProviderDatabase(t, ctx, parent, cfg, identity)
			r, pc, providerKey := providerSignedFixture(t)
			now := configProofDBNow(t, ctx, db)
			pc.DatabaseNow, pc.Keys[0].NotBefore, pc.Keys[0].NotAfter = now, now.Add(-time.Hour), now.Add(time.Hour)
			r.Proof.IssuedAt, r.Proof.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano), now.Add(4*time.Minute).Format(time.RFC3339Nano)
			providerResign(t, &r, pc, providerKey)
			_, actor, _, proof, synthetic := registrationFixture(t)
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
			authority := mysqlRegistrationAuthority{pc: pc, sc: syntheticAuthorityConfig(t, synthetic, actor, key)}
			_, err := db.ExecContext(ctx, `INSERT INTO users VALUES(42,'admin',true); INSERT INTO system_backup_v2_installation_state VALUES('installation_synthetic',1); INSERT INTO system_backup_v2_configs VALUES('installation_synthetic',1,'synthetic-v1',REPEAT('a',64),'auth-v1',REPEAT('b',64),'rbac-v1',REPEAT('c',64),'v1',REPEAT('d',64),300,30,300,86400,2592000,60,1073741824)`)
			mysqlMust(t, err)
			_, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_external_actions VALUES(?,?,3)", pc.Scope.InstallationID, r.Target.TargetPublicID)
			mysqlMust(t, err)
			callDB, tap := aRealNonceTimeDB(t, childCfg)
			service := ProviderRegistrationService{DB: callDB, InstallationID: pc.Scope.InstallationID, Authority: aNonceProviderAuthority{authority, DatabaseIdentity{ServerUUID: identity.ServerUUID, Database: childCfg.DBName}}}
			now = configProofDBNow(t, ctx, db)
			auth, expiry := now.Add(-time.Minute), now.Add(time.Minute)
			switch name {
			case "future_within_skew":
				auth = now.Add(15 * time.Second)
			case "future_outside_skew":
				auth, expiry = now.Add(90*time.Second), now.Add(3*time.Minute)
			case "expiry_during_insert":
				expiry = now.Add(10 * time.Second)
			}
			aRealNonceResign(t, &proof, key, auth, expiry)
			body := mysqlRequest(t, r, &proof, key)
			if name == "expiry_during_insert" {
				tap.before = func(call context.Context) error {
					return waitConfigWriterADBExpiry(call, expiry, configWriterASample(db))
				}
			}
			before := configProofDBNow(t, ctx, db)
			result, err := service.Register(ctx, actor, body, proof)
			if name == "past_auth" || name == "future_within_skew" {
				mysqlMust(t, err)
				if result.HTTPStatus != 201 || result.Replayed {
					t.Fatal("fresh nonce provider registration not committed once")
				}
				aRealNonceTimes(t, ctx, db, pc.Scope.InstallationID, r.IdempotencyKey, before, auth, expiry, name == "future_within_skew", tap)
				mysqlRegistrationCounts(t, db, 1, 1, 1, 2, 1)
			} else {
				var failure *VerificationError
				if !errors.As(err, &failure) || failure.Code != FailureExpired || result.HTTPStatus != 0 {
					t.Fatal("invalid provider proof returned success or wrong failure")
				}
				if name == "future_outside_skew" && tap.called || name == "expiry_during_insert" && !tap.called {
					t.Fatal("provider did not exercise intended time boundary")
				}
				mysqlRegistrationCounts(t, db, 0, 0, 0, 0, 0)
			}
		}) {
			return
		}
	}
}

func runANonceConfigTimes(t *testing.T, ctx context.Context, db *sql.DB, cfg *mysql.Config, identity DatabaseIdentity) {
	for _, name := range []string{"past_auth", "future_within_skew", "future_outside_skew", "expiry_during_insert"} {
		if !t.Run(name, func(t *testing.T) {
			p := newConfigProofMySQLFixture(t, ctx, db, cfg, identity)
			f := newConfigWriterMySQLFixture(t, p)
			f.proposed = aNonceAcceptanceProposed(t, f.current)
			key := "a_nonce_time_mysql_key_012345"
			raw := f.request(t, ConfigUpdateEndpoint, 1)
			request, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
			mysqlMust(t, err)
			digest, err := request.RequestHash(p.installation, "admin", strconv.FormatInt(p.userID, 10))
			mysqlMust(t, err)
			now := configProofDBNow(t, ctx, db)
			proof, err := p.svc.Issuer.issue(ctx, p.actor, RequestBinding{Endpoint: ConfigUpdateEndpoint, RequestHash: digest, IdempotencyKey: key}, now)
			mysqlMust(t, err)
			skew := time.Duration(f.current.snapshot.numbers["strong_auth_clock_skew_seconds"]) * time.Second
			if skew < 2*time.Second {
				t.Fatal("fixture needs a positive configured skew")
			}
			auth, expiry := now.Add(-time.Minute), now.Add(time.Minute)
			switch name {
			case "future_within_skew":
				auth = now.Add(skew / 2)
			case "future_outside_skew":
				auth, expiry = now.Add(skew+time.Minute), now.Add(3*time.Minute)
			case "expiry_during_insert":
				expiry = now.Add(10 * time.Second)
			}
			aRealNonceResign(t, &proof, p.signer.key, auth, expiry)
			callDB, tap := aRealNonceTimeDB(t, cfg)
			service := f.svc
			service.DB = callDB
			if name == "expiry_during_insert" {
				tap.before = func(call context.Context) error {
					return waitConfigWriterADBExpiry(call, expiry, configWriterASample(db))
				}
			}
			beforeCounts, before := f.counts(t), configProofDBNow(t, ctx, db)
			result, err := service.Mutate(ctx, p.actor, ConfigUpdateEndpoint, key, "a-nonce-time-mysql", raw, &proof)
			if name == "past_auth" || name == "future_within_skew" {
				mysqlMust(t, err)
				f.checkCommitted(t, result, ConfigUpdateEndpoint, key, raw, 2)
				aRealNonceTimes(t, ctx, db, p.installation, key, before, auth, expiry, name == "future_within_skew", tap)
			} else {
				if err == nil || result.HTTPStatus != 0 || !reflect.DeepEqual(beforeCounts, f.counts(t)) {
					t.Fatal("invalid config proof did not roll back every SQL effect")
				}
				if name == "future_outside_skew" {
					var failure *VerificationError
					if !errors.As(err, &failure) || failure.Code != FailureExpired {
						t.Fatal("config failed before its intended proof time check")
					}
				}
				if name == "future_outside_skew" && tap.called || name == "expiry_during_insert" && !tap.called {
					t.Fatal("config did not exercise intended time boundary")
				}
			}
		}) {
			return
		}
	}
}

func aNonceAcceptanceProposed(t *testing.T, current ConfigValues) ConfigValues {
	t.Helper()
	var doc map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(current.CanonicalJSON(), &doc))
	if current.snapshot.numbers["retention_seconds"] <= 86400 {
		t.Fatal("nonce fixture must have reducible original retention")
	}
	var durations map[string]json.RawMessage
	mysqlMust(t, json.Unmarshal(doc["durations"], &durations))
	durations["retention_seconds"] = json.RawMessage(`86400`)
	var err error
	doc["durations"], err = json.Marshal(durations)
	mysqlMust(t, err)
	doc["enabled"] = json.RawMessage(`true`)
	raw, err := json.Marshal(doc)
	mysqlMust(t, err)
	proposed, err := DecodeConfigValues(raw)
	mysqlMust(t, err)
	risk := configMutationBaseRisk(current, proposed)
	if !risk.ProtectionReduction || !risk.StrongAuthRequired() {
		t.Fatal("nonce fixture must trigger actual strong-auth protection reduction")
	}
	return proposed
}

func TestANonceAcceptanceMySQL(t *testing.T) {
	ctx, db, cfg, identity := configWriterMySQLDatabase(t)
	if !t.Run("provider", func(t *testing.T) { runANonceProviderTimes(t, ctx, db, cfg, identity) }) {
		return
	}
	if !t.Run("config", func(t *testing.T) { runANonceConfigTimes(t, ctx, db, cfg, identity) }) {
		return
	}
	t.Log("PASS real nonce SQL acceptance time: eight new cases; synthetic issuer/authority/capacity; no human MFA or production approval")
}

func TestANonceAcceptanceMySQLSeed(t *testing.T) {
	var _ driver.ConnBeginTx = (*aRealNonceTimeConn)(nil)
	var _ driver.QueryerContext = (*aRealNonceTimeConn)(nil)
	var _ driver.ExecerContext = (*aRealNonceTimeConn)(nil)
	if (SensitiveDownloadProofVerification{}).ProofAcceptedAt() != (time.Time{}) {
		t.Fatal("zero verification has acceptance time")
	}
	current, err := DecodeConfigValues(bootstrapFixture(t))
	mysqlMust(t, err)
	proposed := aNonceAcceptanceProposed(t, current)
	if current.SHA256() == proposed.SHA256() || !proposed.Enabled() || proposed.snapshot.numbers["retention_seconds"] != 86400 {
		t.Fatal("nonce fixture did not change actual protected input")
	}
}
