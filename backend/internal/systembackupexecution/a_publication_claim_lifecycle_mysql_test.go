package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	mysql "github.com/go-sql-driver/mysql"
)

var errAPublicationACKLost = errors.New("local test: actual committed SQL acknowledgement lost")

// Transparent proxy to the REAL MySQL connector. Only Commit's client ACK is
// lost, after the actual original transaction has committed successfully.
type aPublicationACKConnector struct {
	driver.Connector
	lose *atomic.Bool
}

func (c aPublicationACKConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aPublicationACKConn{Conn: conn, lose: c.lose}, nil
}

type aPublicationACKConn struct {
	driver.Conn
	lose *atomic.Bool
}

func (c *aPublicationACKConn) Begin() (driver.Tx, error) {
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return aPublicationACKTx{Tx: tx, lose: c.lose}, nil
}
func (c *aPublicationACKConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return aPublicationACKTx{Tx: tx, lose: c.lose}, nil
}
func (c *aPublicationACKConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *aPublicationACKConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

type aPublicationACKTx struct {
	driver.Tx
	lose *atomic.Bool
}

func (t aPublicationACKTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if t.lose.Swap(false) {
		return errAPublicationACKLost
	}
	return nil
}

// Same original c.Executor contract, with an actual autocommitted mutation
// followed by a lost ACK. No claim token is fabricated on an ambiguous result.
type aPublicationExecACK struct {
	db   *sql.DB
	lose bool
}

func (e *aPublicationExecACK) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	r, err := e.db.ExecContext(ctx, q, args...)
	if err == nil && e.lose {
		e.lose = false
		return nil, errAPublicationACKLost
	}
	return r, err
}

type aPublicationClaims struct {
	x                *publicationStartupFixture
	db, owner, ackDB *sql.DB
	ctx              context.Context
	installation     string
	target           c.Target
	policy           c.LeasePolicy
	loseCommit       atomic.Bool
	payloads         map[string][]byte
	receipts         int
}

func newAPublicationClaims(t *testing.T) *aPublicationClaims {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	f := &aPublicationClaims{ctx: ctx, policy: c.LeasePolicy{TTL: 15 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, target: c.Target{Kind: c.TargetBackup, PublicID: "sbk_11111111-2222-4333-8444-555555555555"}, payloads: map[string][]byte{}}
	var connector driver.Connector
	db, owner, account, uuid, database := aPublicationStartupSQL(t, ctx, func(config *mysql.Config) {
		var err error
		connector, err = mysql.NewConnector(config)
		if err != nil {
			t.Fatal(err)
		}
	})
	f.db, f.owner = db, owner
	f.ackDB = sql.OpenDB(aPublicationACKConnector{Connector: connector, lose: &f.loseCommit})
	t.Cleanup(func() { f.ackDB.Close() })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("owned original claim schema/setup", err)
		}
	}
	exec(`ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL,ADD COLUMN next_reconcile_at DATETIME(6) NULL`)
	exec(`ALTER TABLE system_backup_v2_backups ADD COLUMN schema_version VARCHAR(64) CHARACTER SET ascii NOT NULL DEFAULT 'system-backup-task.v1',ADD COLUMN task_type ENUM('backup') NOT NULL DEFAULT 'backup'`)
	eventDDL, err := os.ReadFile(filepath.Join("..", "db", "migrations", "099_backup_v2_add_system_backup_coordination_observability.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(strings.Split(string(eventDDL), "CREATE TABLE IF NOT EXISTS system_backup_v2_alert_states")[0])
	user, host, ok := strings.Cut(account, "@")
	if !ok || !strings.HasPrefix(user, "ad_a_pub_") || host != "127.0.0.1" {
		t.Fatal("claim test workload identity mismatch")
	}
	exec("GRANT UPDATE(controller_owner,controller_lease_expires_at,heartbeat_at,next_reconcile_at,row_version) ON `" + database + "`.`system_backup_v2_backups` TO '" + user + "'@'127.0.0.1'")
	exec("GRANT SELECT,INSERT ON `" + database + "`.`system_backup_v2_events` TO '" + user + "'@'127.0.0.1'")
	f.x = newPublicationStartupFixture(t, account, uuid, database)
	// A 10-second token legitimately cannot fit a frozen window with <10s
	// remaining. Preserve that production refusal and use an exact 1s provider
	// policy for lifecycle retries inside the unchanged original 15s window.
	f.x.tokenTTLSeconds.Store(1)
	f.installation = f.x.grant.InstallationID
	if err := f.x.service.bindDeploymentStartupInputs(f.x.inputs); err != nil {
		t.Fatal(err)
	}
	if err := f.x.service.attachPublicationSigners(ctx, db, f.x.client, f.x.inputs.ControllerPodName); err != nil {
		t.Fatal(err)
	}
	if f.x.service.PublisherOwner == f.x.service.Config.ControllerOwner {
		t.Fatal("actual publisher confused with capture owner")
	}
	var now time.Time
	if owner.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("original database clock unavailable")
	}
	exec(`INSERT INTO system_backup_v2_backups(origin_installation_id,public_id,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_sha256,task_purpose,requested_parts) VALUES (?,?,?,'validating',NULL,7,NULL,?,1,?,'acceptance',?)`, f.installation, f.target.PublicID, "original-claim-api-publication", now.Add(4*time.Minute), f.x.grant.ConfigSHA256, "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle")
	exec(`INSERT INTO system_backup_v2_attempts VALUES ('backup',?,'capture',1,'sealed')`, f.target.PublicID)
	exec(`INSERT INTO system_backup_v2_runtime_captures VALUES (?,17,?,?)`, f.target.PublicID, now.Add(-time.Second), now)
	exec(`INSERT INTO system_backup_v2_execution_records VALUES (?,?,1,'capture','capture_result',?)`, f.installation, f.target.PublicID, strings.Repeat("d", 64))
	return f
}

func (f *aPublicationClaims) acquire(t *testing.T, owner string, version uint64) c.ClaimToken {
	t.Helper()
	token, err := (c.SQLTaskClaimStore{DB: f.db, InstallationID: f.installation}).AcquireWithReceipt(f.ctx, f.target, owner, version, f.policy)
	if err != nil {
		t.Fatal("actual original AcquireWithReceipt API", err)
	}
	f.receipts++
	f.checkReceipts(t, f.receipts)
	return token
}

func (f *aPublicationClaims) checkReceipts(t *testing.T, expected int) {
	t.Helper()
	rows, err := f.db.QueryContext(f.ctx, `SELECT id,schema_version,origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,request_id,created_at FROM system_backup_v2_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id uint64
		var schema, installation, kind, publicID, event, level, status, message, request string
		var details bool
		var created time.Time
		if err = rows.Scan(&id, &schema, &installation, &kind, &publicID, &event, &level, &status, &message, &details, &request, &created); err != nil {
			t.Fatal(err)
		}
		if id == 0 || schema != "system-backup-event.v1" || installation != f.installation || kind != "backup" || publicID != f.target.PublicID || event != c.TaskClaimAcquiredEvent || level != "info" || status != "validating" || message != "Controller acquired task claim." || details || request != "original-claim-api-publication" || created.IsZero() {
			t.Fatal("original durable claim receipt differs from current task/request")
		}
		count++
	}
	if rows.Err() != nil || count != expected {
		t.Fatal("original claim CAS and durable receipt were not preserved together")
	}
}
func (f *aPublicationClaims) task(t *testing.T, claim c.ClaimToken) *s.SQLPublicationTaskSigners {
	t.Helper()
	q, err := f.x.service.PublicationSignersForTask(f.ctx, claim)
	if err != nil {
		t.Fatal("actual service original claim consumer", err)
	}
	t.Cleanup(q.Close)
	return q
}

func (f *aPublicationClaims) prepare(t *testing.T, q *s.SQLPublicationTaskSigners) map[string]*s.SQLPreparedPublicationRecord {
	t.Helper()
	if len(f.payloads) == 0 {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "public-c-crypto-v1", "signature-vectors.json"))
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Vectors []struct {
				Payload string `json:"payload_json"`
				Trust   struct{ Purpose string }
			}
		}
		if json.Unmarshal(raw, &v) != nil || len(v.Vectors) != 4 {
			t.Fatal("public C vectors")
		}
		for _, v := range v.Vectors[:3] {
			purpose := v.Trust.Purpose
			key, err := q.PublicationSigningKey(f.ctx, purpose)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if json.Unmarshal([]byte(v.Payload), &body) != nil {
				t.Fatal("C payload")
			}
			body["backup_public_id"] = f.target.PublicID
			body["attempt_no"] = 1
			body["signing_key"] = key
			if purpose != "acceptance_record" {
				body["origin_installation_id"] = f.installation
			}
			field := map[string]string{"capture_certificate": "issued_at", "acceptance_record": "decision_at", "catalog_record": "recorded_at"}[purpose]
			body[field] = time.Now().UTC().Format(time.RFC3339Nano)
			f.payloads[purpose], _ = json.Marshal(body)
		}
	}
	out := map[string]*s.SQLPreparedPublicationRecord{}
	for purpose, payload := range f.payloads {
		p, err := q.PreparePublicationRecord(f.ctx, purpose, payload)
		if err != nil {
			t.Fatal(err)
		}
		out[purpose] = p
	}
	return out
}

func (f *aPublicationClaims) stage(t *testing.T, db *sql.DB, prepared map[string]*s.SQLPreparedPublicationRecord) error {
	t.Helper()
	tx, err := db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		if err = prepared[purpose].Stage(f.ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type aFrozenPublicationRow struct {
	ID      string
	Payload []byte
	SHA     string
	Size    uint64
	Until   time.Time
}

func (f *aPublicationClaims) frozen(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	rows, err := f.db.QueryContext(f.ctx, `SELECT public_id,inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence ORDER BY public_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var frozen []aFrozenPublicationRow
	var earliest time.Time
	for rows.Next() {
		var r aFrozenPublicationRow
		if err = rows.Scan(&r.ID, &r.Payload, &r.SHA, &r.Size, &r.Until); err != nil {
			t.Fatal(err)
		}
		if earliest.IsZero() || r.Until.Before(earliest) {
			earliest = r.Until
		}
		frozen = append(frozen, r)
	}
	if rows.Err() != nil || len(frozen) != 3 {
		t.Fatal("original frozen record readback incomplete")
	}
	raw, _ := json.Marshal(frozen)
	return raw, earliest
}

func (f *aPublicationClaims) sign(t *testing.T, prepared map[string]*s.SQLPreparedPublicationRecord, expected map[string][]byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	history, err := f.x.service.PublicationSigningHistory(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		raw, sum, err := prepared[purpose].SignCommitted(f.ctx)
		if err != nil {
			t.Fatal("actual original claim SQL/TLS signing", err)
		}
		if got, err := history.VerifyPublicationRecord(raw, s.ArtifactSigningTask{BackupPublicID: f.target.PublicID, AttemptNo: 1}, purpose); err != nil || got != sum {
			t.Fatal("independent original public history", err)
		}
		if expected != nil && !bytes.Equal(raw, expected[purpose]) {
			t.Fatal("new original token changed frozen signed record")
		}
		out[purpose] = raw
	}
	return out
}

func (f *aPublicationClaims) reject(t *testing.T, token c.ClaimToken, prepared map[string]*s.SQLPreparedPublicationRecord) {
	t.Helper()
	login, sign := f.x.logins.Load(), f.x.signs.Load()
	if _, err := f.x.service.PublicationSignersForTask(f.ctx, token); err == nil {
		t.Fatal("stale/foreign original token admitted")
	}
	for _, p := range prepared {
		if raw, sum, err := p.SignCommitted(f.ctx); err == nil || raw != nil || sum != "" {
			t.Fatal("old original token returned signature")
		}
	}
	if f.x.logins.Load() != login || f.x.signs.Load() != sign {
		t.Fatal("old original token reached provider")
	}
}

func (f *aPublicationClaims) waitDB(t *testing.T, query string, args ...any) {
	t.Helper()
	for {
		var ready bool
		if err := f.db.QueryRowContext(f.ctx, query, args...).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("original database-time condition timed out")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestAPublicationActualAcquireRenewReleaseTakeoverMySQLAndTLS(t *testing.T) {
	f := newAPublicationClaims(t)
	token := f.acquire(t, f.x.service.PublisherOwner, 7)
	q := f.task(t, token)
	first := f.prepare(t, q)
	f.loseCommit.Store(true)
	if err := f.stage(t, f.ackDB, first); !errors.Is(err, errAPublicationACKLost) {
		t.Fatal("real committed Stage ACK was not lost", err)
	}
	frozen, end := f.frozen(t)
	if err := f.stage(t, f.db, first); err != nil {
		t.Fatal("unknown ACK original input readback", err)
	}
	if got, _ := f.frozen(t); !bytes.Equal(got, frozen) {
		t.Fatal("ACK retry changed original input/expiry")
	}
	records := f.sign(t, first, nil)
	f.policy.TTL = 45 * time.Second
	renewed, err := c.RenewClaimInInstallation(f.ctx, f.db, f.installation, token, f.policy)
	if err != nil {
		t.Fatal("actual Renew API", err)
	}
	f.reject(t, token, first)
	current := f.prepare(t, f.task(t, renewed))
	if err = f.stage(t, f.db, current); err != nil {
		t.Fatal(err)
	}
	f.sign(t, current, records)
	var afterLogin c.ClaimToken
	var renewErr error
	f.x.onLogin = func() {
		afterLogin, renewErr = c.RenewClaimInInstallation(f.ctx, f.db, f.installation, renewed, f.policy)
	}
	before := f.x.signs.Load()
	if raw, _, err := current["capture_certificate"].SignCommitted(f.ctx); err == nil || raw != nil || f.x.signs.Load() != before {
		t.Fatal("actual Renew during JWT login reached Transit Sign")
	}
	f.x.onLogin = nil
	if renewErr != nil || afterLogin.RowVersion != renewed.RowVersion+1 {
		t.Fatal("actual login-hook Renew failed", renewErr)
	}
	f.reject(t, renewed, current)
	releasedVersion, err := c.ReleaseClaimInInstallation(f.ctx, f.db, f.installation, afterLogin, 3*time.Second)
	if err != nil {
		t.Fatal("actual Release API", err)
	}
	f.reject(t, afterLogin, current)
	other := "public:other-original-controller"
	if _, err = (c.SQLTaskClaimStore{DB: f.db, InstallationID: f.installation}).AcquireWithReceipt(f.ctx, f.target, other, releasedVersion, f.policy); !errors.Is(err, c.ErrClaimNotAcquired) {
		t.Fatal("actual acquire skipped original release retry time", err)
	}
	f.waitDB(t, `SELECT next_reconcile_at<=UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, f.installation, f.target.PublicID)
	takeover := f.acquire(t, other, releasedVersion)
	f.reject(t, takeover, current)
	if _, err = c.RenewClaimInInstallation(f.ctx, f.db, f.installation, afterLogin, f.policy); !errors.Is(err, c.ErrClaimLost) {
		t.Fatal("old owner renewed taken-over claim", err)
	}
	releasedVersion, err = c.ReleaseClaimInInstallation(f.ctx, f.db, f.installation, takeover, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.waitDB(t, `SELECT next_reconcile_at<=UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, f.installation, f.target.PublicID)
	reacquired := f.acquire(t, f.x.service.PublisherOwner, releasedVersion)
	fresh := f.prepare(t, f.task(t, reacquired))
	if err = f.stage(t, f.db, fresh); err != nil {
		t.Fatal(err)
	}
	f.sign(t, fresh, records)
	if got, until := f.frozen(t); !bytes.Equal(got, frozen) || !until.Equal(end) {
		t.Fatal("renew/release/takeover expanded original frozen validity")
	}
	var lease time.Time
	if f.db.QueryRowContext(f.ctx, `SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=?`, f.target.PublicID).Scan(&lease) != nil || !lease.After(end) {
		t.Fatal("live renewed claim must outlast old frozen input")
	}
	f.waitDB(t, `SELECT UTC_TIMESTAMP(6)>=?`, end)
	login, sign := f.x.logins.Load(), f.x.signs.Load()
	if err = f.stage(t, f.db, fresh); err == nil {
		t.Fatal("expired frozen record renewed under new live claim")
	}
	for _, p := range fresh {
		if raw, _, err := p.SignCommitted(f.ctx); err == nil || raw != nil {
			t.Fatal("expired original input signed")
		}
	}
	if f.x.logins.Load() != login || f.x.signs.Load() != sign {
		t.Fatal("expired frozen input reached provider")
	}
	if got, _ := f.frozen(t); !bytes.Equal(got, frozen) {
		t.Fatal("failed expiry retry changed original evidence")
	}
	history, err := f.x.service.PublicationSigningHistory(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for purpose, raw := range records {
		if _, err = history.VerifyPublicationRecord(raw, s.ArtifactSigningTask{BackupPublicID: f.target.PublicID, AttemptNo: 1}, purpose); err != nil {
			t.Fatal("expired signing window destroyed independent history", err)
		}
	}
}

func TestAPublicationActualProviderLostACKMySQLAndTLS(t *testing.T) {
	f := newAPublicationClaims(t)
	token := f.acquire(t, f.x.service.PublisherOwner, 7)
	first := f.prepare(t, f.task(t, token))
	if err := f.stage(t, f.db, first); err != nil {
		t.Fatal(err)
	}
	records := f.sign(t, first, nil)
	frozen, end := f.frozen(t)
	f.policy.TTL = 45 * time.Second
	renewed, err := c.RenewClaimInInstallation(f.ctx, f.db, f.installation, token, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.reject(t, token, first)
	fresh := f.prepare(t, f.task(t, renewed))
	if err := f.stage(t, f.db, fresh); err != nil {
		t.Fatal(err)
	}
	f.x.dropSignACK.Store(true)
	before := f.x.signs.Load()
	if raw, sum, err := fresh["capture_certificate"].SignCommitted(f.ctx); err == nil || raw != nil || sum != "" || f.x.signs.Load() != before+1 {
		t.Fatal("provider completed Sign with lost ACK was not surfaced as unknown")
	}
	observed := f.x.unknownSignature.Load()
	if observed == nil || len(observed.Signature) != 64 {
		t.Fatal("ACK was dropped before real Ed25519 signing")
	}
	var old struct {
		Payload   json.RawMessage `json:"payload"`
		Signature struct {
			Header string `json:"protected_header"`
			Value  string `json:"value"`
		} `json:"signature"`
	}
	if json.Unmarshal(records["capture_certificate"], &old) != nil {
		t.Fatal("original capture record")
	}
	expectedSignature, err := base64.RawURLEncoding.Strict().DecodeString(old.Signature.Value)
	if err != nil || !bytes.Equal(expectedSignature, observed.Signature) || string(observed.Input) != old.Signature.Header+"."+base64.RawURLEncoding.EncodeToString(old.Payload) {
		t.Fatal("provider unknown ACK used different bytes or key from frozen original record")
	}
	if err := f.stage(t, f.db, fresh); err != nil {
		t.Fatal("original frozen input retry failed", err)
	}
	f.sign(t, fresh, records)
	if got, until := f.frozen(t); !bytes.Equal(got, frozen) || !until.Equal(end) {
		t.Fatal("lost claim/provider ACK changed original record bytes or extended expiry")
	}
}

func (f *aPublicationClaims) checkClaimReadback(t *testing.T, expectedVersion uint64) {
	t.Helper()
	var schema, kind, request, status, owner string
	var version uint64
	var heartbeat, until, now time.Time
	if err := f.db.QueryRowContext(f.ctx, `SELECT schema_version,task_type,request_id,status,controller_owner,row_version,heartbeat_at,controller_lease_expires_at,UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, f.installation, f.target.PublicID).Scan(&schema, &kind, &request, &status, &owner, &version, &heartbeat, &until, &now); err != nil {
		t.Fatal(err)
	}
	if schema != "system-backup-task.v1" || kind != "backup" || request != "original-claim-api-publication" || status != "validating" || owner != f.x.service.PublisherOwner || version != expectedVersion || !until.Equal(heartbeat.Add(f.policy.TTL)) || now.Before(heartbeat) || !now.Before(until) {
		t.Fatal("independent original claim state readback differs from committed mutation")
	}
}

func TestAPublicationActualAcquireReceiptCommitLostACKMySQL(t *testing.T) {
	f := newAPublicationClaims(t)
	f.loseCommit.Store(true)
	returned, err := (c.SQLTaskClaimStore{DB: f.ackDB, InstallationID: f.installation}).AcquireWithReceipt(f.ctx, f.target, f.x.service.PublisherOwner, 7, f.policy)
	if !errors.Is(err, c.ErrTaskClaimCommitUnknown) || returned != (c.ClaimToken{}) {
		t.Fatal("ambiguous actual AcquireWithReceipt commit returned a token", err)
	}
	f.checkClaimReadback(t, 8)
	f.checkReceipts(t, 1)
	if _, err = f.x.service.PublicationSignersForTask(f.ctx, returned); err == nil {
		t.Fatal("unknown claim receipt became an execution token")
	}
	// The old expected version is not silently replaced with readback version.
	if retry, err := (c.SQLTaskClaimStore{DB: f.db, InstallationID: f.installation}).AcquireWithReceipt(f.ctx, f.target, f.x.service.PublisherOwner, 7, f.policy); !errors.Is(err, c.ErrClaimNotAcquired) || retry != (c.ClaimToken{}) {
		t.Fatal("unknown commit blind retry manufactured a new token or receipt", err)
	}
	f.checkClaimReadback(t, 8)
	f.checkReceipts(t, 1)
	if f.x.logins.Load() != 0 || f.x.signs.Load() != 0 {
		t.Fatal("unknown Acquire ACK reached signing provider")
	}
}

func TestAPublicationActualRenewLostACKLeavesOriginalStateMySQL(t *testing.T) {
	f := newAPublicationClaims(t)
	token := f.acquire(t, f.x.service.PublisherOwner, 7)
	first := f.prepare(t, f.task(t, token))
	if err := f.stage(t, f.db, first); err != nil {
		t.Fatal(err)
	}
	frozen, end := f.frozen(t)
	f.policy.TTL = 45 * time.Second
	unknown := &aPublicationExecACK{db: f.db, lose: true}
	returned, err := c.RenewClaimInInstallation(f.ctx, unknown, f.installation, token, f.policy)
	if !errors.Is(err, errAPublicationACKLost) || returned != (c.ClaimToken{}) {
		t.Fatal("ambiguous actual Renew returned a token", err)
	}
	f.checkClaimReadback(t, token.RowVersion+1)
	f.checkReceipts(t, 1)
	f.reject(t, token, first)
	if _, err = f.x.service.PublicationSignersForTask(f.ctx, returned); err == nil {
		t.Fatal("unknown renew ACK became a manufactured signing token")
	}
	if got, until := f.frozen(t); !bytes.Equal(got, frozen) || !until.Equal(end) {
		t.Fatal("unknown Renew ACK changed original frozen input")
	}
	// Recovery scheduling from this authoritative observation belongs to D;
	// this test deliberately does not mint a token or issue a fresh-version CAS.
}
