package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/golang-jwt/jwt/v5"
)

// Atomic, scripted SQL transport ONLY. JWT/Ed25519, A session/RBAC parsing and
// the actual D orchestration/SQL execute; owner/capacity facts are synthetic.
// It does not prove InnoDB locks/FK, physical capacity or production readiness.
type admissionTxRows struct {
	data         [][]driver.Value
	width, index int
}

func (r *admissionTxRows) Columns() []string { return make([]string, r.width) }
func (*admissionTxRows) Close() error        { return nil }
func (r *admissionTxRows) Next(dest []driver.Value) error {
	if r.index >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.index])
	r.index++
	return nil
}
func admissionTxRow(values ...driver.Value) driver.Rows {
	return &admissionTxRows{width: len(values), data: [][]driver.Value{values}}
}

type admissionTxSnapshot struct {
	record                 Record
	op, receipt, nonce     []driver.Value
	body                   []byte
	user, resource         driver.Value
	action, kind           string
	created, consumed      time.Time
	reserved, activeConfig int64
	sample                 time.Time
	resultBody             []byte
	resultCreated          time.Time
	resultRetention        []driver.Value
}
type admissionTxDB struct {
	*downloadAuditDB
	m                                                       *admissionRecordsModel
	record                                                  Record
	config                                                  sec.ConfigValues
	configCells                                             map[string]driver.Value
	nonce                                                   []driver.Value
	consumed                                                time.Time
	saved                                                   admissionTxSnapshot
	reserved, activeConfig                                  int64
	sample                                                  time.Time
	active, installationLocked, ownerLocked, evidenceLocked bool
	opKeyLocked                                             bool
	fault                                                   string
	preConsumed                                             string
	identity                                                sec.DatabaseIdentity
	sessionUntil                                            time.Time
	revokedBefore                                           time.Time
	committedOrigin                                         *string
	retainedVersions                                        []string
	sessionRevoked, userActive                              bool
	password                                                string
	credential, role                                        string
	commitUnknown, commitLate                               bool
	commitAttempts                                          int
	faultSeen                                               bool
	calls                                                   []string
	queries                                                 []string
	proof                                                   sec.SensitiveDownloadProofVerification
	resultBody                                              []byte
	resultCreated                                           time.Time
	resultInserts                                           int
	resultRetention                                         []driver.Value
	resultRetentionReads                                    int
	resultRetentionLocked                                   bool
	groupReads                                              map[string]int
	groupMutate                                             func(string, int, []driver.Value) []driver.Value
	groupFault                                              string
	ownerQuery                                              func(context.Context, string, []driver.NamedValue) (driver.Rows, bool, error)
}

func (d *admissionTxDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *admissionTxDB) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if d.active || opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || opts.ReadOnly {
		d.t.Fatal("wrong transaction ownership")
	}
	d.begins++
	d.active = true
	d.installationLocked, d.ownerLocked, d.evidenceLocked, d.opKeyLocked = false, false, false, false
	d.resultRetentionLocked, d.resultRetentionReads = false, 0
	d.groupReads = make(map[string]int)
	d.saved = admissionTxSnapshot{record: d.record, op: append([]driver.Value(nil), d.m.op...), receipt: append([]driver.Value(nil), d.m.receipt...), nonce: append([]driver.Value(nil), d.nonce...), body: append([]byte(nil), d.body...), user: d.user, resource: d.resource, action: d.action, kind: d.kind, created: d.created, consumed: d.consumed, reserved: d.reserved, activeConfig: d.activeConfig, sample: d.sample}
	d.saved.resultBody, d.saved.resultCreated = append([]byte(nil), d.resultBody...), d.resultCreated
	d.saved.resultRetention = append([]driver.Value(nil), d.resultRetention...)
	d.calls = append(d.calls, "begin")
	return d, nil
}
func (d *admissionTxDB) Commit() error {
	d.commitAttempts++
	d.commits++
	d.active = false
	d.calls = append(d.calls, "commit")
	if d.commitLate {
		time.Sleep(30 * time.Millisecond)
	}
	if d.commitUnknown {
		return errors.New("PRIVATE commit reply lost")
	}
	return nil
}
func (d *admissionTxDB) Rollback() error {
	d.rollbacks++
	d.active = false
	d.calls = append(d.calls, "rollback")
	s := d.saved
	d.record = s.record
	d.m.op, d.m.receipt, d.nonce = s.op, s.receipt, s.nonce
	d.body, d.user, d.resource, d.action, d.kind, d.created, d.consumed, d.reserved, d.activeConfig = s.body, s.user, s.resource, s.action, s.kind, s.created, s.consumed, s.reserved, s.activeConfig
	d.sample = s.sample
	d.resultBody, d.resultCreated = s.resultBody, s.resultCreated
	d.resultRetention = s.resultRetention
	d.m.f.Record = d.record
	return nil
}
func (d *admissionTxDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d.queries = append(d.queries, q)
	if !d.active {
		d.t.Fatal("SQL outside original transaction")
	}
	// The closed metadata query contains a regex quantifier inside a SQL string
	// literal, not a bind marker. Its interceptor separately requires no args.
	if q != taskDownloadReferenceColumnsSQL && strings.Count(q, "?") != len(args) {
		return nil, fmt.Errorf("query placeholder mismatch: %s", q)
	}
	if d.ownerQuery != nil {
		if rows, ok, err := d.ownerQuery(ctx, q, args); ok {
			return rows, err
		}
	}
	if rows, ok, err := d.retentionGroupQuery(q, args); ok {
		return rows, err
	}
	switch {
	case q == downloadResultRetentionKeySQL:
		if !d.opKeyLocked || d.ownerLocked || args[0].Value != int64(73) {
			return nil, errors.New("result retention key outside L3")
		}
		d.calls = append(d.calls, "result-retention-key")
		if d.fault == "result_retention_key" {
			return nil, errors.New("PRIVATE retention key")
		}
		d.resultRetentionLocked = true
		if len(d.resultRetention) != 0 {
			return admissionTxRow(d.resultRetention[0]), nil
		}
		return &admissionTxRows{width: 1}, nil
	case q == downloadResultRetentionReadSQL:
		d.resultRetentionReads++
		if args[0].Value != int64(73) || !d.resultRetentionLocked || d.fault == "result_retention_read" {
			return nil, errors.New("PRIVATE retention read")
		}
		if len(d.resultRetention) == 0 || d.fault == "result_retention_missing" {
			return &admissionTxRows{width: 11}, nil
		}
		values := append([]driver.Value(nil), d.resultRetention...)
		for _, prefix := range []string{"result_retention_corrupt_", "result_retention_final_"} {
			if !strings.HasPrefix(d.fault, prefix) || prefix == "result_retention_final_" && d.resultRetentionReads < 2 {
				continue
			}
			index, err := strconv.Atoi(strings.TrimPrefix(d.fault, prefix))
			if err != nil || index < 0 || index >= len(values) {
				return nil, errors.New("invalid retention test fault")
			}
			switch v := values[index].(type) {
			case int64:
				values[index] = v + 1
			case string:
				values[index] = v + "changed"
			case time.Time:
				values[index] = v.Add(-time.Microsecond)
			}
		}
		return admissionTxRow(values...), nil
	case q == downloadResultActorSQL:
		d.calls = append(d.calls, "result-actor")
		if d.fault == "result_actor" {
			return &admissionTxRows{width: 1}, nil
		}
		return admissionTxRow(int64(42)), nil
	case q == downloadResultReadSQL && len(args) == 1 && args[0].Value == int64(1730):
		if d.fault == "result_read" {
			return nil, errors.New("PRIVATE result read")
		}
		body := append([]byte(nil), d.resultBody...)
		created := d.resultCreated
		if d.fault == "result_body" {
			body = []byte(`{"changed":true}`)
		}
		if d.fault == "result_time" {
			created = created.Add(time.Second)
		}
		return admissionTxRow(int64(42), "system_backup.evidence_download.result", "system_backup", nil, body, created), nil
	case q == downloadResultReleaseReadSQL:
		return admissionTxRow(d.record.Manifest.Identity.Installation, d.record.RowVersion, nullString(d.record.Claim), nullTime(d.record.ClaimUntil)), nil
	case q == "SELECT @@server_uuid,DATABASE()":
		return admissionTxRow(d.identity.ServerUUID, d.identity.Database), nil
	case strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)"):
		return admissionTxRow(d.identity.ServerUUID, d.identity.Database, d.now, int64(0)), nil
	case q == "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE":
		d.installationLocked = true
		d.calls = append(d.calls, "L0")
		return admissionTxRow(d.record.Manifest.Identity.Installation), nil
	case strings.HasPrefix(q, "SELECT active_config_version FROM system_backup_v2_installation_state"):
		if !d.installationLocked {
			d.t.Fatal("config before L0")
		}
		return admissionTxRow(d.activeConfig), nil
	case strings.HasPrefix(q, "SELECT nonce_hmac_ref_version FROM system_backup_v2_configs WHERE"):
		return admissionTxRow("v2"), nil
	case strings.HasPrefix(q, "SELECT nonce_hmac_ref_version FROM system_backup_v2_configs"):
		if d.retainedVersions != nil {
			out := &admissionTxRows{width: 1}
			for _, v := range d.retainedVersions {
				out.data = append(out.data, []driver.Value{v})
			}
			return out, nil
		}
		return &admissionTxRows{width: 1, data: [][]driver.Value{{"v1"}, {"v2"}}}, nil
	case q == "SELECT DISTINCT nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs ORDER BY nonce_hmac_ref_version,nonce_hmac_identity_hash":
		return &admissionTxRows{width: 2, data: [][]driver.Value{{"v1", hash([]byte("old-nonce-identity"))}, {"v2", d.configCells["nonce_hmac_identity_hash"]}}}, nil
	case strings.HasPrefix(q, "SELECT schema_version,version,row_version,canonical_config_json"):
		if d.fault == "canonical_missing" {
			d.faultSeen = true
			return admissionTxRow("system-backup-config.v1", int64(1), int64(1), nil, d.config.SHA256(), int64(len(d.config.CanonicalJSON()))), nil
		}
		return admissionTxRow("system-backup-config.v1", d.activeConfig, int64(1), d.config.CanonicalJSON(), d.config.SHA256(), int64(len(d.config.CanonicalJSON()))), nil
	case q == "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?":
		return admissionTxRow(d.record.Manifest.Identity.OwnerType, d.record.Manifest.Identity.OwnerID), nil
	case strings.HasPrefix(q, "SELECT config_sha256,rbac_bindings_registry_version"):
		return admissionTxRow(d.config.SHA256(), d.configCells["rbac_bindings_registry_version"], d.configCells["rbac_bindings_registry_sha256"], d.configCells["evidence_store_identity_hash"], d.configCells["evidence_store_ref_version"], d.configCells["evidence_read_identity_hash"], d.configCells["evidence_read_ref_version"]), nil
	case q == "SELECT UTC_TIMESTAMP(6)":
		return admissionTxRow(d.now), nil
	case strings.HasSuffix(q, "FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE"):
		columns := strings.Split(strings.TrimPrefix(strings.Split(q, " FROM ")[0], "SELECT "), ",")
		values := make([]driver.Value, len(columns))
		for i, k := range columns {
			v, ok := d.configCells[k]
			if !ok {
				d.t.Log("unmodeled independent config projection", k)
				return nil, fmt.Errorf("unmodeled config column %s", k)
			}
			values[i] = v
		}
		if d.fault == "materialized_drift" {
			d.faultSeen = true
			values[0] = !d.config.Enabled()
		}
		return admissionTxRow(values...), nil
	case strings.HasPrefix(q, "SELECT password_hash FROM users"):
		if !d.userActive || d.role != "admin" {
			return &admissionTxRows{width: 1}, nil
		}
		return admissionTxRow(d.password), nil
	case strings.HasPrefix(q, "SELECT user_id,subject,credential_hash,expires_at,revoked,UTC_TIMESTAMP(6)"):
		return admissionTxRow(int64(42), "user:42", d.credential, d.sessionUntil, d.sessionRevoked, d.now), nil
	case strings.HasPrefix(q, "SELECT revoked_before FROM system_backup_v2_admin_revocations"):
		if !d.revokedBefore.IsZero() {
			return admissionTxRow(d.revokedBefore), nil
		}
		return &admissionTxRows{width: 1}, nil
	case q == downloadCommittedOwnerSQL:
		var origin driver.Value = d.record.Manifest.Identity.Installation
		if d.committedOrigin != nil {
			if *d.committedOrigin == "" {
				origin = nil
			} else {
				origin = *d.committedOrigin
			}
		}
		return admissionTxRow(origin, d.record.Manifest.Identity.OwnerType, d.record.Manifest.Identity.OwnerID), nil
	case q == downloadAdmissionKeySQL:
		d.opKeyLocked = true
		d.calls = append(d.calls, "L3")
		if len(d.m.op) > 0 && d.m.op[1] == args[0].Value && d.m.op[4] == args[1].Value && d.m.op[5] == args[2].Value {
			return admissionTxRow(int64(73), d.m.op[6]), nil
		}
		return &admissionTxRows{width: 2}, nil
	case q == downloadAdmissionNonceCandidateReadSQL:
		if !d.ownerLocked {
			d.t.Fatal("nonce before owner/ref locks")
		}
		if d.nonce == nil {
			d.calls = append(d.calls, "L5")
		}
		if len(d.nonce) > 0 && args[0].Value == d.nonce[4] && args[1].Value == d.nonce[5] {
			return admissionTxRow(int64(95)), nil
		}
		for _, c := range d.proof.NonceCandidates() {
			if d.preConsumed == c.KeyVersion && args[0].Value == c.HMAC && args[1].Value == c.KeyVersion {
				return admissionTxRow(int64(94)), nil
			}
		}
		return &admissionTxRows{width: 1}, nil
	case q == downloadAdmissionInstallationSQL:
		publicCleanup := oneOf(d.record.Manifest.Identity.Classification, "public", "internal")
		if !d.ownerLocked || !publicCleanup && (d.reserved == 0 || len(d.body) == 0) {
			// Public claim cleanup adds neither admission nor an audit row. Return
			// driver errors instead of Goexit while database/sql holds its lock.
			return nil, fmt.Errorf("evidence locked before required prefix/capacity/audit")
		}
		d.evidenceLocked = true
		d.calls = append(d.calls, "L9")
		if d.fault == "legacy_installation" {
			d.faultSeen = true
			return admissionTxRow(nil), nil
		}
		return admissionTxRow(d.record.Manifest.Identity.Installation), nil
	case q == downloadAdmissionEvidenceAnchorSQL:
		r := d.record
		return admissionTxRow(int64(61), r.Manifest.Identity.Installation, r.RowVersion, nullString(r.Claim), nullTime(r.ClaimUntil), nullTime(r.ProtectedUntil), r.State), nil
	case strings.HasPrefix(q, "SELECT id,owner_target_type"):
		r := d.record
		m := r.Manifest
		i := m.Identity
		return admissionTxRow(int64(61), i.OwnerType, i.OwnerID, i.Type, r.State, r.Failure, r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, r.Ref.ImmutableVersion, i.ContentHash, i.ContentSize,
			m.ObjectHash, m.ObjectSize, ChunkSize, int64(len(m.Chunks)), m.ChunkRoot, i.Media, "envelope_v1", m.Key.Identity, m.Key.Version, m.EnvelopeHash, i.Classification, nullString(r.Claim), nullTime(r.ClaimUntil), r.ExpiresAt, nullTime(r.ProtectedUntil), r.RowVersion, r.CreatedAt, "evidence", hash([]byte(r.Ref.RelativeKey)), Framing), nil
	case strings.Contains(q, "FROM system_backup_v2_evidence_chunks WHERE evidence_id=?"):
		rows := &admissionTxRows{width: 9}
		for _, c := range d.record.Manifest.Chunks {
			nonce, _ := base64.RawURLEncoding.DecodeString(c.Nonce)
			tag, _ := base64.RawURLEncoding.DecodeString(c.Tag)
			rows.data = append(rows.data, []driver.Value{c.Index, c.PlainOffset, c.PlainLength, c.PlainHash, c.FrameOffset, c.FrameLength, c.CipherHash, nonce, tag})
		}
		return rows, nil
	case q == downloadAdmissionNonceReadSQL:
		if d.fault == "nonce_read" {
			d.faultSeen = true
			return nil, errors.New("PRIVATE nonce read")
		}
		if len(d.nonce) < 13 {
			return &admissionTxRows{width: 2}, nil
		}
		want := append([]driver.Value{int64(95)}, d.nonce[:13]...)
		if !reflect.DeepEqual(admissionValues(args), want) {
			return &admissionTxRows{width: 2}, nil
		}
		return admissionTxRow(d.consumed, d.consumed), nil
	case q == "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE":
		return admissionTxRow(d.reserved), nil
	case q == "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE":
		return admissionTxRow(d.sample, d.reserved), nil
	}
	d.m.f.Record = d.record
	switch q {
	case downloadIntentClockSQL, downloadIntentReadSQL:
		return d.downloadAuditDB.QueryContext(ctx, q, args)
	case downloadAdmissionTombstoneSQL, downloadAdmissionReceiptKeySQL, downloadAdmissionOperationReadSQL, downloadAdmissionReceiptReadSQL:
		if q == downloadAdmissionOperationReadSQL {
			d.opKeyLocked = true
			d.calls = append(d.calls, "operation-read")
		}
		if q == downloadAdmissionReceiptReadSQL {
			d.calls = append(d.calls, "receipt-read")
		}
		return d.m.query(q, args)
	}
	d.t.Log("unmodeled transaction query", q)
	return nil, errors.New("unmodeled transaction query")
}
func (d *admissionTxDB) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !d.active {
		d.t.Fatal("mutation outside transaction")
	}
	if strings.Count(q, "?") != len(args) {
		d.t.Fatal("mutation placeholder mismatch", q, len(args))
	}
	if strings.HasPrefix(q, "UPDATE system_backup_v2_evidence SET storage_state=?,evidence_failure_code=?,storage_immutable_version=?,claim_owner=?,claim_expires_at=?,expires_at=?,protected_until=?") {
		if len(args) != 9 || args[7].Value != d.record.Manifest.Identity.ID || args[8].Value != d.record.RowVersion {
			return admissionRecordsResult{rows: 0}, nil
		}
		d.record.State = args[0].Value.(string)
		d.record.Failure = args[1].Value.(string)
		d.record.Claim = ""
		d.record.ClaimUntil = time.Time{}
		if args[3].Value != nil {
			d.record.Claim = args[3].Value.(string)
		}
		if args[4].Value != nil {
			d.record.ClaimUntil = args[4].Value.(time.Time)
		}
		d.record.RowVersion++
		return admissionRecordsResult{rows: 1}, nil
	}
	switch q {
	case downloadResultRetentionInsertSQL:
		if !d.resultRetentionLocked || !d.ownerLocked || len(d.resultBody) == 0 || len(d.resultRetention) != 0 || args[0].Value != int64(73) || args[6].Value != int64(1730) || args[7].Value != int64(len(d.resultBody)) || args[8].Value != hash(d.resultBody) {
			return nil, errors.New("result retention missing lock, audit or exact body")
		}
		d.calls = append(d.calls, "result-retention-insert")
		if d.fault == "result_retention_insert" {
			return nil, errors.New("PRIVATE retention INSERT")
		}
		d.resultRetention = admissionValues(args)
		result := admissionRecordsResult{rows: 1}
		if d.fault == "result_retention_zero" {
			result.rows = 0
		}
		if d.fault == "result_retention_multiple" {
			result.rows = 2
		}
		result.rowsError = d.fault == "result_retention_rows_error"
		return result, nil
	case downloadResultInsertSQL:
		d.resultInserts++
		d.calls = append(d.calls, "result-audit")
		if d.fault == "result_insert" {
			return nil, errors.New("PRIVATE result INSERT")
		}
		d.resultBody = append([]byte(nil), args[1].Value.([]byte)...)
		d.resultCreated = args[2].Value.(time.Time)
		id, rows := int64(1730), int64(1)
		if d.fault == "result_id" {
			id = 0
		}
		if d.fault == "result_zero" {
			rows = 0
		}
		return admissionRecordsResult{rows: rows, id: id}, nil
	case downloadResultReleaseSQL:
		d.calls = append(d.calls, "result-release")
		if d.fault == "release_sql" {
			return nil, errors.New("PRIVATE release SQL")
		}
		if d.fault == "release_multiple" {
			return admissionRecordsResult{rows: 2}, nil
		}
		if d.fault == "release_not_applied" {
			return admissionRecordsResult{rows: 1}, nil
		}
		r := d.record
		i := r.Manifest.Identity
		if args[0].Value != int64(61) || args[1].Value != i.ID || args[2].Value != i.Installation || args[3].Value != i.OwnerType || args[4].Value != i.OwnerID || args[5].Value != r.RowVersion || args[6].Value != r.Claim || args[7].Value != r.ClaimUntil || d.committedOrigin != nil || r.RowVersion >= 9007199254740991 {
			return admissionRecordsResult{rows: 0}, nil
		}
		d.record.Claim = ""
		d.record.ClaimUntil = time.Time{}
		d.record.RowVersion++
		return admissionRecordsResult{rows: 1}, nil
	case "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)":
		if d.sample.IsZero() {
			d.sample = args[0].Value.(time.Time)
		}
		return admissionRecordsResult{rows: 1}, nil
	case "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?":
		if !d.ownerLocked || !d.sample.Equal(args[1].Value.(time.Time)) || d.reserved != args[2].Value {
			return admissionRecordsResult{rows: 0}, nil
		}
		d.reserved += args[0].Value.(int64)
		d.calls = append(d.calls, "L6")
		return admissionRecordsResult{rows: 1}, nil
	case "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND reserved_bytes=?":
		if !d.ownerLocked || args[1].Value != d.reserved {
			d.t.Fatal("reservation order/CAS")
		}
		d.reserved += args[0].Value.(int64)
		d.calls = append(d.calls, "L6")
		return admissionRecordsResult{rows: 1}, nil
	case downloadAdmissionClaimCASSQL:
		if !d.evidenceLocked || len(d.body) == 0 {
			d.t.Fatal("claim before audit/evidence")
		}
		d.calls = append(d.calls, "claim")
		if d.fault == "claim_sql" {
			d.faultSeen = true
			return nil, errors.New("PRIVATE claim CAS")
		}
		if d.fault == "claim_cas" {
			d.faultSeen = true
			return admissionRecordsResult{rows: 0}, nil
		}
		if d.record.State != "ready" || d.record.Failure != "none" || args[2].Value != d.record.Manifest.Identity.ID || args[3].Value != d.record.Manifest.Identity.Installation ||
			args[4].Value != d.record.RowVersion || args[5].Value != nullString(d.record.Claim) || !reflect.DeepEqual(args[6].Value, nullTime(d.record.ClaimUntil)) || d.record.Claim != "" && d.now.Before(d.record.ClaimUntil) {
			return admissionRecordsResult{rows: 0}, nil
		}
		if d.now.Before(args[7].Value.(time.Time)) || !d.now.Before(args[8].Value.(time.Time)) || !d.now.Before(args[9].Value.(time.Time)) || !d.now.Before(args[10].Value.(time.Time)) {
			return admissionRecordsResult{rows: 0}, nil
		}
		d.record.Claim, d.record.ClaimUntil, d.record.RowVersion = args[0].Value.(string), args[1].Value.(time.Time), d.record.RowVersion+1
		d.m.f.Record = d.record
		return admissionRecordsResult{rows: 1}, nil
	case downloadAdmissionNonceInsertSQL:
		d.calls = append(d.calls, "nonce")
		if d.fault == "nonce_insert" {
			d.faultSeen = true
			return nil, errors.New("PRIVATE nonce insert")
		}
		if d.fault == "nonce_zero" {
			d.faultSeen = true
			return admissionRecordsResult{rows: 0}, nil
		}
		if len(d.m.op) == 0 || len(d.m.receipt) == 0 || args[10].Value != int64(73) || args[11].Value != d.id {
			d.t.Fatal("nonce uses unrelated IDs")
		}
		if d.now.Before(args[13].Value.(time.Time)) || !d.now.Before(args[14].Value.(time.Time)) || !d.now.Before(args[15].Value.(time.Time)) {
			return admissionRecordsResult{rows: 0}, nil
		}
		if args[8].Value != d.proof.ProofAcceptedAt() || args[1].Value != d.proof.IssuerSHA256() {
			d.t.Fatal("nonce uses signed auth_time or wrong issuer")
		}
		d.nonce, d.consumed = admissionValues(args), d.now
		return admissionRecordsResult{rows: 1, id: 95}, nil
	}
	if q == downloadIntentInsertSQL {
		d.calls = append(d.calls, "audit")
	}
	result, err := d.downloadAuditDB.ExecContext(ctx, q, args)
	if q == downloadIntentInsertSQL && err == nil {
		var body map[string]any
		if json.Unmarshal(d.body, &body) != nil {
			d.t.Fatal("invalid actual intent")
		}
		d.m.f.Intent.OperationID = body["operation_public_id"].(string)
		d.m.f.Intent.EvidenceID = body["evidence_id"].(string)
		d.m.f.Intent.Installation = body["origin_installation_id"].(string)
	}
	return result, err
}

type admissionTxEnvironment struct {
	db                                                           *admissionTxDB
	sessions                                                     *sec.SQLLoginSessions
	cfg                                                          sec.VerifyConfig
	actor                                                        sec.RegistrationActor
	hint                                                         Record
	rbac                                                         []byte
	rbacHash, rbacVersion                                        string
	validUntil, minimumRetention, reservationUntil               time.Time
	guards, closes                                               int
	prepares, owners, reserves, capacityChecks                   int
	onPrepare, onOwner, onReserve, onGuard                       func()
	denyPrepare, denyOwner, denyReserve, denyGuard, denyCapacity bool
}

func (e *admissionTxEnvironment) Prepare(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, c *sec.SensitiveDownloadConfig, id string, versions []string) (PreparedDownloadAdmission, error) {
	e.prepares++
	if e.onPrepare != nil {
		e.onPrepare()
	}
	if e.denyPrepare {
		return nil, ErrDenied
	}
	if e.sessions.CheckConfigMutationSession(ctx, tx, e.hint.Manifest.Identity.Installation, actor, e.db.now) != nil {
		return nil, ErrDenied
	}
	if sec.AuthorizeEvidencePermissions(e.rbac, e.rbacHash, e.rbacVersion, e.hint.Manifest.Identity.Installation, actor, permissions(e.hint.Manifest.Identity.Classification)) != nil {
		return nil, ErrDenied
	}
	if id != e.hint.Manifest.Identity.ID || !reflect.DeepEqual(versions, []string{"v1", "v2"}) {
		return nil, ErrDownloadAdmissionNotReady
	}
	return e, nil
}
func (e *admissionTxEnvironment) Preview() Record               { return e.hint }
func (e *admissionTxEnvironment) Issuer() string                { return "issuer-transaction" }
func (e *admissionTxEnvironment) ProofConfig() sec.VerifyConfig { return e.cfg }
func (e *admissionTxEnvironment) ValidUntil() time.Time         { return e.validUntil }
func (e *admissionTxEnvironment) MinimumRetainUntil() time.Time { return e.minimumRetention }
func (e *admissionTxEnvironment) LockOwnerReferences(context.Context, *sql.Tx) error {
	e.owners++
	if e.onOwner != nil {
		e.onOwner()
	}
	if e.denyOwner {
		return ErrDenied
	}
	if !e.db.opKeyLocked {
		e.db.t.Fatal("owner before keys")
	}
	e.db.ownerLocked = true
	e.db.calls = append(e.db.calls, "L4")
	return nil
}
func (e *admissionTxEnvironment) Reserve(ctx context.Context, tx *sql.Tx, now time.Time) (DownloadAdmissionReservation, error) {
	e.reserves++
	if e.onReserve != nil {
		e.onReserve()
	}
	if e.denyReserve {
		return nil, ErrCapacity
	}
	if !downloadAdmissionOne(tx.ExecContext(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND reserved_bytes=?", int64(65536), e.db.reserved)) {
		return nil, ErrCapacity
	}
	return admissionTxReservation{e}, nil
}
func (e *admissionTxEnvironment) Recheck(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, r Record, now time.Time) error {
	e.guards++
	if e.onGuard != nil {
		e.onGuard()
	}
	if e.denyGuard {
		return ErrDenied
	}
	if e.sessions.CheckConfigMutationSession(ctx, tx, e.hint.Manifest.Identity.Installation, actor, now) != nil {
		return ErrDenied
	}
	if sec.AuthorizeEvidencePermissions(e.rbac, e.rbacHash, e.rbacVersion, e.hint.Manifest.Identity.Installation, actor, permissions(r.Manifest.Identity.Classification)) != nil {
		return ErrDenied
	}
	return nil
}
func (e *admissionTxEnvironment) Close() { e.closes++ }

type admissionTxReservation struct{ env *admissionTxEnvironment }

func (r admissionTxReservation) ValidUntil() time.Time { return r.env.reservationUntil }
func (r admissionTxReservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	r.env.capacityChecks++
	if r.env.denyCapacity {
		return ErrCapacity
	}
	var reserved int64
	if tx.QueryRowContext(ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&reserved) != nil || reserved < 65536 {
		return ErrCapacity
	}
	return nil
}

func admissionConfigFixture(t *testing.T, rbacHash string) (sec.ConfigValues, map[string]driver.Value) {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/evidence/a-config-canonical-request-vectors-20261014.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Input struct {
				Request struct {
					Config json.RawMessage `json:"config"`
				} `json:"request"`
			} `json:"input"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Vectors) == 0 {
		t.Fatal("missing complete canonical fixture")
	}
	return admissionConfigBytes(t, vectors.Vectors[0].Input.Request.Config, rbacHash)
}

func admissionConfigBytes(t *testing.T, raw []byte, rbacHash string) (sec.ConfigValues, map[string]driver.Value) {
	t.Helper()
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&doc) != nil {
		t.Fatal("bad config fixture")
	}
	for _, v := range doc["registries"].([]any) {
		r := v.(map[string]any)
		if r["registry_kind"] == "rbac_bindings" {
			r["version"], r["sha256"] = "v1", rbacHash
		}
	}
	for _, v := range doc["references"].([]any) {
		r := v.(map[string]any)
		if r["purpose"] == "nonce_hmac" {
			r["version"] = "v2"
		}
	}
	doc["enabled"] = false // retained-evidence admission is independent of backup scheduling
	return admissionConfigDocument(t, doc)
}

func admissionConfigDocument(t *testing.T, doc map[string]any) (sec.ConfigValues, map[string]driver.Value) {
	t.Helper()
	raw, _ := json.Marshal(doc)
	config, err := sec.DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	cells := map[string]driver.Value{}
	for k, v := range doc {
		switch x := v.(type) {
		case bool:
			cells[k] = x
		case string:
			cells[k] = x
		case json.Number:
			cells[k] = x.String()
		case map[string]any:
			for key, value := range x {
				if k == "preflight_limits" {
					key = "preflight_" + key
				}
				switch n := value.(type) {
				case json.Number:
					cells[key] = n.String()
				case string:
					cells[key] = n
				case bool:
					cells[key] = n
				}
			}
		}
	}
	for _, r := range config.Registries() {
		cells[r.Kind+"_registry_version"], cells[r.Kind+"_registry_sha256"] = r.Version, r.SHA256
	}
	for _, r := range config.References() {
		cells[r.Purpose+"_identity_hash"], cells[r.Purpose+"_ref_version"] = r.IdentityHash, r.Version
	}
	return config, cells
}

type admissionTxFixture struct {
	service *DownloadAdmissionService
	db      *admissionTxDB
	env     *admissionTxEnvironment
	request *http.Request
	initial Record
	secret  []byte
	proof   sec.Proof
}

func newAdmissionTxFixture(t *testing.T) *admissionTxFixture {
	return newAdmissionTxFixtureWithConfig(t, admissionConfigFixture)
}

func newAdmissionTxFixtureWithConfig(t *testing.T, configFactory func(*testing.T, string) (sec.ConfigValues, map[string]driver.Value)) *admissionTxFixture {
	t.Helper()
	m, h := sensitiveDownloadManifestFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	secret := bytes.Repeat([]byte{7}, 32)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": "admission-test"}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://local"+Path+m.Identity.ID, nil)
	request.TLS = &tls.ConnectionState{}
	request.Header = h.Clone()
	request.Header.Set("Authorization", "Bearer "+token)
	actor, err := (sec.JWTRegistrationAuthenticator{Secret: secret}).Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	rbac := []byte(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"v1","installation_id":"` + m.Identity.Installation + `","bindings":[{"actor_id":"42","subject":"user:42","role":"security_admin"}]}`)
	config, cells := configFactory(t, hash(rbac))
	r := Record{Manifest: m, Ref: Ref{Identity: hash([]byte("store")), Version: "v1", RelativeKey: "evidence/immutable-object", ImmutableVersion: "v1"}, State: "ready", Failure: "none", RowVersion: 6, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), ProtectedUntil: now.Add(2 * time.Hour), OwnerDeadline: now.Add(time.Hour)}
	d := &admissionTxDB{downloadAuditDB: &downloadAuditDB{t: t, id: 1729, affected: 1, now: now}, record: r, config: config, configCells: cells, activeConfig: 1, identity: sec.DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "admission_test"}, sessionUntil: actor.SessionExpiresAt, userActive: true, password: "synthetic-current-password", credential: hash([]byte("synthetic-current-password")), role: "admin"}
	d.m = &admissionRecordsModel{t: t, d: d.downloadAuditDB, f: DownloadAdmissionContentFacts{Actor: actor, Record: r, Intent: DownloadAdmissionIntent{Installation: m.Identity.Installation, EvidenceID: m.Identity.ID}}}
	d.extraQuery, d.extraExec = d.m.query, d.m.exec
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	sessions, err := sec.NewSQLLoginSessions(db, d.identity, m.Identity.Installation, secret)
	if err != nil {
		t.Fatal(err)
	}
	e := &admissionTxEnvironment{db: d, sessions: sessions, actor: actor, hint: r, rbac: rbac, rbacHash: hash(rbac), rbacVersion: "v1", validUntil: now.Add(2 * time.Minute), minimumRetention: now.Add(3 * time.Hour), reservationUntil: now.Add(5 * time.Second)}
	registry := SQLRegistry{DB: db, Installation: m.Identity.Installation, ServerUUID: d.identity.ServerUUID, Database: d.identity.Database, Policy: &downloadTestPolicy{deadline: r.OwnerDeadline}}
	svc, err := NewDownloadAdmissionService(registry, secret, e)
	if err != nil {
		t.Fatal(err)
	}
	f := &admissionTxFixture{service: svc, db: d, env: e, request: request, initial: r, secret: secret}
	f.sign(t, request.Header.Get("Idempotency-Key"), now.Add(-time.Minute), now.Add(time.Minute))
	return f
}
func (f *admissionTxFixture) sign(t *testing.T, key string, auth, expiry time.Time) {
	t.Helper()
	f.request.Header.Set("Idempotency-Key", key)
	r, err := BindSensitiveDownloadRequest(f.env.actor, f.initial.Manifest, f.request.Header)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.ProofBinding("issuer-transaction")
	p := sec.Proof{SchemaVersion: sec.ProofSchemaVersion, Payload: sec.ProofPayload{Issuer: b.Issuer, Audience: b.Audience, Subject: b.Subject, Session: b.Session, Endpoint: b.Endpoint, RequestHash: b.RequestHash, IdempotencyKey: b.IdempotencyKey,
		AuthTime: auth.Format(time.RFC3339Nano), ExpiresAt: expiry.Format(time.RFC3339Nano), Method: "totp", AMR: []string{"pwd", "otp"}, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	v := sec.Ed25519JWSVerifier{PublicKey: private.Public().(ed25519.PublicKey), KeyID: "admission-key", KeyVersion: "v1", Purpose: "strong_auth_issuer"}
	header := `{"alg":"EdDSA","key_version":"v1","kid":"admission-key","purpose":"strong_auth_issuer","typ":"` + sec.DomainSeparator + `"}`
	p.Signature = sec.ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: v.KeyID, KeyVersion: "v1", DomainSeparator: sec.DomainSeparator, ProtectedHeader: base64.RawURLEncoding.EncodeToString([]byte(header))}
	payload, err := sec.CanonicalPayload(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	raw, _ := json.Marshal(p)
	f.request.Header.Set(sec.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
	maxAge, ageErr := strconv.ParseInt(f.db.configCells["strong_auth_max_age_seconds"].(string), 10, 64)
	skew, skewErr := strconv.ParseInt(f.db.configCells["strong_auth_clock_skew_seconds"].(string), 10, 64)
	if ageErr != nil || skewErr != nil {
		t.Fatal("invalid independent time policy fixture")
	}
	f.env.cfg = sec.VerifyConfig{Now: f.db.now, MaxAge: time.Duration(maxAge) * time.Second, ClockSkew: time.Duration(skew) * time.Second, ExpectedAudience: b.Audience, ExpectedSubject: b.Subject, ExpectedSession: b.Session,
		TrustedSigners: map[string]map[string]sec.SignatureVerifier{b.Issuer: {"v1": v}}, TrustedIssuerPolicies: map[string]sec.IssuerPolicy{b.Issuer: {Methods: []string{"totp"}, AMR: []string{"pwd", "otp"}}},
		NonceHMACKeys: map[string][]byte{"v1": bytes.Repeat([]byte{0x11}, 32), "v2": bytes.Repeat([]byte{0x22}, 32)}, ActiveNonceHMACKeyVersion: "v2", RequiredNonceHMACKeyVersions: []string{"v1", "v2"}}
	f.db.proof, err = VerifySensitiveDownloadRequestHeader(f.env.actor, f.initial.Manifest, f.request.Header, b.Issuer, f.env.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.db.m.f.Proof = f.db.proof
	f.proof = p
}
