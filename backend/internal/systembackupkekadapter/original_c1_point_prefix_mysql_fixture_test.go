//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	ev "clawreef/internal/systembackupevidence"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	pd "clawreef/internal/systembackupproducer"
)

// Every source/permission/signature here is explicitly TEST COMPARISON DATA.
// Only SQL, the real mixed reader/helper, the real authority writer, locks,
// connection identities and independent readbacks are native. No opaque
// producer/closure/history/coverage/adoption authority is manufactured.
type aPointNativeFixture struct {
	db       *sql.DB
	database reg.DatabaseIdentity
	record   OriginalRecord
	key      ed25519.PrivateKey
	writer   *InstallationAuthorityWriter
	raw, sig []byte
	caps     []OriginalRuntimeCapabilityImport
	c1       *OriginalC1SQLSnapshot
	want     RuntimeInstalledSQLSnapshot
	chunkIDs []int64
	evidence int64
	publicID string
}

type aPointNativeExec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func aPointNativeInsert(t *testing.T, ctx context.Context, db aPointNativeExec, table string, row map[string]any) int64 {
	t.Helper()
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	columns, marks, args := []string{}, []string{}, []any{}
	for _, key := range keys {
		columns, marks, args = append(columns, "`"+key+"`"), append(marks, "?"), append(args, row[key])
	}
	r, err := db.ExecContext(ctx, "INSERT INTO `"+table+"` ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
	if err != nil {
		t.Fatal("native TEST row insert", table, err)
	}
	id, err := r.LastInsertId()
	if err != nil {
		t.Fatal("native inserted ID", table, err)
	}
	return id
}

func aPointNativeChunk(t *testing.T, ctx context.Context, db aPointNativeExec, evidence int64, index int) int64 {
	t.Helper()
	return aPointNativeInsert(t, ctx, db, "system_backup_v2_evidence_chunks", map[string]any{
		"evidence_id": evidence, "chunk_index": index, "plaintext_offset": index,
		"plaintext_length": 1, "plaintext_sha256": coveragePayloadSHA([]byte("model plain")),
		"object_frame_offset": index, "object_frame_length": 1,
		"ciphertext_sha256": coveragePayloadSHA([]byte("model cipher")),
		"gcm_nonce":         []byte("model-nonce!"), "gcm_tag": []byte("model-tag-00001!"),
	})
}

// SQL-valid external evidence shape only, not real encryption/publication.
func aPointNativeEvidence(t *testing.T, ctx context.Context, db aPointNativeExec, installation, public string, chunks int, now time.Time) int64 {
	t.Helper()
	return aPointNativeInsert(t, ctx, db, "system_backup_v2_evidence", map[string]any{
		"public_id": public, "owner_target_type": "system", "owner_target_public_id": installation,
		"evidence_type": "capability_snapshot", "storage_state": "ready", "evidence_failure_code": "none",
		"storage_provider_role": "evidence", "storage_identity_hash": strings.Repeat("1", 64),
		"storage_ref_version": "model-v1", "storage_relative_key": "native-comparison/" + public,
		"storage_relative_key_hash": coveragePayloadSHA([]byte("native-comparison/" + public)),
		"storage_immutable_version": "model-version-1", "content_checksum": coveragePayloadSHA([]byte("model plain")),
		"content_size_bytes": chunks, "object_checksum": coveragePayloadSHA([]byte("model cipher")), "object_size_bytes": chunks,
		"plaintext_chunk_size_bytes": 1048576, "chunk_count": chunks, "chunk_list_root": strings.Repeat("2", 64),
		"media_type": "application/json", "encryption": "envelope_v1", "envelope_framing_version": "system-backup-evidence-envelope.v1",
		"kek_identity_hash": strings.Repeat("3", 64), "kek_version": "model-v1", "envelope_hash": strings.Repeat("4", 64),
		"redaction_classification": "internal", "observed_health": "healthy", "expires_at": now.Add(time.Hour),
		"protected_until": now.Add(time.Hour), "row_version": 3, "created_at": now, "updated_at": now,
	})
}

func aPointNativeModelRecords(t *testing.T, ctx context.Context, db *sql.DB, scope pd.Scope) ev.OriginalC1EvidenceFacts {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal("original HEAD contract fixture required", err)
	}
	var vectors struct {
		Records []struct {
			Definition string
			Value      json.RawMessage
		}
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("contract record fixtures")
	}
	facts := ev.OriginalC1EvidenceFacts{References: make([]pd.ReferenceRecord, 1), Commands: make([]pd.CommandReceiptRecord, 1)}
	destinations := map[string]any{
		"DomainRecord": &facts.Domain, "GrantRecord": &facts.Grant, "RunRecord": &facts.Run,
		"TargetRecord": &facts.Target, "HistoricalBindingRecord": &facts.History, "ReceiptRecord": &facts.Receipt,
		"CommandReceiptRecord": &facts.Commands[0], "ReferenceRecord": &facts.References[0],
	}
	seen := map[string]bool{}
	for _, v := range vectors.Records {
		out := destinations[v.Definition]
		if out == nil || seen[v.Definition] {
			continue
		}
		var tree any
		if json.Unmarshal(v.Value, &tree) != nil {
			t.Fatal("contract tree")
		}
		// Re-scope this new TEST data to the actual disposable SQL identity.
		// The contract's synthetic records grant no native owner authority.
		var replace func(any) any
		replace = func(value any) any {
			switch x := value.(type) {
			case string:
				switch x {
				case "11111111-2222-4333-8444-555555555555":
					return string(scope.ServerUUID)
				case "synthetic_backup":
					return string(scope.Database)
				case "installation_synthetic":
					return string(scope.Installation)
				}
			case map[string]any:
				for k, value := range x {
					x[k] = replace(value)
				}
			case []any:
				for k, value := range x {
					x[k] = replace(value)
				}
			}
			return value
		}
		patched, err := json.Marshal(replace(tree))
		if err != nil || json.Unmarshal(patched, out) != nil {
			t.Fatal("new TEST record scope", v.Definition)
		}
		seen[v.Definition] = true
	}
	if len(seen) != len(destinations) {
		t.Fatal("incomplete original eight-record contract fixture")
	}
	result, err := pd.ResultHashes(facts.Receipt.Request)
	if err != nil {
		t.Fatal("re-scoped TEST result", err)
	}
	facts.Receipt.ReceiptKeyHash, facts.Receipt.RequestHash = result.Key, result.Request
	command, err := pd.CommandHashes(facts.Commands[0].Request)
	if err != nil {
		t.Fatal("re-scoped TEST command", err)
	}
	facts.Commands[0].ReceiptKeyHash, facts.Commands[0].RequestHash = command.Key, command.Request
	for _, record := range []any{&facts.Domain, &facts.Grant, &facts.Run, &facts.Target, &facts.History, &facts.Receipt, &facts.Commands[0], &facts.References[0]} {
		row, err := pd.EncodeStoredRecord(record)
		if err != nil {
			t.Fatal("actual production record codec", err)
		}
		aPointNativeInsert(t, ctx, db, row.Table, row.Columns)
	}
	return facts
}

func aPointNativeSetup(t *testing.T, ctx context.Context) *aPointNativeFixture {
	t.Helper()
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("explicit pinned disposable SAN/TLS fixture required; no SKIP")
	}
	// Use the accepted a2c41128913e fixture, not a copy of its old non-TLS
	// canonical variant. It owns migrations, the marked schema and cleanup.
	db, database := censusOriginalMySQL(t, ctx)
	db.SetMaxOpenConns(8)
	var version, tlsVersion string
	var secure int
	if db.QueryRowContext(ctx, "SELECT VERSION(),@@require_secure_transport").Scan(&version, &secure) != nil || !strings.HasPrefix(version, "8.4.") || secure != 1 || db.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_version'").Scan(&tlsVersion) != nil || tlsVersion != "TLSv1.3" {
		t.Fatal("actual MySQL8.4 and SAN/TLS1.3 fixture required")
	}
	original, public, key := ownerRecordFixture(t)
	t.Cleanup(func() { clear(key) })
	f := &aPointNativeFixture{db: db, database: database, record: original, key: key}
	f.raw, f.sig = signOwner(original, key)
	var err error
	f.writer, err = NewInstallationAuthorityWriter(db, original.Binding.InstallationID, database, public)
	if err != nil {
		t.Fatal(err)
	}
	scope := pd.Scope{ServerUUID: pd.ServerUUID(database.ServerUUID), Database: pd.Database(database.Database), Installation: pd.Installation(original.Binding.InstallationID)}
	facts := aPointNativeModelRecords(t, ctx, db, scope)
	f.publicID = string(facts.History.Evidence.EvidenceID)
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("native time")
	}
	f.evidence = aPointNativeEvidence(t, ctx, db, original.Binding.InstallationID, f.publicID, 2, now)
	for n := 0; n < 2; n++ {
		f.chunkIDs = append(f.chunkIDs, aPointNativeChunk(t, ctx, db, f.evidence, n))
	}
	facts.Record = ev.Record{Manifest: ev.Manifest{Identity: ev.Identity{ID: f.publicID}, Chunks: make([]ev.Chunk, 2)}}
	facts.EvidenceRowID, facts.EvidenceRowVersion, facts.ObservedAt = f.evidence, 3, now
	f.c1 = &OriginalC1SQLSnapshot{Database: database, InstallationID: original.Binding.InstallationID, Sources: []ev.OriginalC1EvidenceFacts{facts}}
	read, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer read.Rollback()
	f.c1.Tables, f.c1.ObservedAt, err = scanOriginalC1ProtocolClosure(ctx, read, *f.c1)
	if err != nil || captureOriginalC1EvidenceRows(ctx, read, f.c1) != nil {
		t.Fatal("native comparison snapshot seed", err)
	}
	if read.Rollback() != nil {
		t.Fatal("seed read rollback")
	}
	for n, operation := range []kms.Operation{kms.Generate, kms.Unwrap, kms.Unwrap} {
		record, pin, private := providerCapabilityFixture(t, original.Binding, operation)
		record.Source.RecordID = fmt.Sprintf("sev_99999999-0000-4000-8000-%012x", n+1)
		pin.Source = record.Source
		evidence := signCapabilityFixture(t, record, private)
		clear(private)
		f.caps = append(f.caps, OriginalRuntimeCapabilityImport{Raw: evidence.raw, Pin: pin, Operation: operation})
	}
	stage, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Rollback()
	if err = f.writer.StageInitialRuntimeAuthorities(ctx, stage, f.raw, f.sig, f.caps, time.Now().UTC()); err != nil {
		t.Fatal("actual writer, TEST signatures", err)
	}
	if stage.Commit() != nil {
		t.Fatal("seed writer commit")
	}
	query, _ := aPointNativeTx(t, ctx, db)
	f.want, err = f.query(ctx, query)
	if err != nil {
		t.Fatal("actual mixed reader positive seed", err)
	}
	if query.Rollback() != nil {
		t.Fatal("seed query rollback")
	}
	return f
}

func aPointNativeTx(t *testing.T, ctx context.Context, db *sql.DB) (*sql.Tx, uint64) {
	t.Helper()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err = conn.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=4"); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	var id uint64
	if tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id) != nil || id == 0 {
		t.Fatal("native connection identity")
	}
	return tx, id
}

func (f *aPointNativeFixture) query(ctx context.Context, tx *sql.Tx) (RuntimeInstalledSQLSnapshot, error) {
	return QueryMixedRuntimeInstalledSQLSnapshotTx(ctx, tx, f.database, f.record.Binding.InstallationID, f.raw, f.sig, f.caps, f.c1)
}
