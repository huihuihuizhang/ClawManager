//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Separate capsule: never changes the accepted admission/MFA inputs or adds
// candidate C1 tables to the formal migration catalog.
//
//go:embed testdata/download_producer_probe_inputs.json
var dProducerDownloadSeed []byte

type dProducerDownloadInputs struct {
	Kind         string                     `json:"kind"`
	AdmissionRaw string                     `json:"admission_inputs"`
	AdmissionSHA string                     `json:"admission_sha256"`
	DDL          string                     `json:"producer_ddl"`
	DDLSHA       string                     `json:"producer_ddl_sha256"`
	Records      map[string]json.RawMessage `json:"records"`
	Capability   json.RawMessage            `json:"capability_evidence"`
	admission    aDownloadMFAInputs
}

func decodeDProducerDownloadInputs(raw []byte) (dProducerDownloadInputs, error) {
	var input dProducerDownloadInputs
	// The exact complete input hash also rejects duplicate/extra JSON keys,
	// reformatting, trailing documents and independently changed record vectors.
	if len(raw) > 131072 || hash(raw) != "2f7533093e5b1b38980f0c86bd65c632be8b6b515d4dbcf46d984e2032f060a8" {
		return input, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || input.Kind != "d_download_producer_probe_inputs.v2" || input.AdmissionSHA != "d9c5e055812f2467ed0377337e864ee94e082c13b0cc53d7f4b150c9b8e329c0" || hash([]byte(input.AdmissionRaw)) != input.AdmissionSHA || input.DDLSHA != "26e64e491ca677fbd0e53e1d619cb905733adcfb8f0567b7ad47a22ae0a84d1c" || hash([]byte(input.DDL)) != input.DDLSHA || len(input.Records) != 4 || len(input.Capability) == 0 {
		return dProducerDownloadInputs{}, ErrInvalid
	}
	var err error
	input.admission, err = decodeADownloadMFAInputs([]byte(input.AdmissionRaw))
	if err != nil {
		return dProducerDownloadInputs{}, err
	}
	return input, nil
}

// C1 candidate has exactly eight single CREATE statements, no routines or
// embedded semicolons. Discard only whole comment lines before splitting; a
// semicolon in an explanatory comment must never become executable SQL.
func dProducerDownloadDDL(input dProducerDownloadInputs) ([]string, error) {
	var body []string
	for _, line := range strings.Split(input.DDL, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			body = append(body, line)
		}
	}
	var statements []string
	seen := map[string]bool{}
	allowed := map[string]bool{"domains": true, "grants": true, "runs": true, "targets": true, "evidence_bindings": true, "result_receipts": true, "command_receipts": true, "evidence_refs": true}
	pattern := regexp.MustCompile(`^CREATE TABLE system_backup_producer_([a-z_]+) \(`)
	for _, part := range strings.Split(strings.Join(body, "\n"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		match := pattern.FindStringSubmatch(part)
		if len(match) != 2 || !allowed[match[1]] || seen[match[1]] || !strings.HasSuffix(part, "ENGINE=InnoDB DEFAULT CHARACTER SET ascii COLLATE ascii_bin") {
			return nil, ErrInvalid
		}
		seen[match[1]] = true
		statements = append(statements, part)
	}
	if len(statements) != 8 {
		return nil, ErrInvalid
	}
	return statements, nil
}

type dProducerDownloadRecords struct {
	domain  pd.DomainRecord
	grant   pd.GrantRecord
	run     pd.RunRecord
	history pd.HistoricalBindingRecord
	receipt pd.ReceiptRecord
	refs    []pd.ReferenceRecord
}

func dProducerDownloadObject(t *testing.T, input dProducerDownloadInputs) (Prepared, []byte, []byte, testKeys) {
	t.Helper()
	// Detached probes have no repository-relative fixtures. Normalize the
	// exact embedded A example instead of calling capabilityFixture.
	var content sec.CapabilityEvidence
	mustSQL(t, json.Unmarshal(input.Capability, &content))
	now := time.Now().UTC().Truncate(time.Second)
	content.StartedAt, content.FinishedAt = now.Add(-30*time.Second).Format(time.RFC3339), now.Add(-10*time.Second).Format(time.RFC3339)
	content.Cleanup.VerifiedAt = now.Add(-5 * time.Second).Format(time.RFC3339)
	for n := range content.Capabilities {
		content.Capabilities[n].CheckedAt = now.Add(-20 * time.Second).Format(time.RFC3339)
		content.Capabilities[n].ExpiresAt = now.Add(2 * time.Minute).Format(time.RFC3339)
	}
	plain, err := json.Marshal(content)
	mustSQL(t, err)
	if len(plain) == 0 || len(plain) > 8192 {
		t.Fatal("embedded capability must exercise the unpadded small-body path")
	}
	i := Identity{Installation: "installation_test", ID: "sev_11111111-2222-4333-8444-555555555555", OwnerType: "system", OwnerID: "installation_test", Type: "capability_snapshot", Media: "application/json", Classification: "sensitive", ContentHash: hash(plain), ContentSize: int64(len(plain))}
	policy := CapabilityContentPolicy{Installation: i.Installation, EvidenceID: i.ID, Classification: i.Classification, Role: content.Role, ProviderIdentity: content.IdentityHash, ProviderVersion: content.RefVersion, ScopeHash: content.ScopeHash, RunID: content.Cleanup.RunID, OwnerMarker: content.Cleanup.Owner, ObservedVersion: content.ObservedVersion, MaxValidity: 5 * time.Minute, ValidUntil: now.Add(4 * time.Minute)}
	auth := &systemTestAuthority{grant: ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("c", 64), ValidUntil: policy.ValidUntil, Capability: &policy}}
	keys := testKeys{key: bytes.Repeat([]byte{7}, 32)}
	var object bytes.Buffer
	p, err := PrepareSystemCapability(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(plain), auth, keys, &object)
	mustSQL(t, err)
	return p, plain, object.Bytes(), keys
}

func dProducerDownloadRecordSet(t *testing.T, input dProducerDownloadInputs, scope pd.Scope, p Prepared, r Record) dProducerDownloadRecords {
	t.Helper()
	var set dProducerDownloadRecords
	for name, out := range map[string]any{"DomainRecord": &set.domain, "GrantRecord": &set.grant, "HistoricalBindingRecord": &set.history, "ReceiptRecord": &set.receipt} {
		mustSQL(t, pd.DecodeRecord(input.Records[name], out))
	}
	channel := ProducerEvidenceChannel{Root: "evidence", Store: KeyRef{r.Ref.Identity, r.Ref.Version}, Write: KeyRef{strings.Repeat("d", 64), "v2"}, RecoveryProfileHash: strings.Repeat("e", 64)}
	binding, err := p.PendingProducerBinding(channel)
	mustSQL(t, err)
	h := &set.history
	h.Scope, h.Evidence, h.RelativeKey = scope, binding, pd.RelativeKey(r.Ref.RelativeKey)
	h.CreatedAt, h.ObservedAt = systemExecutionStamp(r.CreatedAt), systemExecutionStamp(r.CreatedAt)
	h.OwnerWriteExpiresAt = systemExecutionStamp(r.OwnerDeadline)
	h.ObservationExpiresAt, h.RetentionExpiresAt = systemExecutionStamp(r.CreatedAt.Add(time.Minute)), systemExecutionStamp(r.ExpiresAt)
	request := &set.receipt.Request
	request.Scope, request.GrantID, request.GrantGeneration, request.RunID = scope, h.GrantID, h.GrantGeneration, h.RunID
	request.DomainEpoch, request.Admission = h.DomainEpoch, h.Admission
	request.Evidence = binding
	version := pd.Text(r.Ref.ImmutableVersion)
	request.Evidence.ImmutableVersion = &version
	request.InputHash, request.ObservedAt, request.ObservationExpiresAt = h.InputHash, h.ObservedAt, h.ObservationExpiresAt
	request.ExpectedEvidenceVersion = pd.Counter(strconv.FormatInt(r.RowVersion, 10))
	request.TargetGeneration, request.ExpectedResultVersion = "1", "0"
	digests, err := pd.ResultHashes(*request)
	mustSQL(t, err)
	h.TargetHash = digests.Target
	set.receipt.Scope, set.receipt.ReceiptKeyHash, set.receipt.RequestHash = scope, digests.Key, digests.Request
	set.receipt.ResultVersion, set.receipt.CommittedAt, set.receipt.RetentionExpiresAt = "1", h.CreatedAt, h.RetentionExpiresAt
	set.run = pd.RunRecord{Scope: scope, RunID: h.RunID, GrantID: h.GrantID, GrantGeneration: h.GrantGeneration, TargetHash: h.TargetHash, TargetGeneration: "1", InputHash: h.InputHash, EvidenceID: h.Evidence.EvidenceID, OwnerWriteExpiresAt: h.OwnerWriteExpiresAt, ObservedAt: &h.ObservedAt, ObservationExpiresAt: &h.ObservationExpiresAt, State: "committed", RowVersion: "5"}
	set.domain.Scope, set.domain.Epoch, set.domain.Admission = scope, h.DomainEpoch, h.Admission
	set.domain.CreatedAt, set.domain.UpdatedAt = systemExecutionStamp(r.CreatedAt.Add(-time.Second)), systemExecutionStamp(r.CreatedAt.Add(-time.Second))
	set.domain.AdmissionExpiresAt = h.OwnerWriteExpiresAt
	set.grant.Scope, set.grant.GrantID, set.grant.Generation, set.grant.DomainEpoch = scope, h.GrantID, h.GrantGeneration, h.DomainEpoch
	set.grant.Admission, set.grant.Target, set.grant.Purpose = h.Admission, request.Target, request.Purpose
	set.grant.CreatedAt, set.grant.LeaseExpiresAt, set.grant.AuthorizationExpiresAt = h.CreatedAt, h.OwnerWriteExpiresAt, h.OwnerWriteExpiresAt
	for _, kind := range []string{"producer_result", "producer_receipt", "bootstrap_candidate", "hold"} {
		set.refs = append(set.refs, pd.ReferenceRecord{Scope: scope, EvidenceID: h.Evidence.EvidenceID, ReferenceKind: kind, ReferenceKeyHash: pd.Hash(strings.Repeat("a", 64)), ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt})
	}
	return set
}

func (s *dProducerDownloadRecords) all() []any {
	rows := []any{&s.domain, &s.grant, &s.run, &s.history, &s.receipt}
	for n := range s.refs {
		rows = append(rows, &s.refs[n])
	}
	return rows
}

func dProducerStoredInsert(record any) (string, []any, error) {
	stored, err := pd.EncodeStoredRecord(record)
	if err != nil {
		return "", nil, err
	}
	allowed := map[string]bool{"system_backup_producer_domains": true, "system_backup_producer_grants": true, "system_backup_producer_runs": true, "system_backup_producer_evidence_bindings": true, "system_backup_producer_result_receipts": true, "system_backup_producer_evidence_refs": true}
	if !allowed[stored.Table] {
		return "", nil, ErrInvalid
	}
	var columns []string
	for column := range stored.Columns {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(column) {
			return "", nil, ErrInvalid
		}
		columns = append(columns, column)
	}
	sort.Strings(columns)
	var args []any
	for _, column := range columns {
		args = append(args, stored.Columns[column])
	}
	return "INSERT INTO " + stored.Table + "(" + strings.Join(columns, ",") + ") VALUES(" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")", args, nil
}

func TestDProducerDownloadOwnersMySQLSeed(t *testing.T) {
	input, err := decodeDProducerDownloadInputs(dProducerDownloadSeed)
	mustSQL(t, err)
	t.Run("eight_exact_ddl_statements", func(t *testing.T) {
		statements, err := dProducerDownloadDDL(input)
		mustSQL(t, err)
		if len(statements) != 8 {
			t.Fatal("missing C1 schema")
		}
	})
	t.Run("actual_scope_projections_encrypted_object", func(t *testing.T) {
		p, plain, object, keys := dProducerDownloadObject(t, input)
		base := aDownloadMFAPinnedFixture(t, input.admission)
		r := base.initial
		r.Manifest = p.Manifest()
		r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
		mustSQL(t, err)
		scope := pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "amfa_11111111222243338444555555555555", Installation: pd.Installation(r.Manifest.Identity.Installation)}
		set := dProducerDownloadRecordSet(t, input, scope, p, r)
		for _, record := range set.all() {
			stored, err := pd.EncodeStoredRecord(record)
			mustSQL(t, err)
			out := reflect.New(reflect.TypeOf(record).Elem()).Interface()
			mustSQL(t, pd.DecodeStoredRecord(stored, scope, out))
			if !reflect.DeepEqual(record, out) {
				t.Fatal("actual-scope full C1 projections did not roundtrip", stored.Table)
			}
			query, args, err := dProducerStoredInsert(record)
			mustSQL(t, err)
			if strings.Count(query, "?") != len(args) {
				t.Fatal("C1 insert lost a complete projection")
			}
		}
		store := &testStore{data: object, present: true, info: ObjectInfo{Version: r.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}
		got, err := OpenRange(context.Background(), r.Manifest, r.Ref, store, keys, 0, int64(len(plain)-1))
		mustSQL(t, err)
		defer wipe(got)
		if !bytes.Equal(got, plain) || len(plain) > 8192 {
			t.Fatal("small system capability changed content")
		}
	})
	for _, mode := range []string{"unknown", "duplicate", "trailing", "ddl", "admission", "records", "budget"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(dProducerDownloadSeed)
			switch mode {
			case "unknown":
				raw = append([]byte(`{"extra":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"kind":"duplicate",`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "ddl":
				raw = bytes.Replace(raw, []byte("CREATE TABLE system_backup_producer_domains"), []byte("CREATE TABLE system_unknown_domains"), 1)
			case "admission":
				raw = bytes.Replace(raw, []byte(input.AdmissionSHA), []byte(strings.Repeat("0", 64)), 1)
			case "records":
				raw = bytes.Replace(raw, []byte("synthetic_run_1"), []byte("synthetic_run_2"), 1)
			case "budget":
				raw = make([]byte, 131073)
			}
			if _, err := decodeDProducerDownloadInputs(raw); err == nil {
				t.Fatal("changed producer capsule accepted")
			}
		})
	}
	t.Log("PASS producer download seed; actual_mysql=not_run production_approval=no")
}

type dProducerDownloadMySQLFixture struct {
	*aAdmissionMySQLFixture
	concrete *SQLDownloadOwners
	records  dProducerDownloadRecords
}

func (f *dProducerDownloadMySQLFixture) requireOriginalProducerRows(t *testing.T, mode string) {
	t.Helper()
	keys := map[string][]string{
		"system_backup_producer_domains":           {"scope_key"},
		"system_backup_producer_grants":            {"scope_key", "grant_id"},
		"system_backup_producer_runs":              {"scope_key", "run_id"},
		"system_backup_producer_evidence_bindings": {"scope_key", "evidence_id"},
		"system_backup_producer_result_receipts":   {"scope_key", "receipt_key_hash"},
		"system_backup_producer_evidence_refs":     {"scope_key", "evidence_id", "reference_kind", "reference_key_hash"},
	}
	for _, record := range f.records.all() {
		if mode == "empty_receipt_range" {
			if _, ok := record.(*pd.ReceiptRecord); ok {
				continue
			}
		}
		if mode == "empty_hold_range" {
			if _, ok := record.(*pd.ReferenceRecord); ok {
				continue
			}
		}
		stored, err := pd.EncodeStoredRecord(record)
		mustSQL(t, err)
		var columns, predicates []string
		var args []any
		for column := range stored.Columns {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		for _, column := range keys[stored.Table] {
			predicates = append(predicates, column+"=?")
			args = append(args, stored.Columns[column])
		}
		values, dest := make([]any, len(columns)), make([]any, len(columns))
		for n := range values {
			dest[n] = &values[n]
		}
		mustSQL(t, f.aDownloadMFAFixture.db.QueryRowContext(f.ctx, "SELECT "+strings.Join(columns, ",")+" FROM "+stored.Table+" WHERE "+strings.Join(predicates, " AND "), args...).Scan(dest...))
		actual := pd.StoredRecord{Table: stored.Table, Columns: map[string]any{}}
		for n, column := range columns {
			actual.Columns[column] = values[n]
		}
		out := reflect.New(reflect.TypeOf(record).Elem()).Interface()
		mustSQL(t, pd.DecodeStoredRecord(actual, f.records.history.Scope, out))
		if !reflect.DeepEqual(record, out) {
			t.Fatal("download changed an immutable original C1 row", stored.Table)
		}
	}
	for table, want := range map[string]int{"system_backup_producer_result_receipts": 1, "system_backup_producer_evidence_refs": 4} {
		if mode == "empty_receipt_range" && strings.HasSuffix(table, "result_receipts") || mode == "empty_hold_range" && strings.HasSuffix(table, "evidence_refs") {
			want = 0
		}
		var count int
		mustSQL(t, f.aDownloadMFAFixture.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&count))
		if count != want {
			t.Fatal("original producer reference cardinality changed", table, count, want)
		}
	}
}

func newDProducerDownloadMySQLFixture(t *testing.T, input dProducerDownloadInputs, mode string) *dProducerDownloadMySQLFixture {
	t.Helper()
	x := newAAdmissionMySQLFixture(t, input.admission)
	f := &dProducerDownloadMySQLFixture{aAdmissionMySQLFixture: x}
	db := x.aDownloadMFAFixture.db
	if !regexp.MustCompile(`^amfa_[a-f0-9]{32}$`).MatchString(x.identity.Database) {
		t.Fatal("C1 candidate is restricted to this exact cloned child database")
	}
	statements, err := dProducerDownloadDDL(input)
	mustSQL(t, err)
	for _, statement := range statements {
		_, err = db.ExecContext(x.ctx, statement)
		mustSQL(t, err)
	}
	p, plain, object, keys := dProducerDownloadObject(t, input)
	r := x.initial
	r.Manifest = p.Manifest()
	r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
	mustSQL(t, err)
	if mode == "expired_owner_write_read" {
		r.CreatedAt = aDownloadMFANow(t, x.ctx, db).Add(-2 * time.Hour)
		r.OwnerDeadline = r.CreatedAt.Add(time.Minute)
	}
	m := r.Manifest
	_, err = db.ExecContext(x.ctx, `UPDATE system_backup_v2_evidence SET owner_target_type='system',owner_target_public_id=?,evidence_type='capability_snapshot',media_type='application/json',storage_relative_key=?,storage_relative_key_hash=?,content_checksum=?,content_size_bytes=?,object_checksum=?,object_size_bytes=?,chunk_count=?,chunk_list_root=?,envelope_hash=?,created_at=? WHERE public_id=?`, m.Identity.OwnerID, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), m.Identity.ContentHash, m.Identity.ContentSize, m.ObjectHash, m.ObjectSize, len(m.Chunks), m.ChunkRoot, m.EnvelopeHash, r.CreatedAt, m.Identity.ID)
	mustSQL(t, err)
	var evidenceID int64
	mustSQL(t, db.QueryRowContext(x.ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=?", m.Identity.ID).Scan(&evidenceID))
	_, err = db.ExecContext(x.ctx, "DELETE FROM system_backup_v2_evidence_chunks WHERE evidence_id=?", evidenceID)
	mustSQL(t, err)
	for _, chunk := range m.Chunks {
		nonce, e := base64.RawURLEncoding.DecodeString(chunk.Nonce)
		mustSQL(t, e)
		tag, e := base64.RawURLEncoding.DecodeString(chunk.Tag)
		mustSQL(t, e)
		_, err = db.ExecContext(x.ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) VALUES(?,?,?,?,?,?,?,?,?,?)`, evidenceID, chunk.Index, chunk.PlainOffset, chunk.PlainLength, chunk.PlainHash, chunk.FrameOffset, chunk.FrameLength, chunk.CipherHash, nonce, tag)
		mustSQL(t, err)
	}
	scope := pd.Scope{ServerUUID: pd.ServerUUID(x.identity.ServerUUID), Database: pd.Database(x.identity.Database), Installation: pd.Installation(x.registry.Installation)}
	f.records = dProducerDownloadRecordSet(t, input, scope, p, r)
	if mode == "expired_owner_write_read" || mode == "superseded_run" {
		f.records.domain.State, f.records.grant.State = "revoked", "revoked"
	}
	if mode == "superseded_run" {
		f.records.run.State = "superseded"
	}
	if mode == "empty_receipt_range" {
		f.records.run.State = "published"
	}
	for _, record := range f.records.all() {
		if mode == "empty_receipt_range" {
			if _, ok := record.(*pd.ReceiptRecord); ok {
				continue
			}
		}
		if mode == "empty_hold_range" {
			if _, ok := record.(*pd.ReferenceRecord); ok {
				continue
			}
		}
		query, args, err := dProducerStoredInsert(record)
		mustSQL(t, err)
		_, err = db.ExecContext(x.ctx, query, args...)
		mustSQL(t, err)
	}
	_, err = db.ExecContext(x.ctx, "DROP TABLE synthetic_download_mfa_owner")
	mustSQL(t, err)
	f.concrete, err = NewSQLDownloadOwners(SQLDownloadOwnersConfig{Registry: x.registry, Sessions: x.environment.config.Sessions, RegistryDirectory: x.environment.config.RegistryDirectory, Root: "evidence"})
	mustSQL(t, err)
	x.registry = f.concrete.Registry()
	x.initial, x.plain, x.object, x.keys = r, plain, object, keys
	config := x.environment.config
	config.Owners = f.concrete
	x.environment, err = NewPinnedDownloadAdmissionEnvironment(config)
	mustSQL(t, err)
	x.targets, err = NewPinnedSensitiveDownloadProofTargets(x.registry, x.environment)
	mustSQL(t, err)
	x.admission, err = NewDownloadAdmissionService(x.registry, x.secret, x.environment)
	mustSQL(t, err)
	resultConfig := x.results.c
	resultConfig.Registry, resultConfig.Owners = x.registry, f.concrete
	x.results, err = NewSQLDownloadResults(resultConfig)
	mustSQL(t, err)
	x.authority.c.Registry = x.registry
	x.store.testStore = &testStore{data: object, present: true, info: ObjectInfo{Version: r.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}
	bound, err := BindSensitiveDownloadRequest(x.env.actor, m, x.request.Header)
	mustSQL(t, err)
	binding, err := bound.ProofBinding("issuer-transaction")
	mustSQL(t, err)
	proof := x.proof
	proof.Payload.RequestHash, proof.Payload.IdempotencyKey = binding.RequestHash, binding.IdempotencyKey
	payload, err := sec.CanonicalPayload(proof.Payload)
	mustSQL(t, err)
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(x.signer.key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	x.proof = proof
	x.setProof(t, proof)
	x.refreshReport(t)
	return f
}

func TestDProducerDownloadOwnersMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("producer download actual capsule pin")
	}
	input, err := decodeDProducerDownloadInputs(raw)
	mustSQL(t, err)
	for _, mode := range []string{"http_result", "expired_owner_write_read", "superseded_run", "wrong_root", "run_projection", "history_manifest", "receipt_manifest", "receipt_version", "foreign_reference", "partial_schema", "missing_history", "original_run_lock", "original_history_lock", "empty_receipt_range", "empty_hold_range", "revoked_result", "result_link_rollback", "late_history_rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newDProducerDownloadMySQLFixture(t, input, mode)
			db := f.aDownloadMFAFixture.db
			switch mode {
			case "wrong_root":
				f.concrete.producerRoot = "wrong-root"
			case "run_projection":
				_, err = db.ExecContext(f.ctx, "UPDATE system_backup_producer_runs SET target_generation=target_generation+1")
			case "partial_schema":
				_, err = db.ExecContext(f.ctx, "DROP TABLE system_backup_producer_evidence_refs")
			case "missing_history":
				_, err = db.ExecContext(f.ctx, "DELETE FROM system_backup_producer_evidence_bindings")
			case "history_manifest":
				_, err = db.ExecContext(f.ctx, "DELETE FROM system_backup_producer_evidence_bindings")
				mustSQL(t, err)
				f.records.history.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
				q, args, e := dProducerStoredInsert(&f.records.history)
				mustSQL(t, e)
				_, err = db.ExecContext(f.ctx, q, args...)
			case "receipt_manifest", "receipt_version":
				_, err = db.ExecContext(f.ctx, "DELETE FROM system_backup_producer_result_receipts")
				mustSQL(t, err)
				if mode == "receipt_manifest" {
					f.records.receipt.Request.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
				} else {
					v := pd.Text("wrong-version")
					f.records.receipt.Request.Evidence.ImmutableVersion = &v
				}
				h, e := pd.ResultHashes(f.records.receipt.Request)
				mustSQL(t, e)
				f.records.receipt.RequestHash, f.records.receipt.ReceiptKeyHash = h.Request, h.Key
				q, args, e := dProducerStoredInsert(&f.records.receipt)
				mustSQL(t, e)
				_, err = db.ExecContext(f.ctx, q, args...)
			case "foreign_reference":
				ref := f.records.refs[3]
				ref.Scope.Database = "foreign_database"
				q, args, e := dProducerStoredInsert(&ref)
				mustSQL(t, e)
				_, err = db.ExecContext(f.ctx, q, args...)
			}
			mustSQL(t, err)
			if mode == "wrong_root" || mode == "run_projection" || mode == "history_manifest" || mode == "receipt_manifest" || mode == "receipt_version" || mode == "partial_schema" || mode == "missing_history" {
				if c, err := f.admission.Admit(f.request); err == nil || c != nil {
					t.Fatal("invalid historical producer admitted", mode)
				}
				f.requireRows(t, 0, 0, false)
				return
			}
			if mode == "late_history_rollback" {
				_, err := db.ExecContext(f.ctx, "CREATE TRIGGER d_producer_history_late_change AFTER INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='system_backup.evidence_download.intent' THEN UPDATE system_backup_producer_evidence_bindings SET owner_write_expires_at=owner_write_expires_at+INTERVAL 1 MICROSECOND; END IF; END")
				mustSQL(t, err)
				if c, err := f.admission.Admit(f.request); err == nil || c != nil {
					t.Fatal("late producer history mutation committed")
				}
				f.requireRows(t, 0, 0, false)
				var deadline time.Time
				mustSQL(t, db.QueryRowContext(f.ctx, "SELECT owner_write_expires_at FROM system_backup_producer_evidence_bindings").Scan(&deadline))
				if !deadline.Equal(f.initial.OwnerDeadline) {
					t.Fatal("history projection escaped original transaction rollback")
				}
				f.requireOriginalProducerRows(t, mode)
				return
			}
			if mode == "foreign_reference" || mode == "original_run_lock" || mode == "original_history_lock" || mode == "empty_receipt_range" || mode == "empty_hold_range" {
				tx, err := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				mustSQL(t, err)
				defer tx.Rollback()
				r, err := f.concrete.Preview(f.ctx, tx, f.registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
				mustSQL(t, err)
				err = f.concrete.LockOwnerReferences(f.ctx, tx, r)
				if mode == "foreign_reference" {
					if err == nil {
						t.Fatal("foreign C1 scope reference accepted")
					}
					mustSQL(t, tx.Rollback())
					f.requireRows(t, 0, 0, false)
					return
				}
				mustSQL(t, err)
				mustSQL(t, f.concrete.Recheck(f.ctx, tx, f.env.actor, r))
				observer := &dTaskOwnerDownloadChainFixture{aAdmissionMySQLFixture: f.aAdmissionMySQLFixture}
				switch mode {
				case "original_run_lock":
					observer.observeExactBlockedWrite(t, tx, "system_backup_producer_runs", "UPDATE system_backup_producer_runs SET row_version=row_version+1")
				case "original_history_lock":
					observer.observeExactBlockedWrite(t, tx, "system_backup_producer_evidence_bindings", "UPDATE system_backup_producer_evidence_bindings SET retention_expires_at=retention_expires_at+INTERVAL 1 SECOND")
				case "empty_receipt_range":
					q, args, e := dProducerStoredInsert(&f.records.receipt)
					mustSQL(t, e)
					observer.observeExactBlockedWrite(t, tx, "system_backup_producer_result_receipts", q, args...)
				case "empty_hold_range":
					q, args, e := dProducerStoredInsert(&f.records.refs[3])
					mustSQL(t, e)
					observer.observeExactBlockedWrite(t, tx, "system_backup_producer_evidence_refs", q, args...)
				}
				f.requireRows(t, 0, 0, false)
				f.requireOriginalProducerRows(t, mode)
				return
			}
			if mode == "revoked_result" || mode == "result_link_rollback" {
				c := f.admitted(t)
				if mode == "result_link_rollback" {
					_, err := db.ExecContext(f.ctx, "CREATE TRIGGER d_producer_result_link_reject BEFORE INSERT ON system_backup_v2_download_result_receipts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='producer result link probe rejection'")
					mustSQL(t, err)
					if f.results.Finish(f.ctx, c, DownloadResultObservation{Outcome: "interrupted"}) == nil {
						t.Fatal("producer result link failure committed")
					}
					f.requireRows(t, 1, 0, false)
					f.requireOriginalProducerRows(t, mode)
					return
				}
				ctx, cancel, err := f.authority.BindCommittedDownload(f.ctx, c)
				mustSQL(t, err)
				defer cancel()
				mustSQL(t, f.authority.CheckCommittedDownload(ctx, c))
				_, err = db.ExecContext(f.ctx, "UPDATE users SET is_active=FALSE WHERE id=42")
				mustSQL(t, err)
				if f.authority.CheckCommittedDownload(ctx, c) == nil {
					t.Fatal("revoked producer evidence reader retained provider authority")
				}
				f.result(t, c)
				f.requireOriginalProducerRows(t, mode)
				return
			}
			failures := 0
			service := Service{Registry: f.registry, Store: f.store, Keys: DownloadKeys{Authority: f.authority, Keys: f.keys}, Failure: func(context.Context, string, string) { failures++ }}
			handler, err := newAdmittedDownloadHandler(f.admission, f.authority, f.results, service, Handler{Auth: f.authority, Service: service})
			mustSQL(t, err)
			w := admittedWriter()
			handler.ServeHTTP(w, f.request)
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), f.plain) || failures != 0 || len(f.store.scopes) != 3 {
				t.Fatal("actual historical producer HTTP/result composition", mode, w.Code, failures, len(f.store.scopes))
			}
			f.requireRows(t, 1, 1, true)
			f.requireOriginalProducerRows(t, mode)
		})
	}
	t.Log("PASS actual producer download owner cases=18 owner_adapter=SQLDownloadOwners provider_transport=synthetic production_approval=no")
}
