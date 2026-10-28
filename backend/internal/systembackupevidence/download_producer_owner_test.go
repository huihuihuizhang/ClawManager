package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type producerDownloadModel struct {
	base          *sqlTaskOwnerModel
	rows          map[string][]pd.StoredRecord
	history       pd.HistoricalBindingRecord
	run           pd.RunRecord
	plain, object []byte
	keys          testKeys
}

type producerOwnerTestEnvironment struct {
	base   *admissionTxEnvironment
	owners DownloadAdmissionOwners
}
type producerOwnerPreparedTest struct {
	PreparedDownloadAdmission
	owners DownloadAdmissionOwners
}

func (e *producerOwnerTestEnvironment) Prepare(ctx context.Context, tx *sql.Tx, a sec.RegistrationActor, c *sec.SensitiveDownloadConfig, id string, versions []string) (PreparedDownloadAdmission, error) {
	r, err := e.owners.Preview(ctx, tx, c.InstallationID(), a, id)
	if err != nil {
		return nil, err
	}
	e.base.hint = r
	p, err := e.base.Prepare(ctx, tx, a, c, id, versions)
	if err != nil {
		return nil, err
	}
	return &producerOwnerPreparedTest{p, e.owners}, nil
}
func (p *producerOwnerPreparedTest) LockOwnerReferences(ctx context.Context, tx *sql.Tx) error {
	return p.owners.LockOwnerReferences(ctx, tx, p.Preview())
}
func (p *producerOwnerPreparedTest) Recheck(ctx context.Context, tx *sql.Tx, a sec.RegistrationActor, r Record, now time.Time) error {
	if err := p.PreparedDownloadAdmission.Recheck(ctx, tx, a, r, now); err != nil {
		return err
	}
	return p.owners.Recheck(ctx, tx, a, r)
}

func (m *producerDownloadModel) query(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
	for _, d := range producerDownloadDefinitions() {
		if !strings.HasPrefix(q, "SELECT scope_key,") || !strings.Contains(q, " FROM "+d.table+" WHERE ") {
			continue
		}
		if len(args) != 1 || args[0].Value != m.base.f.initial.Manifest.Identity.ID || q != producerDownloadSQL(d, strings.HasSuffix(q, " FOR UPDATE")) {
			return nil, true, ErrInvalid
		}
		if err := m.base.mark(d.stage, q); err != nil {
			return nil, true, err
		}
		fields := strings.Fields(d.fields)
		rows := &admissionTxRows{width: len(fields)}
		for _, stored := range m.rows[d.table] {
			values := make([]driver.Value, len(fields))
			for n, c := range fields {
				v := stored.Columns[c]
				if c == "record_bytes" {
					if b, ok := v.([]byte); ok && len(b) > d.limit {
						v = nil
					}
				}
				if count, ok := v.(uint64); ok {
					v = strconv.FormatUint(count, 10)
				}
				values[n] = v
			}
			rows.data = append(rows.data, values)
		}
		return rows, true, nil
	}
	return m.base.query(ctx, q, args)
}
func (m *producerDownloadModel) store(t *testing.T, r any) {
	t.Helper()
	s, err := pd.EncodeStoredRecord(r)
	if err != nil {
		t.Fatal("invalid producer test record", err)
	}
	m.rows[s.Table] = []pd.StoredRecord{s}
}

func producerDownloadFixture(t *testing.T) (*admissionTxFixture, *SQLDownloadAuthority, *SQLDownloadOwners, *producerDownloadModel) {
	t.Helper()
	var prepared Prepared
	var plain, object []byte
	var keys testKeys
	f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
		i, body, auth, key := smallSystemFixture(t)
		i.Installation, i.OwnerID, i.ID, i.Classification = f.initial.Manifest.Identity.Installation, f.initial.Manifest.Identity.Installation, f.initial.Manifest.Identity.ID, "sensitive"
		p := *auth.grant.Capability
		p.Installation, p.EvidenceID, p.Classification = i.Installation, i.ID, i.Classification
		auth.grant.Identity, auth.grant.Capability = i, &p
		var out bytes.Buffer
		var err error
		prepared, err = PrepareSystemCapability(context.Background(), i, f.initial.Manifest.Key, source(body), auth, key, &out)
		if err != nil {
			t.Fatal("prepare producer download", err)
		}
		f.initial.Manifest = prepared.Manifest()
		plain, object, keys = body, append([]byte(nil), out.Bytes()...), key
	})
	s, err := NewSQLDownloadOwners(SQLDownloadOwnersConfig{Registry: f.service.registry, Sessions: f.env.sessions, RegistryDirectory: a.c.RegistryDirectory, Root: "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	f.service.registry, a.c.Registry = s.Registry(), s.Registry()
	b := newSQLTaskOwnerModel(t, f, "system")
	for _, table := range taskDownloadSystemProducerTables {
		b.metadata[table+".evidence_id"] = "varchar"
	}
	m := &producerDownloadModel{base: b, rows: map[string][]pd.StoredRecord{}, plain: plain, object: object, keys: keys}
	f.db.ownerQuery = m.query
	channel := ProducerEvidenceChannel{Root: "evidence", Store: KeyRef{f.initial.Ref.Identity, f.initial.Ref.Version}, Write: KeyRef{strings.Repeat("d", 64), "v2"}, RecoveryProfileHash: strings.Repeat("e", 64)}
	binding, err := prepared.PendingProducerBinding(channel)
	if err != nil {
		t.Fatal(err)
	}
	if err = pd.DecodeRecord(producerHistoricalVector(t), &m.history); err != nil {
		t.Fatal(err)
	}
	h := &m.history
	h.Scope = pd.Scope{ServerUUID: pd.ServerUUID(f.db.identity.ServerUUID), Database: pd.Database(f.db.identity.Database), Installation: pd.Installation(f.initial.Manifest.Identity.Installation)}
	h.Evidence, h.RelativeKey = binding, pd.RelativeKey(f.initial.Ref.RelativeKey)
	h.CreatedAt, h.ObservedAt = systemExecutionStamp(f.initial.CreatedAt), systemExecutionStamp(f.initial.CreatedAt)
	h.OwnerWriteExpiresAt, h.ObservationExpiresAt, h.RetentionExpiresAt = systemExecutionStamp(f.initial.OwnerDeadline), systemExecutionStamp(f.initial.CreatedAt.Add(time.Minute)), systemExecutionStamp(f.initial.ExpiresAt)
	m.run = pd.RunRecord{Scope: h.Scope, RunID: h.RunID, GrantID: h.GrantID, GrantGeneration: h.GrantGeneration, TargetHash: h.TargetHash, TargetGeneration: "1", InputHash: h.InputHash, EvidenceID: h.Evidence.EvidenceID, OwnerWriteExpiresAt: h.OwnerWriteExpiresAt, ObservedAt: &h.ObservedAt, ObservationExpiresAt: &h.ObservationExpiresAt, State: "committed", RowVersion: "5"}
	m.store(t, h)
	m.store(t, &m.run)
	return f, a, s, m
}

func TestProducerDownloadProjectionCatalogMatchesActualPersistenceDDL(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-persistence.json")
	if err != nil {
		t.Fatal(err)
	}
	var dictionary struct {
		Tables []struct {
			Name    string
			Columns map[string]string
			Limit   int `json:"record_max_bytes"`
		}
	}
	if json.Unmarshal(raw, &dictionary) != nil {
		t.Fatal("dictionary")
	}
	ddl, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range producerDownloadDefinitions() {
		for _, table := range dictionary.Tables {
			if table.Name != d.table {
				continue
			}
			seen++
			if len(strings.Fields(d.fields)) != len(table.Columns) || d.limit != table.Limit {
				t.Fatal("projection dictionary drift", d.table)
			}
			for _, c := range strings.Fields(d.fields) {
				if _, ok := table.Columns[c]; !ok {
					t.Fatal("unknown column", c)
				}
			}
		}
		block := regexp.MustCompile(`(?ms)^CREATE TABLE ` + d.table + ` \(\r?\n(.*?)^\) ENGINE`).FindSubmatch(ddl)
		if len(block) != 2 {
			t.Fatal("actual producer DDL missing", d.table)
		}
		for _, c := range strings.Fields(d.fields) {
			if !bytes.Contains(block[1], []byte("  "+c+" ")) {
				t.Fatal("column absent in actual DDL", c)
			}
		}
	}
	if seen != 4 {
		t.Fatal("missing producer definitions", seen)
	}
	if !bytes.Contains(ddl, []byte("reference_kind ENUM('producer_result', 'producer_receipt', 'bootstrap_candidate', 'hold')")) {
		t.Fatal("MySQL reference-kind ordering changed")
	}
}

func producerDownloadReceipt(t *testing.T, m *producerDownloadModel) pd.ReceiptRecord {
	t.Helper()
	var receipt pd.ReceiptRecord
	if err := pd.DecodeRecord(dIntegrationVector(t, "records", "ReceiptRecord"), &receipt); err != nil {
		t.Fatal(err)
	}
	h := m.history
	r := &receipt.Request
	r.Scope, r.GrantID, r.GrantGeneration, r.RunID, r.DomainEpoch, r.Admission = h.Scope, h.GrantID, h.GrantGeneration, h.RunID, h.DomainEpoch, h.Admission
	r.Evidence = h.Evidence
	version := pd.Text(m.base.f.initial.Ref.ImmutableVersion)
	r.Evidence.ImmutableVersion = &version
	r.InputHash, r.ObservedAt, r.ObservationExpiresAt = h.InputHash, h.ObservedAt, h.ObservationExpiresAt
	r.ExpectedResultVersion, r.TargetGeneration = "0", m.run.TargetGeneration
	digests, err := pd.ResultHashes(*r)
	if err != nil {
		t.Fatal(err)
	}
	// The immutable target hash in both original rows must match the receipt.
	m.history.TargetHash, m.run.TargetHash = digests.Target, digests.Target
	m.store(t, &m.history)
	m.store(t, &m.run)
	receipt.Scope, receipt.ReceiptKeyHash, receipt.RequestHash = h.Scope, digests.Key, digests.Request
	receipt.ResultVersion, receipt.CommittedAt, receipt.RetentionExpiresAt = "1", h.ObservedAt, h.RetentionExpiresAt
	return receipt
}

func TestProducerDownloadReceiptsAndHoldsBindOriginalEvidence(t *testing.T) {
	for _, mode := range []string{"normal", "receipt_manifest", "receipt_version", "receipt_grant", "foreign_hold", "duplicate_hold", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := producerDownloadFixture(t)
			receipt := producerDownloadReceipt(t, m)
			switch mode {
			case "receipt_manifest":
				receipt.Request.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
			case "receipt_version":
				v := pd.Text("other-version")
				receipt.Request.Evidence.ImmutableVersion = &v
			case "receipt_grant":
				receipt.Request.GrantGeneration = "99"
			}
			d, err := pd.ResultHashes(receipt.Request)
			if err != nil {
				t.Fatal(err)
			}
			receipt.ReceiptKeyHash, receipt.RequestHash = d.Key, d.Request
			m.store(t, &receipt)
			for _, kind := range []string{"producer_result", "producer_receipt", "bootstrap_candidate", "hold"} {
				r := pd.ReferenceRecord{Scope: m.history.Scope, EvidenceID: m.history.Evidence.EvidenceID, ReferenceKind: kind, ReferenceKeyHash: pd.Hash(strings.Repeat("a", 64)), ProtectedUntil: m.history.RetentionExpiresAt, CreatedAt: m.history.CreatedAt}
				if mode == "foreign_hold" && kind == "hold" {
					r.Scope.Database = "foreign_database"
				}
				stored, err := pd.EncodeStoredRecord(&r)
				if err != nil {
					t.Fatal(err)
				}
				m.rows[stored.Table] = append(m.rows[stored.Table], stored)
			}
			if mode == "duplicate_hold" {
				table := "system_backup_producer_evidence_refs"
				m.rows[table] = append(m.rows[table], m.rows[table][3])
			}
			if mode == "overflow" {
				d := producerDownloadDefinitions()[0]
				count := maxTaskDownloadReferences
				tx, _, err := s.Registry().begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = s.producerRows(context.Background(), tx, d, f.initial.Manifest.Identity, true, &count); err == nil {
					t.Fatal("producer rows ignored shared capacity bound")
				}
				return
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = s.LockOwnerReferences(context.Background(), tx, f.initial)
			if mode == "foreign_hold" || mode == "duplicate_hold" {
				if err == nil {
					t.Fatal("bad hold accepted")
				}
				return
			}
			if strings.HasPrefix(mode, "receipt_") {
				if err == nil {
					t.Fatal("bad receipt passed the original owner lock boundary", mode)
				}
				return
			}
			if err != nil {
				t.Fatal("producer reference lock prefix", err)
			}
			_, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			if (err == nil) != (mode == "normal") {
				t.Fatal("receipt original binding", mode, err)
			}
		})
	}
}

func TestProducerDownloadRootIsConfiguredAndNeverInferred(t *testing.T) {
	for _, mode := range []string{"configured", "wrong"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := producerDownloadFixture(t)
			key, err := keyFor("archive/evidence", f.initial.Manifest.Identity)
			if err != nil {
				t.Fatal(err)
			}
			f.initial.Ref.RelativeKey = key
			f.db.record = f.initial
			m.history.RelativeKey = pd.RelativeKey(key)
			m.history.Evidence.RelativeKeyHash = pd.Hash(hash([]byte(key)))
			m.store(t, &m.history)
			root := "archive/evidence"
			if mode == "wrong" {
				root = "other-root"
			}
			s, err = NewSQLDownloadOwners(SQLDownloadOwnersConfig{Registry: s.c.Registry, Sessions: s.c.Sessions, RegistryDirectory: s.c.RegistryDirectory, Root: root})
			if err != nil {
				t.Fatal(err)
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			if (err == nil) != (mode == "configured") {
				t.Fatal("configured root binding", mode, err)
			}
		})
	}
}

func TestProducerDownloadPreviewOriginalHistoryAndNoExecutionLease(t *testing.T) {
	for _, mode := range []string{"committed", "superseded", "past_write_deadline"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := producerDownloadFixture(t)
			if mode == "superseded" {
				m.run.State = "superseded"
				m.store(t, &m.run)
			}
			if mode == "past_write_deadline" {
				m.history.OwnerWriteExpiresAt = systemExecutionStamp(f.initial.CreatedAt.Add(time.Minute))
				m.run.OwnerWriteExpiresAt = m.history.OwnerWriteExpiresAt
				m.store(t, &m.history)
				m.store(t, &m.run)
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, err := s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			deadline, _ := m.history.OwnerWriteExpiresAt.Time()
			if err != nil || !r.OwnerDeadline.Equal(deadline) || !reflect.DeepEqual(r.Manifest, f.initial.Manifest) || len(m.base.lockedStages) != 0 {
				t.Fatal("historical producer preview", err)
			}
			for _, q := range f.db.queries {
				if strings.Contains(q, "system_backup_producer_grants") || strings.Contains(q, "system_backup_producer_domains") {
					t.Fatal("retained read used current execution lease")
				}
			}
		})
	}
}

func TestProducerDownloadRejectsCorruptOrMissingHistory(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "foreign_scope", "projection", "digest", "oversize", "run_deadline", "manifest", "missing_schema", "session_revoked", "unsupported_system"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := producerDownloadFixture(t)
			table := "system_backup_producer_evidence_bindings"
			switch mode {
			case "missing":
				delete(m.rows, table)
			case "duplicate":
				m.rows[table] = append(m.rows[table], m.rows[table][0])
			case "foreign_scope":
				m.history.Scope.Database = "foreign_database"
				m.store(t, &m.history)
			case "projection":
				m.rows[table][0].Columns["owner_write_expires_at"] = f.db.now
			case "digest":
				m.rows[table][0].Columns["record_sha256"] = bytes.Repeat([]byte{1}, 32)
			case "oversize":
				m.rows[table][0].Columns["record_bytes"] = bytes.Repeat([]byte{1}, 32769)
			case "run_deadline":
				m.run.OwnerWriteExpiresAt = systemExecutionStamp(f.initial.OwnerDeadline.Add(time.Microsecond))
				m.store(t, &m.run)
			case "manifest":
				m.history.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
				m.store(t, &m.history)
			case "missing_schema":
				delete(m.base.metadata, "system_backup_producer_runs.evidence_id")
			case "session_revoked":
				f.db.sessionRevoked = true
			case "unsupported_system":
				f.db.record.Manifest.Identity.Type = "diagnostic"
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID); err == nil {
				t.Fatal("corrupt history authorized", mode)
			}
			if mode != "manifest" && m.base.chunkReads != 0 {
				t.Fatal("owner failure reached chunks", mode)
			}
		})
	}
}

func TestProducerDownloadActualAdmissionProviderAndRevokedResult(t *testing.T) {
	for _, slow := range []bool{false, true} {
		name := "normal"
		if slow {
			name = "sql_clock_advances_after_six_seconds"
		}
		t.Run(name, func(t *testing.T) { testProducerDownloadActualAdmissionProviderAndRevokedResult(t, slow) })
	}
}

func testProducerDownloadActualAdmissionProviderAndRevokedResult(t *testing.T, slow bool) {
	t.Helper()
	f, a, s, m := producerDownloadFixture(t)
	// Admit must exercise this adapter, not the old environment's no-op owner.
	var err error
	f.service, err = NewDownloadAdmissionService(s.Registry(), f.secret, &producerOwnerTestEnvironment{f.env, s})
	if err != nil {
		t.Fatal(err)
	}
	// Complete provider-file setup before admission, then verify the SAME
	// signed proof at a fresh SQL acceptance sample. No material limit changes.
	writeCommittedProviderToken(t, a)
	proofExpiry, materialLimit, capacityLimit := f.db.proof.ProofExpiresAt(), f.env.validUntil, f.env.reservationUntil
	if err = sampleAAdmissionProofTime(f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal("producer original proof at fresh acceptance time", err)
	}
	c, err := f.service.Admit(f.request)
	if err != nil {
		t.Fatal("producer admission", err)
	}
	deadline, localDeadline, claimUntil, retainUntil := c.deadlineAt, c.localDeadline, c.record.ClaimUntil, c.rows.retainUntil
	// Only this success-control fixture ticks its simulated database clock on
	// actual UTC queries AFTER the known commit. Original proof/receipt/claim,
	// material/capacity limits and the returned local deadline remain frozen.
	baseQuery := f.db.ownerQuery
	clockQueries := 0
	f.db.ownerQuery = func(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
		if strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)") || strings.HasPrefix(q, "SELECT UTC_TIMESTAMP(6)") || strings.HasPrefix(q, "SELECT user_id,subject,credential_hash,expires_at,revoked,UTC_TIMESTAMP(6)") {
			at := time.Now().UTC().Truncate(time.Microsecond)
			if at.Before(f.db.now) {
				t.Fatal("simulated SQL clock moved backwards")
			}
			f.db.now = at
			clockQueries++
		}
		return baseQuery(ctx, q, args)
	}
	ctx := bindCommittedFixture(t, a, c)
	if err = a.CheckCommittedDownload(ctx, c); err != nil {
		t.Fatal("producer committed authority", err)
	}
	if slow {
		time.Sleep(6 * time.Second)
		if time.Since(f.db.now) <= 5*time.Second {
			t.Fatal("six-second control did not outlive the old frozen SQL sample")
		}
	}
	store := &committedScopedReadStore{testStore: &testStore{data: m.object, present: true, info: ObjectInfo{Version: c.record.Ref.ImmutableVersion, SHA256: hash(m.object), Size: int64(len(m.object))}}, authority: a}
	if info, err := store.Stat(ctx, c.record.Ref); err != nil || !matchObject(c.Record(), info) {
		t.Fatal("producer exact-object stat", err)
	}
	got, err := OpenRange(ctx, c.Record().Manifest, c.Record().Ref, store, DownloadKeys{Authority: a, Keys: m.keys}, 0, int64(len(m.plain))-1)
	if err != nil || !bytes.Equal(got, m.plain) {
		t.Fatal("original producer ciphertext", err)
	}
	wipe(got)
	if len(store.scopes) != 3 || store.scopes[0].Operation != S3Stat || store.scopes[1].Length != c.record.Manifest.HeaderSize || store.scopes[2].Offset != c.record.Manifest.Chunks[0].FrameOffset || store.scopes[2].Length != c.record.Manifest.Chunks[0].FrameLength {
		t.Fatal("producer provider read escaped original frames", store.scopes)
	}
	results := resultFixture(t, f)
	results.c.Registry, results.c.Owners = s.Registry(), s
	f.db.sessionRevoked, f.db.userActive = true, false
	if err = results.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted"}); err != nil {
		t.Fatal("revoked producer result", err)
	}
	if f.db.resultInserts != 1 || f.db.record.Claim != "" {
		t.Fatal("producer result/claim not committed")
	}
	if clockQueries < 2 || !c.deadlineAt.Equal(deadline) || !c.localDeadline.Equal(localDeadline) || !c.record.ClaimUntil.Equal(claimUntil) || !c.rows.retainUntil.Equal(retainUntil) || !f.db.proof.ProofExpiresAt().Equal(proofExpiry) || !f.env.validUntil.Equal(materialLimit) || !f.env.reservationUntil.Equal(capacityLimit) {
		t.Fatal("clock sampling refreshed original authorization or retention limits")
	}
}

func TestProducerDownloadOptionalEmptyRangesRespectL3L4L5(t *testing.T) {
	f, _, s, m := sqlTaskOwnerFixture(t, "backup")
	for _, table := range taskDownloadSystemProducerTables {
		m.metadata[table+".evidence_id"] = "varchar"
	}
	tx, _, err := s.Registry().begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = s.LockOwnerReferences(context.Background(), tx, f.initial); err != nil {
		t.Fatal(err)
	}
	previous := 0
	for _, stage := range m.lockedStages {
		if stage < previous {
			t.Fatal("backwards optional producer empty-range lock", m.lockedStages)
		}
		previous = stage
	}
}

func TestProducerDownloadResultRejectsChangedOriginalBinding(t *testing.T) {
	for _, mode := range []string{"manifest", "original_deadline", "scope"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := producerDownloadFixture(t)
			var err error
			f.service, err = NewDownloadAdmissionService(s.Registry(), f.secret, &producerOwnerTestEnvironment{f.env, s})
			if err != nil {
				t.Fatal(err)
			}
			c, err := f.service.Admit(f.request)
			if err != nil {
				t.Fatal(err)
			}
			results := resultFixture(t, f)
			results.c.Registry, results.c.Owners = s.Registry(), s
			f.db.sessionRevoked, f.db.userActive = true, false
			switch mode {
			case "manifest":
				m.history.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
			case "original_deadline":
				m.history.OwnerWriteExpiresAt = systemExecutionStamp(f.initial.OwnerDeadline.Add(-time.Microsecond))
				m.run.OwnerWriteExpiresAt = m.history.OwnerWriteExpiresAt
				m.store(t, &m.run)
			case "scope":
				m.history.Scope.Database = "foreign_database"
			}
			m.store(t, &m.history)
			if err = results.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted"}); err == nil {
				t.Fatal("changed historical owner authorized result/release", mode)
			}
			if f.db.commits != 1 || f.db.resultInserts != 0 || f.db.record.Claim != c.record.Claim {
				t.Fatal("partial result survived invalid owner", mode)
			}
		})
	}
}
