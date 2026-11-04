package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// These tests use a database/sql transaction MODEL and synthetic receipt DATA.
// They do not mint an opaque native Source, prove full17, or claim field adoption.
type disabledSQLModel struct {
	pending, committed          []string
	calls, failAt               int
	active, lostCommit, missing bool
	mutate                      func(*originalDisabledInitializationRecord)
	record                      originalDisabledInitializationRecord
	head                        bool
}
type disabledConnector struct{ s *disabledSQLModel }

func (c disabledConnector) Connect(context.Context) (driver.Conn, error) {
	return &disabledConn{s: c.s}, nil
}
func (c disabledConnector) Driver() driver.Driver { return disabledDriver{} }

type disabledDriver struct{}

func (disabledDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type disabledConn struct{ s *disabledSQLModel }

func (c *disabledConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *disabledConn) Close() error { return nil }
func (c *disabledConn) Begin() (driver.Tx, error) {
	c.s.active = true
	c.s.pending = nil
	return disabledTx{c.s}, nil
}
func (c *disabledConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *disabledConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.s.calls++
	if c.s.failAt == c.s.calls {
		return nil, errors.New("injected SQL failure")
	}
	if !c.s.active {
		return nil, errors.New("write outside original transaction")
	}
	c.s.pending = append(c.s.pending, q)
	return disabledResult{}, nil
}

type disabledResult struct{}

func (disabledResult) LastInsertId() (int64, error) { return 42, nil }
func (disabledResult) RowsAffected() (int64, error) { return 1, nil }

type disabledTx struct{ s *disabledSQLModel }

func (t disabledTx) Commit() error {
	t.s.committed = append(t.s.committed, t.s.pending...)
	t.s.pending = nil
	t.s.active = false
	if t.s.lostCommit {
		return errors.New("lost COMMIT reply")
	}
	return nil
}
func (t disabledTx) Rollback() error { t.s.pending = nil; t.s.active = false; return nil }

type disabledRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *disabledRows) Columns() []string { return r.columns }
func (r *disabledRows) Close() error      { return nil }
func (r *disabledRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (c *disabledConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	row := func(values ...driver.Value) (driver.Rows, error) {
		columns := make([]string, len(values))
		for n := range columns {
			columns[n] = "value"
		}
		return &disabledRows{columns: columns, values: [][]driver.Value{values}}, nil
	}
	switch {
	case q == "SELECT CONNECTION_ID()":
		return row(int64(9))
	case strings.HasPrefix(q, "SELECT username,password_hash,role,is_active,auth_provider"):
		return row("admin", "pinned-bcrypt-hash", "admin", true, "local")
	case strings.HasPrefix(q, "SELECT head_revision"):
		if c.s.head {
			return row(int64(1))
		}
		return &disabledRows{columns: []string{"head_revision"}}, nil
	case strings.HasPrefix(q, "SELECT id,inline_payload"):
		if c.s.missing || len(c.s.committed) == 0 {
			return &disabledRows{columns: []string{"id", "raw", "sha", "size", "expires", "created", "updated", "rv", "chunks"}}, nil
		}
		r := c.s.record
		if c.s.mutate != nil {
			c.s.mutate(&r)
		}
		raw, e := canonical(r)
		if e != nil {
			return nil, e
		}
		return row(int64(42), raw, hash(raw), int64(len(raw)), r.RetainUntil, r.FinishedAt, r.FinishedAt, int64(1), int64(0))
	case strings.HasPrefix(q, "SELECT owner_target_public_id"):
		return row(c.s.record.InstallationID)
	case strings.HasPrefix(q, "SELECT chunk_index"):
		return &disabledRows{columns: []string{"chunk_index"}}, nil
	case strings.HasPrefix(q, "SELECT sample_at,reserved_bytes"):
		return row(c.s.record.StartedAt, int64(10))
	}
	return nil, errors.New("unexpected SQL: " + q)
}
func disabledModelDB(t *testing.T, s *disabledSQLModel) *sql.DB {
	t.Helper()
	db := sql.OpenDB(disabledConnector{s})
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { db.Close() })
	return db
}
func disabledRecordFixture() originalDisabledInitializationRecord {
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("a", 64)
	return originalDisabledInitializationRecord{Version: originalDisabledInitializationVersion, Operation: "sop_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RequestSHA256: digest, InstallationID: "installation_test", ConfigSHA256: digest, Head: HeadCAS{HeadRevision: 1, HeadRowVersion: 1, GrantRowVersion: 1, State: "active"}, Epoch: 7, SnapshotSHA256: digest, C1HistorySHA256: digest, AdoptionOperation: "actual-original-operation", InventorySHA256: digest, Domain: pd.DomainRecord{
		Scope: pd.Scope{ServerUUID: "00000000-0000-4000-8000-000000000001", Database: "model_database", Installation: "installation_test"},
		Epoch: "1", RowVersion: "1", State: "open", IssuerIdentityHash: pd.Hash(digest),
		Admission: pd.Admission{Unconfigured: &pd.UnconfiguredAdmission{
			Scenario: "unconfigured", DeploymentAdmissionID: "model-original-admission-1",
			CandidateHash: pd.Hash(digest), RegistrySetHash: pd.Hash(digest), RefSetHash: pd.Hash(digest),
			PolicyHash: pd.Hash(digest), ChannelProfileHash: pd.Hash(digest),
		}},
		AdmissionExpiresAt: c1stamp(now.Add(time.Minute)), CreatedAt: c1stamp(now), UpdatedAt: c1stamp(now),
	}, CurrentHealth: "unknown", HistoricalReferences: "authenticated_original_history", KEKAdmission: "absent", StartedAt: now, FinishedAt: now, DeadlineAt: now.Add(time.Minute), RetainUntil: now.Add(time.Hour)}
}
func disabledWriteFixture() (sec.OfflineBootstrapGrant, sec.DisabledInitializationPlan) {
	return sec.OfflineBootstrapGrant{InstallationID: "installation_test", UserID: 7, ConfigSHA256: strings.Repeat("a", 64), MatrixKey: "k8s-cluster", IdempotencyKey: "original-initialization-key"}, sec.DisabledInitializationPlan{Columns: []string{"origin_installation_id", "version", "enabled", "a", "b", "c", "d", "e", "f", "canonical_config_json"}, Values: []any{"installation_test", int64(1), false, 1, 2, 3, 4, 5, 6, []byte("{}")}}
}

func TestOriginalDisabledRowsRollbackAndLostCommitQueryOnly(t *testing.T) {
	g, plan := disabledWriteFixture()
	record := disabledRecordFixture()
	// A serialized model receipt must obey the SAME closed C1 DATA codec as
	// an actual readback. No native source/authority is manufactured here.
	domainRaw, fixtureErr := canonical(record.Domain)
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	var decodedDomain pd.DomainRecord
	if fixtureErr = pd.DecodeRecord(domainRaw, &decodedDomain); fixtureErr != nil || !reflect.DeepEqual(decodedDomain, record.Domain) {
		t.Fatalf("invalid synthetic domain DATA fixture: %v", fixtureErr)
	}
	fixtureRaw, fixtureErr := canonical(record)
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	var decodedRecord originalDisabledInitializationRecord
	if fixtureErr = decodeExact(fixtureRaw, &decodedRecord); fixtureErr != nil || !reflect.DeepEqual(decodedRecord, record) {
		t.Fatalf("invalid synthetic exact receipt DATA fixture: %v", fixtureErr)
	}
	for fail := 1; fail <= 6; fail++ {
		t.Run(string(rune('0'+fail)), func(t *testing.T) {
			s := &disabledSQLModel{failAt: fail}
			db := disabledModelDB(t, s)
			tx, e := db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			if originalDisabledWriteRows(context.Background(), tx, g, plan, record) == nil {
				t.Fatal("failure ignored")
			}
			tx.Rollback()
			if len(s.committed) != 0 || len(s.pending) != 0 {
				t.Fatal("partial initialization survived rollback")
			}
		})
	}
	s := &disabledSQLModel{lostCommit: true, record: record}
	db := disabledModelDB(t, s)
	tx, _ := db.Begin()
	if e := originalDisabledWriteRows(context.Background(), tx, g, plan, record); e != nil {
		t.Fatal(e)
	}
	if tx.Commit() == nil {
		t.Fatal("lost reply was not simulated")
	}
	before := s.calls
	read, _ := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	got, e := originalDisabledReadRecord(context.Background(), read, record.RequestSHA256, true)
	read.Rollback()
	if e != nil || !reflect.DeepEqual(got, record) || s.calls != before {
		t.Fatal("independent query rewrote operation or failed exact receipt", e)
	}
	if len(s.committed) != 6 {
		t.Fatalf("unexpected writes %d", len(s.committed))
	}
	for _, q := range s.committed {
		for _, forbidden := range []string{"kek_admissions", "kek_fences", "producer_domains", "dependency_health", "control_health", "execution_readiness", "system_backup_v2_backups"} {
			if strings.Contains(q, forbidden) {
				t.Fatalf("unverified initialization wrote %s", forbidden)
			}
		}
	}
	for _, mutate := range []func(*originalDisabledInitializationRecord){func(r *originalDisabledInitializationRecord) { r.CurrentHealth = "healthy" }, func(r *originalDisabledInitializationRecord) { r.KEKAdmission = "admitted" }, func(r *originalDisabledInitializationRecord) { r.Domain.State = "closed" }} {
		s.mutate = mutate
		read, _ = db.Begin()
		if _, e = originalDisabledReadRecord(context.Background(), read, record.RequestSHA256, true); e == nil {
			t.Fatal("false health/admission/domain accepted")
		}
		read.Rollback()
	}
	s.mutate = nil
	s.missing = true
	read, _ = db.Begin()
	if _, e = originalDisabledReadRecord(context.Background(), read, record.RequestSHA256, true); !errors.Is(e, ErrCommitUnknown) {
		t.Fatal("absence became a retry/success", e)
	}
	read.Rollback()
	if s.calls != before {
		t.Fatal("unknown query issued a write")
	}
}

func TestOriginalDisabledEntryRejectsMissingOriginalOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, i := range []*Installer{nil, {}} {
		if got, e := i.InitializeOriginalDisabledUnverified(ctx, nil, EnrollmentPin{}, OriginalDisabledInitializationInputs{}); e == nil || got.State != "" {
			t.Fatal("missing original sources authorized initialization")
		}
	}
	for _, in := range []OriginalDisabledInitializationInputs{{Production: &OriginalC1SigningProduction{}}, {Production: &OriginalC1SigningProduction{}, Recovered: &PreparedOriginalWriterSet{}, Coverage: &a.SQLCoverageOwnerPreparation{}, CapacityDB: &sql.DB{}}} {
		if _, e := (&Installer{}).InitializeOriginalDisabledUnverified(ctx, nil, EnrollmentPin{}, in); e == nil {
			t.Fatal("zero/reconstructed owner accepted")
		}
	}
}

func TestOriginalC1OpenDomainIsNotHead1WritePermission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := &disabledSQLModel{}
	db := disabledModelDB(t, s)
	tx, _ := db.Begin()
	defer tx.Rollback()
	i := &Installer{plan: Plan{LocalAdminUsername: "admin", EnrollmentID: "enrollment"}}
	op := &authenticatedOperator{installer: i, ctx: ctx, until: time.Now().Add(time.Minute), userID: 7, password: "pinned-bcrypt-hash"}
	p := &OriginalC1Production{ctx: ctx, operator: op, until: op.until, request: &originalRequest{grant: sec.OfflineBootstrapGrant{InstallationID: "installation_test"}}}
	p.origin = p
	stage := &originalC1DomainSession{source: p, connection: 9}
	if e := stage.current(ctx, tx); e != nil {
		t.Fatal("head0 fixture rejected", e)
	}
	s.head = true
	if e := stage.current(ctx, tx); e == nil {
		t.Fatal("OPEN domain accepted head1 original write authority")
	}
}

func TestOriginalDisabledMetadataRejectsForeignTransactionAndContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := &disabledSQLModel{}
	db := disabledModelDB(t, s)
	tx, _ := db.Begin()
	defer tx.Rollback()
	r := &originalDisabledMetadataReservation{ctx: ctx, tx: tx, report: sec.CapacityReport{ObservedAt: time.Now().UTC()}, capacity: 100, floor: 10}
	other, _ := db.Begin()
	defer other.Rollback()
	if r.recheck(ctx, other, time.Now()) == nil {
		t.Fatal("foreign transaction accepted")
	}
	changed, stop := context.WithCancel(ctx)
	defer stop()
	if r.recheck(changed, tx, time.Now()) == nil {
		t.Fatal("foreign context accepted")
	}
	r.report.ObservedAt = time.Now().Add(-6 * time.Second)
	if r.recheck(ctx, tx, time.Now()) == nil {
		t.Fatal("old native capacity observation renewed")
	}
}

func TestOriginalDisabledAuthorityKeepsOriginalIdentityWindowAndRevocation(t *testing.T) {
	f := newAuthorityFixture(t)
	r, e := readRequest(f.i, f.files)
	if e != nil {
		t.Fatal(e)
	}
	defer r.observer.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := currentAuthority{cas: HeadCAS{HeadRevision: 1, HeadRowVersion: 1, GrantRowVersion: 1, State: "active"}, record: f.record}
	h.head.NotBefore, h.head.Until = f.record.NotBefore, f.record.Until
	if !originalDisabledAuthority(r, h, now) {
		t.Fatal("original identity fixture mismatch")
	}
	for name, change := range map[string]func(*currentAuthority){
		"wrong_installation": func(h *currentAuthority) { h.record.Target.InstallationID = "installation_foreign" },
		"wrong_config":       func(h *currentAuthority) { h.record.ConfigSHA256 = strings.Repeat("0", 64) },
		"expired_record":     func(h *currentAuthority) { h.record.Until = now },
		"expired_head":       func(h *currentAuthority) { h.head.Until = now },
		"revoked":            func(h *currentAuthority) { h.cas.State = "revoked" },
		"head0":              func(h *currentAuthority) { h.cas.HeadRevision = 0 },
		"other_head":         func(h *currentAuthority) { h.cas.HeadRevision = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := h
			change(&bad)
			if originalDisabledAuthority(r, bad, now) {
				t.Fatal("invalid original authority accepted")
			}
		})
	}
}

func TestOriginalDisabledRequiresExactSeventeenCommittedJournalMembers(t *testing.T) {
	digest := strings.Repeat("a", 64)
	cfg := a.SQLCoverageOwnerConfig{Adoption: a.CoverageOwnerPin{Source: reg.SourceRecord{RecordID: "adoption"}}}
	expected := originalAdoptionCommitExpected{Version: "original-adoption-commit-expectation.v1", Operation: "original", InstallationID: "installation_test", ServerUUID: "server", Database: "database", InventorySHA256: digest, OldEpoch: 6, NewEpoch: 7, ControlRows: map[string]string{"adoption": digest}, Bindings: []reg.BindingFacts{}, References: []reg.Reference{}}
	for _, partition := range []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune} {
		expected.Sources = append(expected.Sources, reg.CoverageSource{Partition: partition, SourceID: string(partition)})
		for _, kind := range []string{"original_sql_census", "immutable_external_snapshot", "original_writer_fence", "historical_backfill"} {
			id := string(partition) + ":" + kind
			cfg.Witnesses = append(cfg.Witnesses, a.CoverageWitnessPin{CoverageOwnerPin: a.CoverageOwnerPin{Source: reg.SourceRecord{RecordID: id}}, Partition: partition, Kind: kind})
			expected.ControlRows[id] = digest
		}
	}
	snapshot := reg.Snapshot{InstallationID: expected.InstallationID, Database: reg.DatabaseIdentity{ServerUUID: expected.ServerUUID, Database: expected.Database}, Epoch: 7, Coverage: expected.Sources, Bindings: expected.Bindings, References: expected.References}
	journal := func(e originalAdoptionCommitExpected) OriginalWriterJournalInspection {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return OriginalWriterJournalInspection{Operation: "original", InventorySHA256: digest, Records: []originalWriterJournalRecord{{Action: "adoption_commit_readback", Data: raw}, {Action: "original_sources_released_readback"}}}
	}
	if _, e := originalDisabledAdoptedJournal(journal(expected), snapshot, cfg); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*originalAdoptionCommitExpected){"wrong_installation": func(e *originalAdoptionCommitExpected) { e.InstallationID = "installation_foreign" }, "wrong_epoch": func(e *originalAdoptionCommitExpected) { e.NewEpoch++ }, "missing_one": func(e *originalAdoptionCommitExpected) {
		e.ControlRows = map[string]string{}
		for k, v := range expected.ControlRows {
			if k != "adoption" {
				e.ControlRows[k] = v
			}
		}
	}, "foreign_member": func(e *originalAdoptionCommitExpected) {
		e.ControlRows = map[string]string{}
		for k, v := range expected.ControlRows {
			if k != "adoption" {
				e.ControlRows[k] = v
			}
		}
		e.ControlRows["foreign"] = digest
	}} {
		t.Run(name, func(t *testing.T) {
			bad := expected
			change(&bad)
			if _, e := originalDisabledAdoptedJournal(journal(bad), snapshot, cfg); e == nil {
				t.Fatal("incomplete/foreign adoption journal accepted")
			}
		})
	}
}
