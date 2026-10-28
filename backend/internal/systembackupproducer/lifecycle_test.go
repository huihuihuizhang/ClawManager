package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// commandMemory implements only the closed SQL emitted by record_sql.go and
// snapshots it at BEGIN. It models rollback/replay, not InnoDB locking or FKs.
type commandMemory struct {
	t         *testing.T
	rows      map[string][]StoredRecord
	before    map[string][]StoredRecord
	events    []string
	keyEvents []string
}

func cloneMemory(rows map[string][]StoredRecord) map[string][]StoredRecord {
	copy := map[string][]StoredRecord{}
	for table, rs := range rows {
		for _, r := range rs {
			next := copyStored(r)
			for k, v := range next.Columns {
				if b, ok := v.([]byte); ok {
					next.Columns[k] = append([]byte(nil), b...)
				}
			}
			copy[table] = append(copy[table], next)
		}
	}
	return copy
}
func (m *commandMemory) seed(record any) {
	row, e := EncodeStoredRecord(record)
	if e != nil {
		m.t.Fatal(e)
	}
	m.rows[row.Table] = append(m.rows[row.Table], row)
}
func sqlEqual(a, b any) bool { return reflect.DeepEqual(sqlRecordValue(a), sqlRecordValue(b)) }
func (m *commandMemory) query(q string, args []driver.NamedValue) (driver.Rows, error) {
	parts := strings.SplitN(q, " FROM ", 2)
	if len(parts) != 2 {
		return nil, ErrInvalid
	}
	cols := strings.Split(strings.TrimPrefix(parts[0], "SELECT "), ", ")
	rest := strings.SplitN(parts[1], " WHERE ", 2)
	if len(rest) != 2 || !strings.HasSuffix(rest[1], " FOR UPDATE") {
		return nil, ErrInvalid
	}
	table := rest[0]
	conditions := strings.Split(strings.TrimSuffix(rest[1], " FOR UPDATE"), " AND ")
	if len(conditions) != len(args) {
		return nil, ErrInvalid
	}
	m.events = append(m.events, "lock:"+table)
	if in(table, "system_backup_producer_grants", "system_backup_producer_runs") {
		m.keyEvents = append(m.keyEvents, table+":"+args[1].Value.(string))
	}
	out := &storedRows{names: cols}
	for _, row := range m.rows[table] {
		match := true
		for i, c := range conditions {
			key := strings.TrimSuffix(c, " = ?")
			match = match && sqlEqual(row.Columns[key], args[i].Value)
		}
		if match {
			values := make([]driver.Value, len(cols))
			for i, c := range cols {
				values[i] = sqlRecordValue(row.Columns[c])
			}
			out.data = append(out.data, values)
		}
	}
	return out, nil
}
func (m *commandMemory) exec(q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(q, "INSERT INTO ") {
		body := strings.TrimPrefix(q, "INSERT INTO ")
		parts := strings.SplitN(body, " (", 2)
		table := parts[0]
		cols := strings.Split(strings.SplitN(parts[1], ") VALUES", 2)[0], ", ")
		if len(cols) != len(args) {
			return nil, ErrInvalid
		}
		row := StoredRecord{Table: table, Columns: map[string]any{}}
		for i, col := range cols {
			row.Columns[col] = args[i].Value
		}
		m.rows[table] = append(m.rows[table], row)
		m.events = append(m.events, "insert:"+table)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, "UPDATE ") {
		body := strings.TrimPrefix(q, "UPDATE ")
		parts := strings.SplitN(body, " SET ", 2)
		table := parts[0]
		parts = strings.SplitN(parts[1], " WHERE ", 2)
		sets := strings.Split(parts[0], ", ")
		where := strings.Split(parts[1], " AND ")
		if len(args) != len(sets)+len(where) {
			return nil, ErrInvalid
		}
		affected := int64(0)
		for _, row := range m.rows[table] {
			match := true
			for i, c := range where {
				col := strings.TrimSuffix(c, " <=> ?")
				match = match && sqlEqual(row.Columns[col], args[len(sets)+i].Value)
			}
			if match {
				for i, c := range sets {
					row.Columns[strings.TrimSuffix(c, " = ?")] = args[i].Value
				}
				affected++
			}
		}
		m.events = append(m.events, "update:"+table)
		return driver.RowsAffected(affected), nil
	}
	return nil, ErrInvalid
}

type commandTestEnvironment struct {
	db               *fakeDB
	memory           *commandMemory
	fail             string
	management       bool
	termination      *Hash
	alter            func(*CommandAdmission)
	wait             time.Duration
	reserves         int
	costs            []uint64
	rechecks         int
	noReport         bool
	installationWait time.Duration
}

func (e *commandTestEnvironment) phase(name string) error {
	e.memory.events = append(e.memory.events, name)
	if e.fail == name {
		return ErrUnavailable
	}
	return nil
}
func (e *commandTestEnvironment) Prepare(context.Context, CommandRequest) (PreparedCommand, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedCommand{}, err
	}
	prepared := PreparedCommand{Session: e}
	if !e.noReport {
		report := e.db.now
		prepared.CapacityObservedAt = &report
	}
	return prepared, nil
}
func (e *commandTestEnvironment) LockInstallation(context.Context, SQL, CommandRequest) error {
	e.db.now = e.db.now.Add(e.installationWait)
	return e.phase("installation")
}
func (e *commandTestEnvironment) Authenticate(_ context.Context, _ SQL, r CommandRequest, _ DomainRecord) (CommandAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return CommandAdmission{}, err
	}
	h, _ := CommandHashes(r)
	a := CommandAdmission{RequestHash: h.Request, IdentityHash: r.ActorIdentityHash, Deadlines: []time.Time{e.db.now.Add(5 * time.Minute)}, Management: e.management, HistoricalReceiptRead: true, TerminationDecisionHash: e.termination, ReceiptRetentionUntil: Timestamp(e.db.now.Add(24 * time.Hour).Format(timeLayout)), AdditionalCost: "65536"}
	if e.alter != nil {
		e.alter(&a)
	}
	return a, nil
}
func (e *commandTestEnvironment) LockHosts(context.Context, SQL, CommandRequest) error {
	return e.phase("hosts")
}
func (e *commandTestEnvironment) LockReferences(context.Context, SQL, CommandRequest) error {
	return e.phase("references")
}
func (e *commandTestEnvironment) Reserve(_ context.Context, _ SQL, _ CommandRequest, cost uint64) error {
	if err := e.phase("reserve"); err != nil {
		return err
	}
	e.reserves++
	e.costs = append(e.costs, cost)
	e.db.now = e.db.now.Add(e.wait)
	return nil
}
func (e *commandTestEnvironment) Audit(_ context.Context, _ SQL, _ CommandRequest, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *commandTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ CommandRequest, f CommandFacts, _ time.Time) error {
	e.rechecks++
	if !f.Replayed {
		if f.Target == nil || len(f.Grants) == 0 || len(f.Runs) == 0 {
			return ErrInvalid
		}
	}
	return e.phase("recheck")
}

func commandFixture(t *testing.T, name string) CommandRequest {
	t.Helper()
	for _, f := range fixtures(t).Commands {
		if f.ID == name {
			r, e := DecodeCommand(f.Value)
			if e != nil {
				t.Fatal(e)
			}
			return r
		}
	}
	t.Fatal("missing command")
	return CommandRequest{}
}
func setupCommands(t *testing.T) (*Lifecycle, *fakeDB, *commandTestEnvironment, *commandMemory) {
	t.Helper()
	runner, db, _ := setupTx(t)
	db.now = db.now.Add(2 * time.Second)
	m := &commandMemory{t: t, rows: map[string][]StoredRecord{}}
	m.seed(recordFixture(t, "DomainRecord"))
	db.queryRecord = m.query
	db.execRecord = m.exec
	db.beginRecord = func() { m.before = cloneMemory(m.rows) }
	db.commitRecord = func() { m.before = nil }
	db.rollbackRecord = func() { m.rows = m.before; m.before = nil }
	env := &commandTestEnvironment{db: db, memory: m, management: true}
	service, err := NewLifecycle(runner.db, runner.scope, env)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return db.now }
	return service, db, env, m
}
func loadMemoryRecord(t *testing.T, m *commandMemory, out any, index int) {
	t.Helper()
	s, e := storageFor(out)
	if e != nil {
		t.Fatal(e)
	}
	row := m.rows[s.table][index]
	scope := commandFixture(t, "acquire").Scope
	if e = DecodeStoredRecord(row, scope, out); e != nil {
		t.Fatal(e)
	}
}
func requireAcquire(t *testing.T, s *Lifecycle) CommandResult {
	t.Helper()
	r, e := s.Execute(context.Background(), commandFixture(t, "acquire"), nil)
	if e != nil || r.Handle == nil {
		t.Fatal("acquire", e)
	}
	return r
}

func TestLifecycleAcquireRenewRevokeAndReplay(t *testing.T) {
	s, _, env, m := setupCommands(t)
	acquire := requireAcquire(t, s)
	if acquire.Replayed || env.reserves != 1 || acquire.Receipt.ChargedBytes != "524288" {
		t.Fatal("acquire accounting", acquire.Receipt.ChargedBytes, env.costs)
	}
	want := []string{"prepare", "installation", "lock:system_backup_producer_domains", "authenticate", "lock:system_backup_producer_command_receipts", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "hosts", "lock:system_backup_producer_targets", "references", "reserve", "audit:intent", "insert:system_backup_producer_grants", "insert:system_backup_producer_runs", "insert:system_backup_producer_targets", "insert:system_backup_producer_command_receipts", "audit:result", "recheck"}
	if !reflect.DeepEqual(m.events, want) {
		t.Fatal("phase order", m.events)
	}
	var before RunRecord
	loadMemoryRecord(t, m, &before, 0)
	env.noReport = true // exact historical replay must not require new capacity
	replay, e := s.Execute(context.Background(), commandFixture(t, "acquire"), nil)
	if e != nil || !replay.Replayed || replay.Handle != nil || !reflect.DeepEqual(replay.Receipt, acquire.Receipt) || env.reserves != 1 {
		t.Fatal("acquire replay", e)
	}
	env.noReport = false
	renew := commandFixture(t, "renew")
	renewed, e := s.Execute(context.Background(), renew, acquire.Handle)
	if e != nil || renewed.Handle == nil || renewed.Receipt.Outcome.GrantRowVersion != "2" || renewed.Receipt.ChargedBytes != "262144" {
		t.Fatal("renew", e)
	}
	var after RunRecord
	loadMemoryRecord(t, m, &after, 0)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("renew changed original run/deadlines")
	}
	replay, e = s.Execute(context.Background(), renew, acquire.Handle)
	if e != nil || !replay.Replayed || replay.Handle != nil || !reflect.DeepEqual(replay.Receipt, renewed.Receipt) || env.reserves != 2 {
		t.Fatal("renew replay", e)
	}
	revoke := commandFixture(t, "revoke")
	revoke.Expected.GrantRowVersion = "2"
	revoked, e := s.Execute(context.Background(), revoke, nil)
	if e != nil || revoked.Handle != nil || revoked.Receipt.Outcome.GrantRowVersion != "3" {
		t.Fatal("revoke", e)
	}
	var grant GrantRecord
	loadMemoryRecord(t, m, &grant, 0)
	if grant.State != "revoked" {
		t.Fatal("not revoked")
	}
	replay, e = s.Execute(context.Background(), revoke, nil)
	if e != nil || !replay.Replayed || env.reserves != 3 {
		t.Fatal("revoke replay", e)
	}
	loadMemoryRecord(t, m, &after, 0)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("revoke changed run history")
	}
	if _, e = json.Marshal(acquire.Handle); !errors.Is(e, ErrInvalid) {
		t.Fatal("bearer handle serialization")
	}
}

func TestLifecycleTakeover(t *testing.T) {
	for _, mode := range []string{"expired", "termination", "unreviewed_termination", "live_without_termination", "reused_evidence", "target_profile_change", "sorted_ids", "pending_history"} {
		t.Run(mode, func(t *testing.T) {
			s, db, env, m := setupCommands(t)
			requireAcquire(t, s)
			request := commandFixture(t, "takeover")
			var original RunRecord
			loadMemoryRecord(t, m, &original, 0)
			if mode == "pending_history" {
				observed := Timestamp(db.now.Format(timeLayout))
				expires := Timestamp(db.now.Add(time.Minute).Format(timeLayout))
				original.State = "pending"
				original.RowVersion = "2"
				original.ObservedAt = &observed
				original.ObservationExpiresAt = &expires
				row, e := EncodeStoredRecord(&original)
				if e != nil {
					t.Fatal(e)
				}
				m.rows[row.Table][0] = row
			}
			switch mode {
			case "expired":
				db.now = db.now.Add(4 * time.Minute)
				lease := Timestamp(db.now.Add(time.Minute).Format(timeLayout))
				request.LeaseExpiresAt = &lease
				request.Next.OwnerWriteExpiresAt = Timestamp(db.now.Add(2 * time.Minute).Format(timeLayout))
			case "termination", "unreviewed_termination", "reused_evidence", "target_profile_change", "sorted_ids", "pending_history":
				h := Hash(strings.Repeat("c", 64))
				request.TerminationDecisionHash = &h
				if mode != "unreviewed_termination" {
					env.termination = &h
				}
				if mode == "reused_evidence" {
					request.Next.EvidenceID = original.EvidenceID
				}
				if mode == "target_profile_change" {
					request.Target.EvaluatorProfileHash = Hash(strings.Repeat("c", 64))
				}
				if mode == "sorted_ids" {
					request.Next.GrantID = "aaa_grant"
					request.Next.RunID = "aaa_run"
					m.keyEvents = nil
				}
			}
			result, e := s.Execute(context.Background(), request, nil)
			if in(mode, "unreviewed_termination", "live_without_termination", "reused_evidence") {
				if e == nil || result.Handle != nil || len(m.rows["system_backup_producer_grants"]) != 1 {
					t.Fatal("invalid takeover", e)
				}
				return
			}
			if e != nil || result.Handle == nil || result.Receipt.Outcome.TargetGeneration != "2" || result.Receipt.ChargedBytes != "442368" {
				t.Fatal("takeover", e)
			}
			if mode == "sorted_ids" {
				want := []string{"system_backup_producer_grants:aaa_grant", "system_backup_producer_grants:synthetic_grant_1", "system_backup_producer_runs:aaa_run", "system_backup_producer_runs:synthetic_run_1"}
				if !reflect.DeepEqual(m.keyEvents, want) {
					t.Fatal("lock order", m.keyEvents)
				}
			}
			var old, next RunRecord
			loadMemoryRecord(t, m, &old, 0)
			loadMemoryRecord(t, m, &next, 1)
			if old.OwnerWriteExpiresAt != original.OwnerWriteExpiresAt || !reflect.DeepEqual(old.ObservedAt, original.ObservedAt) || !reflect.DeepEqual(old.ObservationExpiresAt, original.ObservationExpiresAt) || old.State != "superseded" || next.EvidenceID == old.EvidenceID || next.ObservedAt != nil || next.State != "acquired" {
				t.Fatal("history or new run binding")
			}
			var target TargetRecord
			loadMemoryRecord(t, m, &target, 0)
			if target.Generation != "2" || target.ResultVersion != "0" || target.CurrentRunID != next.RunID {
				t.Fatal("target fence")
			}
		})
	}
}

func TestLifecycleFailuresRollbackAndDoNotMint(t *testing.T) {
	for _, name := range []string{"prepare", "installation", "authenticate", "hosts", "references", "reserve", "audit:intent", "audit:result", "recheck", "request_binding", "identity_binding", "no_deadlines", "expired_identity", "invalid_capacity", "capacity_wait", "retention_expiry", "cost_overflow", "wrong_issuer", "wrong_admission", "domain_closed", "domain_epoch", "target_exists", "id_exists", "commit_unknown", "commit_expired", "no_pinned_report", "installation_wait"} {
		t.Run(name, func(t *testing.T) {
			s, db, env, m := setupCommands(t)
			request := commandFixture(t, "acquire")
			wantHistorical := false
			switch name {
			case "no_pinned_report":
				env.noReport = true
			case "installation_wait":
				env.installationWait = 6 * time.Second
			case "request_binding":
				env.alter = func(a *CommandAdmission) { a.RequestHash = Hash(strings.Repeat("c", 64)) }
			case "identity_binding":
				env.alter = func(a *CommandAdmission) { a.IdentityHash = Hash(strings.Repeat("c", 64)) }
			case "no_deadlines":
				env.alter = func(a *CommandAdmission) { a.Deadlines = nil }
			case "expired_identity":
				env.alter = func(a *CommandAdmission) { a.Deadlines = []time.Time{db.now} }
			case "invalid_capacity":
				env.wait = 6 * time.Second
			case "capacity_wait":
				db.workWait = 2 * time.Second
			case "retention_expiry":
				env.alter = func(a *CommandAdmission) { a.ReceiptRetentionUntil = Timestamp(db.now.Format(timeLayout)) }
			case "cost_overflow":
				env.alter = func(a *CommandAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "wrong_issuer":
				request.Next.IssuerIdentityHash = Hash(strings.Repeat("c", 64))
			case "wrong_admission":
				request.Next.Admission.Unconfigured.PolicyHash = Hash(strings.Repeat("c", 64))
			case "domain_closed":
				domain := recordFixture(t, "DomainRecord").(*DomainRecord)
				domain.State = "closed"
				m.rows = map[string][]StoredRecord{}
				m.seed(domain)
			case "domain_epoch":
				request.ExpectedDomainEpoch = "2"
			case "target_exists":
				m.seed(recordFixture(t, "TargetRecord"))
			case "id_exists":
				m.seed(recordFixture(t, "GrantRecord"))
			case "commit_unknown":
				db.commitError = true
			case "commit_expired":
				db.commitWait = 6 * time.Second
				wantHistorical = true
			default:
				env.fail = name
			}
			before := cloneMemory(m.rows)
			result, e := s.Execute(context.Background(), request, nil)
			if e == nil || result.Handle != nil {
				t.Fatal("failure minted", e)
			}
			if name == "commit_unknown" {
				if !errors.Is(e, ErrCommitUnknown) || result.Receipt.RequestHash != "" {
					t.Fatal("uncertain commit returned receipt", e)
				}
				return
			}
			if wantHistorical {
				if !errors.Is(e, ErrCommittedExpired) || result.Receipt.RequestHash == "" {
					t.Fatal("lost known commit", e)
				}
				return
			}
			if !reflect.DeepEqual(before, m.rows) || db.commits != 0 {
				t.Fatal("failed command persisted partial state", e, m.events)
			}
		})
	}
}

func TestLifecycleRenewAuthorizationAndReplayConflict(t *testing.T) {
	for _, name := range []string{"no_handle", "foreign_handle", "stale_version", "expired_lease", "lease_beyond_authorization", "wrong_actor", "changed_same_key", "revoked_grant", "revoke_expired", "revoke_without_management", "replay_without_read_authority", "revoke_profile_mismatch"} {
		t.Run(name, func(t *testing.T) {
			s, db, env, m := setupCommands(t)
			first := requireAcquire(t, s)
			request := commandFixture(t, "renew")
			handle := first.Handle
			switch name {
			case "replay_without_read_authority":
				request = commandFixture(t, "acquire")
				handle = nil
				env.alter = func(a *CommandAdmission) { a.HistoricalReceiptRead = false }
			case "revoke_profile_mismatch":
				request = commandFixture(t, "revoke")
				handle = nil
				request.Target.EvaluatorProfileHash = Hash(strings.Repeat("c", 64))
			case "no_handle":
				handle = nil
			case "foreign_handle":
				copy := *handle
				copy.issuer = &Lifecycle{}
				handle = &copy
			case "stale_version":
				request.Expected.GrantRowVersion = "2"
			case "expired_lease":
				db.now = db.now.Add(4 * time.Minute)
			case "lease_beyond_authorization":
				v := Timestamp("2026-09-30T02:00:00.000001Z")
				request.LeaseExpiresAt = &v
			case "wrong_actor":
				request.ActorIdentityHash = Hash(strings.Repeat("c", 64))
			case "changed_same_key":
				request = commandFixture(t, "acquire")
				request.Next.InputHash = Hash(strings.Repeat("c", 64))
				handle = nil
			case "revoked_grant":
				if _, e := s.Execute(context.Background(), commandFixture(t, "revoke"), nil); e != nil {
					t.Fatal(e)
				}
				request.Expected.GrantRowVersion = "2"
				copy := *handle
				copy.version = "2"
				handle = &copy
			case "revoke_expired":
				db.now = db.now.Add(11 * time.Minute)
				request = commandFixture(t, "revoke")
				handle = nil
			case "revoke_without_management":
				request = commandFixture(t, "revoke")
				handle = nil
				env.management = false
			}
			before := cloneMemory(m.rows)
			result, e := s.Execute(context.Background(), request, handle)
			if name == "revoke_expired" {
				if e != nil || result.Handle != nil {
					t.Fatal("expired grant management revoke", e)
				}
				return
			}
			if e == nil || result.Handle != nil || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("invalid lifecycle accepted", name, e)
			}
		})
	}
}

func TestLifecycleConstructorAndCostBounds(t *testing.T) {
	s, _, _, _ := setupCommands(t)
	if _, e := NewLifecycle(s.db, s.scope, nil); !errors.Is(e, ErrGuardRequired) {
		t.Fatal("missing integration")
	}
	var missing *commandTestEnvironment
	if _, e := NewLifecycle(s.db, s.scope, missing); !errors.Is(e, ErrGuardRequired) {
		t.Fatal("typed nil")
	}
	var h ExecutionHandle
	if json.Unmarshal([]byte(`{}`), &h) == nil {
		t.Fatal("forged execution handle")
	}
	if _, e := commandCost(^uint64(0), []any{&GrantRecord{}}); e == nil {
		t.Fatal("capacity overflow")
	}
}
