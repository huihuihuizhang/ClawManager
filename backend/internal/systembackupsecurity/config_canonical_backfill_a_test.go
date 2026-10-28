package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Independent transaction transport, not InnoDB or authenticated runtime
// grants. It preserves committed rows across later observation rollbacks and
// models BOTH committed and rejected outcomes behind an identical lost ACK.
type maintenanceServiceModel struct {
	store                                  *maintenanceReceiptSQLState
	ops                                    []string
	commitMode, failAudit                  string
	commits, rollbacks, fills, auditWrites int
	onCommit                               func()
	auditSQLPrecision                      bool
}
type maintenanceServiceConnector struct{ m *maintenanceServiceModel }

func (maintenanceServiceConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c maintenanceServiceConnector) Connect(context.Context) (driver.Conn, error) {
	return &maintenanceServiceConn{maintenanceReceiptConn: maintenanceReceiptConn{backfillLockedConn: backfillLockedConn{s: c.m.store.base}, s: c.m.store}, m: c.m}, nil
}

type maintenanceServiceConn struct {
	maintenanceReceiptConn
	m            *maintenanceServiceModel
	priorReceipt map[string]driver.Value
	priorAudits  map[int64][]driver.Value
	priorCells   map[string]driver.Value
}

func maintenanceACopyValue(v driver.Value) driver.Value {
	if b, ok := v.([]byte); ok {
		return append([]byte(nil), b...)
	}
	return v
}
func maintenanceACopyCells(in map[string]driver.Value) map[string]driver.Value {
	if in == nil {
		return nil
	}
	out := map[string]driver.Value{}
	for k, v := range in {
		out[k] = maintenanceACopyValue(v)
	}
	return out
}
func (c *maintenanceServiceConn) Begin() (driver.Tx, error) {
	c.priorReceipt = maintenanceACopyCells(c.m.store.receipt)
	c.priorCells = maintenanceACopyCells(c.m.store.base.cells)
	c.priorAudits = map[int64][]driver.Value{}
	for id, cells := range c.m.store.audits {
		copy := make([]driver.Value, len(cells))
		for n, v := range cells {
			copy[n] = maintenanceACopyValue(v)
		}
		c.priorAudits[id] = copy
	}
	return c, nil
}
func (c *maintenanceServiceConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *maintenanceServiceConn) restore() {
	c.m.store.receipt = c.priorReceipt
	c.m.store.audits = c.priorAudits
	c.m.store.base.cells = c.priorCells
}
func (c *maintenanceServiceConn) Rollback() error { c.m.rollbacks++; c.restore(); return nil }
func (c *maintenanceServiceConn) Commit() error {
	c.m.commits++
	c.m.ops = append(c.m.ops, "commit")
	if c.m.commitMode == "rejected-lost-ack" {
		c.restore()
	}
	if c.m.onCommit != nil {
		c.m.onCommit()
	}
	if c.m.commitMode != "" {
		return errors.New("private commit diagnostic")
	}
	return nil
}

type maintenanceServiceResult struct{ id int64 }

func (r maintenanceServiceResult) LastInsertId() (int64, error) { return r.id, nil }
func (maintenanceServiceResult) RowsAffected() (int64, error)   { return 1, nil }
func (c *maintenanceServiceConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	m := c.m
	if q == "INSERT INTO audit_logs(user_id,action,resource_type,resource_id,details,created_at) VALUES(NULL,?,'system_backup',NULL,?,UTC_TIMESTAMP())" || q == "INSERT INTO audit_logs(user_id,action,resource_type,resource_id,details,created_at) VALUES(NULL,?,'system_backup',NULL,?,UTC_TIMESTAMP(6))" {
		if len(args) != 2 {
			return nil, errors.New("audit arity")
		}
		action, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("audit action")
		}
		phase := strings.TrimPrefix(action, "system_backup.config_canonical_backfill.")
		if phase != "intent" && phase != "result" {
			return nil, errors.New("foreign audit")
		}
		m.ops = append(m.ops, "audit-"+phase)
		if m.failAudit == phase {
			return nil, errors.New("private audit diagnostic")
		}
		body, ok := args[1].Value.(string)
		if !ok || !json.Valid([]byte(body)) {
			return nil, errors.New("audit body")
		}
		m.auditWrites++
		id := int64(10 + len(m.store.audits) + 1)
		created := m.store.base.now.Add(-time.Microsecond)
		if m.auditSQLPrecision {
			created = m.store.base.now.Truncate(time.Second)
			if strings.Contains(q, "UTC_TIMESTAMP(6)") {
				created = m.store.base.now.Round(time.Second)
			}
		}
		m.store.audits[id] = []driver.Value{nil, action, "system_backup", nil, []byte(body), created}
		return maintenanceServiceResult{id}, nil
	}
	if q == "UPDATE system_backup_v2_configs SET canonical_config_json=? WHERE id=? AND origin_installation_id=? AND version=? AND canonical_config_json IS NULL AND config_sha256=? AND config_size_bytes=?" {
		if len(args) != 6 || args[1].Value != m.store.base.facts.RowID || args[2].Value != m.store.base.facts.InstallationID || args[3].Value != m.store.base.facts.Version || args[4].Value != m.store.base.facts.ConfigSHA256 || args[5].Value != m.store.base.facts.ConfigSizeBytes || m.store.base.cells["canonical_config_json"] != nil {
			return nil, errors.New("non-exact canonical-only CAS")
		}
		body, ok := args[0].Value.([]byte)
		if !ok || registrationHash(string(body)) != m.store.base.facts.ConfigSHA256 {
			return nil, errors.New("wrong original bytes")
		}
		m.ops = append(m.ops, "canonical-fill")
		m.fills++
		m.store.base.cells["canonical_config_json"] = append([]byte(nil), body...)
		return maintenanceServiceResult{0}, nil
	}
	if q == configMaintenanceReceiptInsert {
		m.ops = append(m.ops, "receipt")
	}
	return c.maintenanceReceiptConn.ExecContext(ctx, q, args)
}

// These adapters are deliberately synthetic. Their purpose separation,
// callback order, byte ownership and deadline behavior exercise orchestration;
// none authenticates a real actor, grant, issuer, source or capacity report.
type maintenanceServiceAuthority struct {
	m                                                              *maintenanceServiceModel
	until, capacityUntil                                           time.Time
	denyWrite, denyObservation, denyFinal                          bool
	nilAdmission, nilCapacity, typedNilAdmission, typedNilCapacity bool
	writeCalls, observationCalls, reserveCalls, finalCalls         int
	budget                                                         configMaintenanceBudget
	onAuthorize                                                    func(configMaintenanceScope, []byte)
	onFinal, onCapacity                                            func()
}
type maintenanceServiceAdmission struct{ a *maintenanceServiceAuthority }

func (a *maintenanceServiceAdmission) ValidUntil() time.Time { return a.a.until }
func (a *maintenanceServiceAdmission) Recheck(context.Context, *sql.Tx, time.Time) error {
	a.a.finalCalls++
	if a.a.onFinal != nil {
		a.a.onFinal()
	}
	if a.a.denyFinal {
		return ErrRegistrationPermission
	}
	return nil
}

type maintenanceServiceCapacity struct{ a *maintenanceServiceAuthority }

func (c *maintenanceServiceCapacity) ValidUntil() time.Time { return c.a.capacityUntil }
func (c *maintenanceServiceCapacity) Recheck(context.Context, *sql.Tx, time.Time) error {
	if c.a.onCapacity != nil {
		c.a.onCapacity()
	}
	return nil
}
func (a *maintenanceServiceAuthority) admit(scope configMaintenanceScope, source []byte) (configMaintenanceAdmission, error) {
	if !scope.valid() || scope.identity.ConfigSHA != registrationHash(string(source)) {
		return nil, ErrRegistrationPermission
	}
	if a.onAuthorize != nil {
		a.onAuthorize(scope, source)
	}
	if a.nilAdmission {
		return nil, nil
	}
	if a.typedNilAdmission {
		var empty *maintenanceServiceAdmission
		return empty, nil
	}
	return &maintenanceServiceAdmission{a}, nil
}
func (a *maintenanceServiceAuthority) AuthorizeWrite(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, source []byte, _ time.Time) (configMaintenanceAdmission, error) {
	a.writeCalls++
	if a.denyWrite {
		return nil, ErrRegistrationPermission
	}
	return a.admit(scope, source)
}
func (a *maintenanceServiceAuthority) AuthorizeObservation(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, source []byte, _ time.Time) (configMaintenanceAdmission, error) {
	a.observationCalls++
	if a.denyObservation {
		return nil, ErrRegistrationPermission
	}
	return a.admit(scope, source)
}
func (a *maintenanceServiceAuthority) Reserve(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, budget configMaintenanceBudget, _ time.Time) (ConfigMutationCapacityReservation, error) {
	a.reserveCalls++
	a.budget = budget
	if !scope.valid() {
		return nil, ErrRegistrationUnavailable
	}
	if a.nilCapacity {
		return nil, nil
	}
	if a.typedNilCapacity {
		var empty *maintenanceServiceCapacity
		return empty, nil
	}
	return &maintenanceServiceCapacity{a}, nil
}
func maintenanceServiceFixture(t *testing.T) (*configCanonicalBackfillService, *maintenanceServiceModel, *maintenanceServiceAuthority, configMaintenanceScope, []byte) {
	t.Helper()
	oldDB, oldTx, store, scope, original := maintenanceReceiptFixture(t)
	if err := oldTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := oldDB.Close(); err != nil {
		t.Fatal(err)
	}
	m := &maintenanceServiceModel{store: store}
	a := &maintenanceServiceAuthority{m: m, until: store.base.now.Add(time.Minute), capacityUntil: store.base.now.Add(time.Minute)}
	db := sql.OpenDB(maintenanceServiceConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := newConfigCanonicalBackfillService(db, scope.database, scope.identity.Installation, scope.identity.Actor, a)
	if err != nil {
		t.Fatal(err)
	}
	return s, m, a, scope, original
}
func maintenanceServiceEmpty(t *testing.T, r configMaintenanceResult, err error) {
	t.Helper()
	if err == nil || r.canonical != nil || r.replayed {
		t.Fatal("failure released maintenance result", err)
	}
}

func TestConfigBackfillServiceApplyNoChangeAndOriginalObservation(t *testing.T) {
	for _, fill := range []bool{true, false} {
		t.Run(map[bool]string{true: "null-fill", false: "same-byte-no-change"}[fill], func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			if !fill {
				m.store.base.cells["canonical_config_json"] = append([]byte(nil), original...)
			}
			before := maintenanceACopyCells(m.store.base.cells)
			r, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			if err != nil {
				t.Fatal(err)
			}
			wantFills := 0
			if fill {
				wantFills = 1
			}
			if m.commits != 1 || m.fills != wantFills || m.auditWrites != 2 || m.store.inserts != 1 || r.replayed || a.writeCalls != 1 || a.reserveCalls != 1 || a.observationCalls != 0 || a.finalCalls != 1 {
				t.Fatal("incomplete atomic flow")
			}
			before["canonical_config_json"] = append([]byte(nil), original...)
			if !reflect.DeepEqual(before, m.store.base.cells) {
				t.Fatal("changed a legacy column beyond canonical")
			}
			var body map[string]any
			if json.Unmarshal(r.bytes(), &body) != nil || body["wrote"] != fill || body["intent_audit_id"] != float64(11) || body["result_audit_id"] != float64(12) {
				t.Fatal("wrong real audit anchors or no-change label")
			}
			if len(r.bytes()) > a.budget.receiptMaxBytes || a.budget.canonicalWriteBytes != wantFills*len(original) || a.budget.intentBytes < 2 || a.budget.resultBytes < 2 {
				t.Fatal("payload reservation missing")
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("private result serializes")
			}
			copy := r.bytes()
			copy[0] = '!'
			if bytes.Equal(copy, r.bytes()) {
				t.Fatal("result aliases receipt")
			}
			// Write admission may be revoked while independent observation remains.
			a.denyWrite = true
			observed, err := s.observe(context.Background(), scope.key, scope.canonical, original)
			if err != nil || !observed.replayed || !bytes.Equal(observed.bytes(), r.bytes()) || m.fills != wantFills || m.auditWrites != 2 || m.store.inserts != 1 || a.reserveCalls != 1 || a.writeCalls != 1 || a.observationCalls != 1 {
				t.Fatal("observation retried write or changed original", err)
			}
		})
	}
}

func TestConfigBackfillServiceUnknownCommitRequiresIndependentObservation(t *testing.T) {
	for _, outcome := range []string{"committed-lost-ack", "rejected-lost-ack"} {
		t.Run(outcome, func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			m.commitMode = outcome
			r, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			maintenanceServiceEmpty(t, r, err)
			if !errors.Is(err, errConfigMaintenanceCommitUnknown) || m.commits != 1 || a.observationCalls != 0 || m.auditWrites != 2 || m.store.inserts != 1 {
				t.Fatal("unknown commit retried or exposed success", err)
			}
			m.commitMode = ""
			a.denyWrite = true
			observed, err := s.observe(context.Background(), scope.key, scope.canonical, original)
			if outcome == "committed-lost-ack" {
				if err != nil || !observed.replayed {
					t.Fatal("committed outcome not observed", err)
				}
			} else {
				maintenanceServiceEmpty(t, observed, err)
				if !errors.Is(err, errConfigMaintenanceReceiptMissing) || m.store.base.cells["canonical_config_json"] != nil || m.store.receipt != nil || len(m.store.audits) != 0 {
					t.Fatal("absent outcome was filled or misclassified", err)
				}
			}
			if m.fills != 1 || m.auditWrites != 2 || m.store.inserts != 1 || a.reserveCalls != 1 || a.writeCalls != 1 {
				t.Fatal("observation performed another mutation")
			}
		})
	}
}

func TestConfigBackfillServiceCancellationAtCommitReleasesNoResult(t *testing.T) {
	s, m, _, scope, original := maintenanceServiceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.onCommit = cancel
	r, err := s.apply(ctx, scope.key, scope.canonical, original)
	maintenanceServiceEmpty(t, r, err)
	if !errors.Is(err, errConfigMaintenanceCommitUnknown) || m.commits != 1 || m.store.receipt == nil || m.auditWrites != 2 || m.fills != 1 {
		t.Fatal("commit cancellation exposed result or repeated mutation", err)
	}
	m.onCommit = nil
	observed, err := s.observe(context.Background(), scope.key, scope.canonical, original)
	if err != nil || !observed.replayed || m.store.inserts != 1 || m.auditWrites != 2 || m.fills != 1 {
		t.Fatal("confirmed outcome could not be independently observed", err)
	}
}

func TestConfigBackfillServiceFailureRollsBackWholeAttempt(t *testing.T) {
	for _, name := range []string{"write-denied", "nil-admission", "typed-nil-admission", "nil-capacity", "typed-nil-capacity", "initial-expiry", "intent-failure", "result-failure", "receipt-failure", "final-revocation", "source-pin-drift", "final-row-drift", "final-audit-time-drift", "final-canonical-drift", "grant-expiry-after-callback", "capacity-expiry-after-callback", "grant-extension-does-not-renew", "capacity-extension-does-not-renew", "wrong-target-after-callback", "clock-backwards"} {
		t.Run(name, func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			initialNow := m.store.base.now
			switch name {
			case "write-denied":
				a.denyWrite = true
			case "nil-admission":
				a.nilAdmission = true
			case "typed-nil-admission":
				a.typedNilAdmission = true
			case "nil-capacity":
				a.nilCapacity = true
			case "typed-nil-capacity":
				a.typedNilCapacity = true
			case "initial-expiry":
				a.until = initialNow
			case "intent-failure":
				m.failAudit = "intent"
			case "result-failure":
				m.failAudit = "result"
			case "receipt-failure":
				m.store.mode = "insert-error"
			case "final-revocation", "source-pin-drift":
				a.denyFinal = true
			case "final-row-drift":
				a.onFinal = func() { m.store.base.cells["created_by"] = "replaced" }
			case "final-audit-time-drift":
				a.onFinal = func() { m.store.audits[11][5] = initialNow.Add(-2 * time.Microsecond) }
			case "final-canonical-drift":
				a.onFinal = func() { m.store.base.cells["canonical_config_json"] = []byte("{}") }
			case "grant-expiry-after-callback":
				a.onFinal = func() { m.store.base.now = a.until }
			case "capacity-expiry-after-callback":
				a.capacityUntil = initialNow.Add(time.Second)
				a.onCapacity = func() { m.store.base.now = a.capacityUntil }
			case "grant-extension-does-not-renew":
				a.onFinal = func() { m.store.base.now = a.until; a.until = a.until.Add(time.Hour) }
			case "capacity-extension-does-not-renew":
				a.capacityUntil = initialNow.Add(time.Second)
				a.onCapacity = func() { m.store.base.now = a.capacityUntil; a.capacityUntil = a.capacityUntil.Add(time.Hour) }
			case "wrong-target-after-callback":
				a.onFinal = func() { m.store.base.wrongDatabase = true }
			case "clock-backwards":
				a.onFinal = func() { m.store.base.now = initialNow.Add(-time.Microsecond) }
			}
			r, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			maintenanceServiceEmpty(t, r, err)
			if m.commits != 0 || m.store.receipt != nil || len(m.store.audits) != 0 || m.store.base.cells["canonical_config_json"] != nil {
				t.Fatal("failed attempt left committed-model state")
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("private database diagnostic leaked")
			}
		})
	}
}

func TestConfigBackfillServicePermanentKeyAndSeparateObservation(t *testing.T) {
	for _, name := range []string{"replay", "observation-denied", "changed-grant", "changed-reason"} {
		t.Run(name, func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			first, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			if err != nil {
				t.Fatal(err)
			}
			raw := append([]byte(nil), scope.canonical...)
			if name == "observation-denied" {
				a.denyObservation = true
			}
			if name == "changed-grant" || name == "changed-reason" {
				var body map[string]any
				json.Unmarshal(raw, &body)
				if name == "changed-grant" {
					body["grant_version"] = "rotated-v2"
				} else {
					body["reason"] = "another reason"
				}
				raw, _ = json.Marshal(body)
			}
			r, err := s.apply(context.Background(), scope.key, raw, original)
			if name == "replay" {
				if err != nil || !r.replayed || !bytes.Equal(r.bytes(), first.bytes()) {
					t.Fatal("original replay", err)
				}
			} else {
				maintenanceServiceEmpty(t, r, err)
				if name != "observation-denied" && !errors.Is(err, ErrRegistrationConflict) {
					t.Fatal("new grant/reason reopened permanent key", err)
				}
			}
			if m.auditWrites != 2 || m.fills != 1 || m.store.inserts != 1 || a.reserveCalls != 1 {
				t.Fatal("replay/conflict caused another write")
			}
		})
	}
}

func TestConfigBackfillServiceFreezesInputsBeforeAuthorityCallbacks(t *testing.T) {
	s, m, a, scope, original := maintenanceServiceFixture(t)
	request := append([]byte(nil), scope.canonical...)
	source := append([]byte(nil), original...)
	a.onAuthorize = func(callbackScope configMaintenanceScope, callbackSource []byte) {
		callbackScope.canonical[0] = '!'
		callbackSource[0] = '!'
		request[0] = '!'
		source[0] = '!'
	}
	r, err := s.apply(context.Background(), scope.key, request, source)
	if err != nil || len(r.bytes()) < 2 || !bytes.Equal(m.store.base.cells["canonical_config_json"].([]byte), original) {
		t.Fatal("authority/caller buffer rewrote admitted original request", err)
	}
}

func TestConfigBackfillServiceObservationCannotCreateMissingResult(t *testing.T) {
	s, m, a, scope, original := maintenanceServiceFixture(t)
	a.denyWrite = true
	r, err := s.observe(context.Background(), scope.key, scope.canonical, original)
	maintenanceServiceEmpty(t, r, err)
	if !errors.Is(err, errConfigMaintenanceReceiptMissing) || a.observationCalls != 1 || a.writeCalls != 0 || a.reserveCalls != 0 || a.finalCalls != 1 || m.commits != 0 || m.fills != 0 || m.auditWrites != 0 || m.store.inserts != 0 {
		t.Fatal("observation created or retried a result", err)
	}
}

func TestConfigBackfillServiceFinalClockUsesLatestSQLObservation(t *testing.T) {
	for _, regress := range []bool{false, true} {
		t.Run(map[bool]string{false: "monotonic", true: "regression-after-final-receipt-scan"}[regress], func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			start := m.store.base.now
			clocks := 0
			a.onFinal = func() {
				m.store.base.callback = func(stage string) {
					if stage != "clock" {
						return
					}
					clocks++
					if clocks == 3 && regress {
						m.store.base.now = start.Add(1500 * time.Millisecond)
					} else {
						m.store.base.now = start.Add(time.Duration(clocks) * time.Second)
					}
				}
			}
			r, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			if regress {
				maintenanceServiceEmpty(t, r, err)
				if !errors.Is(err, ErrRegistrationUnavailable) || m.commits != 0 || m.store.receipt != nil {
					t.Fatal("commit clock forgot newer SQL receipt observation", err)
				}
			} else if err != nil || m.commits != 1 {
				t.Fatal("monotonic SQL observations rejected", err)
			}
			if clocks != 3 {
				t.Fatal("did not observe both receipt scan clocks and the final clock", clocks)
			}
		})
	}
}

func TestConfigBackfillServiceMissingReceiptClockCannotRegress(t *testing.T) {
	for _, regress := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-monotonic", true: "missing-scan-clock-regression"}[regress], func(t *testing.T) {
			s, m, _, scope, original := maintenanceServiceFixture(t)
			start := m.store.base.now
			clocks := 0
			m.store.base.callback = func(stage string) {
				if stage != "clock" {
					return
				}
				clocks++
				if clocks == 3 {
					m.store.base.now = start.Add(2 * time.Second)
				}
				if clocks == 4 {
					if regress {
						m.store.base.now = start.Add(1500 * time.Millisecond)
					} else {
						m.store.base.now = start.Add(3 * time.Second)
					}
				}
			}
			r, err := s.observe(context.Background(), scope.key, scope.canonical, original)
			maintenanceServiceEmpty(t, r, err)
			if regress {
				if !errors.Is(err, ErrRegistrationUnavailable) {
					t.Fatal("negative observation forgot its newer SQL clock", err)
				}
			} else if !errors.Is(err, errConfigMaintenanceReceiptMissing) {
				t.Fatal("legitimate absence misclassified", err)
			}
			if m.fills != 0 || m.auditWrites != 0 || m.store.inserts != 0 || m.commits != 0 {
				t.Fatal("negative observation mutated state")
			}
		})
	}
}

func TestConfigBackfillServiceRejectsUnboundConstructionAndOriginal(t *testing.T) {
	for _, name := range []string{"nil-db", "wrong-target", "wrong-installation", "wrong-actor", "nil-authority", "typed-nil-authority"} {
		t.Run(name, func(t *testing.T) {
			s, _, a, scope, _ := maintenanceServiceFixture(t)
			db, database, installation, actor := s.db, scope.database, scope.identity.Installation, scope.identity.Actor
			var authority configMaintenanceAuthority = a
			switch name {
			case "nil-db":
				db = nil
			case "wrong-target":
				database.Database = "../foreign"
			case "wrong-installation":
				installation = "admin"
			case "wrong-actor":
				actor = "admin:1"
			case "nil-authority":
				authority = nil
			case "typed-nil-authority":
				var empty *maintenanceServiceAuthority
				authority = empty
			}
			if admitted, err := newConfigCanonicalBackfillService(db, database, installation, actor, authority); err == nil || admitted != nil {
				t.Fatal("unbound service constructed")
			}
		})
	}
	for _, name := range []string{"missing-original", "wrong-original", "oversized-original", "oversized-request", "wrong-request-target", "invalid-key", "nil-context", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			raw := append([]byte(nil), scope.canonical...)
			key := scope.key
			ctx := context.Background()
			switch name {
			case "missing-original":
				original = nil
			case "wrong-original":
				original = []byte("{}")
			case "oversized-original":
				original = bytes.Repeat([]byte("x"), 262145)
			case "oversized-request":
				raw = bytes.Repeat([]byte("x"), 262145)
			case "wrong-request-target":
				raw = bytes.ReplaceAll(raw, []byte(scope.database.ServerUUID), []byte("22345678-1234-1234-1234-123456789abc"))
			case "invalid-key":
				key = "short"
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			queries := m.store.base.queries
			r, err := s.apply(ctx, key, raw, original)
			maintenanceServiceEmpty(t, r, err)
			if a.writeCalls != 0 || a.observationCalls != 0 || a.reserveCalls != 0 || m.store.base.queries != queries || m.store.inserts != 0 || m.commits != 0 {
				t.Fatal("invalid original/request reached admission or SQL")
			}
		})
	}
}
