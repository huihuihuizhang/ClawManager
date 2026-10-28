package systembackupsecurity

// Synthetic SQL-driver tests of A's concrete stages. They do not authenticate
// a deployment, exercise InnoDB locks, or constitute actual bootstrap evidence.
import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type candidateBridgeState struct {
	base         *bootstrapTestState
	cells        map[string]driver.Value
	state        bool
	queries      []string
	badAuditID   bool
	lateColumn   string
	phases       []string
	otherConfigs [][]driver.Value
}
type candidateBridgeConnector struct{ state *candidateBridgeState }

func (c candidateBridgeConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c candidateBridgeConnector) Connect(context.Context) (driver.Conn, error) {
	return &candidateBridgeConn{bootstrapConn: bootstrapConn{c.state.base}, state: c.state}, nil
}

type candidateBridgeConn struct {
	bootstrapConn
	state *candidateBridgeState
}

func (c *candidateBridgeConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.state
	s.queries = append(s.queries, q)
	switch {
	case strings.HasPrefix(q, "SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version)"):
		data := append([][]driver.Value(nil), s.otherConfigs...)
		if len(s.cells) != 0 {
			data = append(data, []driver.Value{int64(1), s.base.grant.InstallationID, s.cells["version"], s.cells["config_sha256"], s.cells["enabled"], s.cells["nonce_hmac_ref_version"], s.cells["nonce_hmac_identity_hash"]})
		}
		return &registrationTestRows{data: data, width: 7}, nil
	case strings.HasPrefix(q, "SELECT active_config_version,matrix_key"):
		if !s.state {
			return &registrationTestRows{width: 2}, nil
		}
		return registrationRow(int64(1), s.base.grant.MatrixKey), nil
	case strings.HasPrefix(q, "SELECT version,config_sha256,enabled"):
		if len(s.cells) == 0 {
			return &registrationTestRows{width: 3}, nil
		}
		return registrationRow(s.cells["version"], s.cells["config_sha256"], s.cells["enabled"]), nil
	case strings.HasPrefix(q, "SELECT public_id FROM system_backup_v2_operations"):
		return &registrationTestRows{width: 1}, nil
	case strings.HasPrefix(q, "SELECT origin_installation_id,version,config_sha256,"):
		columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ",")
		values := make([]driver.Value, len(columns))
		for i, k := range columns {
			values[i] = s.cells[k]
		}
		return registrationRow(values...), nil
	}
	return c.bootstrapConn.QueryContext(ctx, q, args)
}
func (c *candidateBridgeConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.bootstrapConn.ExecContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(q, "INSERT INTO system_backup_v2_configs (") {
		columns := strings.Split(strings.Split(strings.TrimPrefix(q, "INSERT INTO system_backup_v2_configs ("), ")")[0], ",")
		c.state.cells = map[string]driver.Value{}
		for i, k := range columns {
			c.state.cells[k] = args[i].Value
		}
	}
	if strings.HasPrefix(q, "INSERT INTO system_backup_v2_installation_state") {
		c.state.state = true
	}
	if strings.HasPrefix(q, "INSERT INTO audit_logs") && c.state.badAuditID {
		return registrationTestResult(0), nil
	}
	return result, nil
}

// The authoritative callback is deliberately a named synthetic fixture. It
// records invocation and can corrupt a cell after checks to exercise A's fixed
// independent verification; a production deployment must supply real authority.
type candidateBridgeAuthority struct{ state *candidateBridgeState }

func (a *candidateBridgeAuthority) PrepareBootstrapCandidates(_ context.Context, _ OfflineBootstrapGrant, _ BootstrapConfig, _ pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	a.state.phases = append(a.state.phases, "prepare")
	return PreparedBootstrapCandidateAuthority{Session: a}, nil
}
func (a *candidateBridgeAuthority) Authorize(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	a.state.phases = append(a.state.phases, "authorize")
	h, e := pd.BootstrapConsumptionHash(r)
	return pd.BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: pd.Timestamp(now.Add(time.Minute).Format("2006-01-02T15:04:05.000000Z")), DependencyExpiresAt: pd.Timestamp(now.Add(time.Minute).Format("2006-01-02T15:04:05.000000Z"))}, e
}
func (a *candidateBridgeAuthority) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.state.phases = append(a.state.phases, "hosts")
	return nil
}
func (a *candidateBridgeAuthority) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.state.phases = append(a.state.phases, "references")
	return nil
}
func (a *candidateBridgeAuthority) Reserve(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	a.state.phases = append(a.state.phases, "reserve")
	return nil
}
func (a *candidateBridgeAuthority) LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	a.state.phases = append(a.state.phases, "evidence")
	return nil, nil
}
func (a *candidateBridgeAuthority) Recheck(context.Context, pd.BootstrapReadSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts, time.Time) error {
	a.state.phases = append(a.state.phases, "recheck")
	if a.state.lateColumn != "" {
		a.state.cells[a.state.lateColumn] = "synthetic-late-corruption"
	}
	return nil
}

type candidateBridgeSQL struct {
	*sql.Tx
	now time.Time
}

func (c candidateBridgeSQL) SampleTime(context.Context) (time.Time, error) { return c.now, nil }
func (c candidateBridgeSQL) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, errors.New("unexpected producer-record use in A stage test")
}

func candidateBridgeFixture(t *testing.T) (*ConfigBootstrapCandidates, *candidateBridgeState) {
	t.Helper()
	_, g, raw, base := bootstrapServiceFixture(t)
	s := &candidateBridgeState{base: base}
	db := sql.OpenDB(candidateBridgeConnector{s})
	t.Cleanup(func() { db.Close() })
	bytes, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		} `json:"positive"`
	}
	if json.Unmarshal(bytes, &vectors) != nil {
		t.Fatal("vectors")
	}
	var r pd.ResultRequest
	for _, v := range vectors.Positive {
		if v.ID == "unconfigured_signing" {
			r, err = pd.DecodeResult(v.Value)
		}
	}
	if err != nil || r.RunID == "" {
		t.Fatal("candidate fixture", err)
	}
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(c.CanonicalJSON(), &fields)
	r.Scope = pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}
	r.Evidence.OwnerID = pd.Installation(g.InstallationID)
	r.Admission.Unconfigured.CandidateHash = pd.Hash(c.SHA256())
	r.Admission.Unconfigured.RegistrySetHash = pd.Hash(registrationHash(string(fields["registries"])))
	r.Admission.Unconfigured.RefSetHash = pd.Hash(registrationHash(string(fields["references"])))
	selection := pd.BootstrapCandidateSelection{Purpose: "capture_signing", ReferenceIdentityHash: pd.Hash(strings.Repeat("c", 64)), ReferenceVersion: "synthetic-v1", MappingHash: pd.Hash(strings.Repeat("e", 64)), Request: r, ResultVersion: "1"}
	p, err := NewConfigBootstrapCandidates(db, g, raw, []pd.BootstrapCandidateSelection{selection}, &candidateBridgeAuthority{s})
	if err != nil {
		t.Fatal(err)
	}
	return p, s
}

func candidateBridgeSession(t *testing.T, p *ConfigBootstrapCandidates, canonical bool) (*configBootstrapCandidateSession, candidateBridgeSQL) {
	t.Helper()
	if canonical {
		p.authority.(*candidateBridgeAuthority).state.base.canonical = p.config.CanonicalJSON()
	}
	env := &configBootstrapCandidateEnvironment{plan: p, canonical: canonical}
	a, e := env.PrepareBootstrapConsumption(context.Background(), p.request)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := p.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { tx.Rollback() })
	return a.Session.(*configBootstrapCandidateSession), candidateBridgeSQL{tx, time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)}
}

func TestBootstrapCandidatePlanIsDetachedAndRequiresAuthority(t *testing.T) {
	p, s := candidateBridgeFixture(t)
	r := p.request
	selections := r.Candidates
	raw := p.config.CanonicalJSON()
	if _, e := NewConfigBootstrapCandidates(p.db, p.grant, raw, selections, nil); e == nil {
		t.Fatal("missing authority accepted")
	}
	var absent *candidateBridgeAuthority
	if _, e := NewConfigBootstrapCandidates(p.db, p.grant, raw, selections, absent); e == nil {
		t.Fatal("typed nil authority accepted")
	}
	second, e := NewConfigBootstrapCandidates(p.db, p.grant, raw, selections, &candidateBridgeAuthority{s})
	if e != nil {
		t.Fatal(e)
	}
	original, _ := pd.BootstrapConsumptionHash(second.request)
	selections[0].Request.Target.ResultSlots[0] = "kek"
	after, _ := pd.BootstrapConsumptionHash(second.request)
	if original != after {
		t.Fatal("caller mutated stored relation")
	}
	if len(s.phases) != 0 {
		t.Fatal("constructor conferred authority", s.phases)
	}
	wrong := p.grant
	wrong.ChangeReason = "changed"
	if _, e = p.bootstrap(context.Background(), p.db, wrong, p.config, false); e != ErrRegistrationUnavailable || len(s.phases) != 0 {
		t.Fatal("wrong original grant reached prepare", e, s.phases)
	}
	if _, e = json.Marshal(p); e == nil {
		t.Fatal("plan serialized")
	}
}

func TestBootstrapCandidateAStagesKeepEarlyPrefixAndOneIntent(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		t.Run(strconv.FormatBool(canonical), func(t *testing.T) {
			p, state := candidateBridgeFixture(t)
			s, tx := candidateBridgeSession(t, p, canonical)
			ctx := context.Background()
			if e := s.LockInstallation(ctx, tx, p.request); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Authorize(ctx, tx, p.request, pd.DomainRecord{}, tx.now); e != nil {
				t.Fatal(e)
			}
			if op, e := s.LockOperation(ctx, tx, p.request, s.hash, s.operationID); e != nil || op.Found {
				t.Fatal(op, e)
			}
			if e := s.AuditIntent(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}); e != nil {
				t.Fatal(e)
			}
			written, e := s.WriteBootstrap(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}, s.operationID, s.hash, tx.now)
			if e != nil {
				t.Fatal(e)
			}
			if written.IntentAuditID != 1 || written.ResultAuditID != 5 || strings.Join(state.base.pending, ",") != "audit,config,state,operation,audit" {
				t.Fatal("duplicate or reordered audit", written, state.base.pending)
			}
			if e = s.Recheck(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}, tx.now); e != nil {
				t.Fatal(e)
			}
			if len(state.queries) < 6 || !strings.Contains(state.queries[0], "ORDER BY origin_installation_id") || !strings.Contains(state.queries[2], "FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE") || strings.Contains(state.queries[2], " WHERE ") || !strings.HasPrefix(state.queries[3], "SELECT username") || !strings.Contains(state.queries[4], "idempotency_key") {
				t.Fatal("late earlier-layer acquisition", state.queries)
			}
			if len(state.base.committed) != 0 {
				t.Fatal("A stage committed caller transaction")
			}
		})
	}
}

func TestBootstrapCandidateGlobalConfigPrefixStreamsForeignFactsBeforeReplayDecision(t *testing.T) {
	p, state := candidateBridgeFixture(t)
	// More raw rows than the legacy UNION-distinct cap, but one shared nonce
	// binding. Its resource validity is deliberately not L1 authorization.
	for i := 1; i <= 20001; i++ {
		state.otherConfigs = append(state.otherConfigs, []driver.Value{int64(i + 1), "installation_foreign", int64(i), "foreign-config", false, "unknown-material", "foreign-identity"})
	}
	s, tx := candidateBridgeSession(t, p, false)
	if err := s.LockInstallation(context.Background(), tx, p.request); err != nil {
		t.Fatal("foreign/raw row facts preempted L3", err)
	}
	if s.configCount != 0 {
		t.Fatal("foreign configs became target initialization state", s.configCount)
	}
	if _, err := s.LockOperation(context.Background(), tx, p.request, s.hash, s.operationID); err != nil {
		t.Fatal("foreign configs prevented target operation lookup", err)
	}
	if len(state.base.pending) != 0 || len(state.base.committed) != 0 {
		t.Fatal("global lock acquisition performed bootstrap writes")
	}
}

type candidateAttemptContextAuthority struct {
	*candidateBridgeAuthority
	preparedContext context.Context
	deadline        time.Time
}

func (a *candidateAttemptContextAuthority) PrepareBootstrapCandidates(ctx context.Context, _ OfflineBootstrapGrant, _ BootstrapConfig, _ pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	a.preparedContext = ctx
	a.deadline, _ = ctx.Deadline()
	return PreparedBootstrapCandidateAuthority{}, pd.ErrGuardRequired
}

func TestBootstrapCandidateAttemptBudgetStartsBeforePreparation(t *testing.T) {
	for _, shorterParent := range []bool{false, true} {
		t.Run(strconv.FormatBool(shorterParent), func(t *testing.T) {
			p, state := candidateBridgeFixture(t)
			a := &candidateAttemptContextAuthority{candidateBridgeAuthority: &candidateBridgeAuthority{state: state}}
			p.authority = a
			parent := context.Background()
			var parentDeadline time.Time
			if shorterParent {
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(parent, time.Minute)
				defer cancel()
				parentDeadline, _ = parent.Deadline()
			}
			started := time.Now()
			if _, err := p.bootstrap(parent, p.db, p.grant, p.config, false); err != ErrRegistrationUnavailable {
				t.Fatal("preparation failure did not fail closed", err)
			}
			if a.preparedContext == nil || a.preparedContext == parent || a.deadline.IsZero() {
				t.Fatal("preparation did not bind a bounded attempt context")
			}
			if shorterParent {
				if !a.deadline.Equal(parentDeadline) {
					t.Fatal("parent deadline extended")
				}
			} else {
				budget := time.Duration(p.config.numbers["operation_deadline_seconds"]) * time.Second
				if a.deadline.Before(started.Add(budget)) || a.deadline.After(time.Now().Add(budget)) {
					t.Fatal("wrong configuration operation budget")
				}
			}
			if a.preparedContext.Err() != context.Canceled || parent.Err() != nil || len(state.queries) != 0 {
				t.Fatal("attempt cleanup canceled caller or reached SQL", a.preparedContext.Err(), parent.Err(), state.queries)
			}
		})
	}
}

func TestBootstrapCandidateAFinalReadRejectsCallbackChangesWithHashPreserved(t *testing.T) {
	for _, column := range []string{"capture_signing_ref_version", "change_reason", "control_metadata_capacity_bytes", "enabled"} {
		t.Run(column, func(t *testing.T) {
			p, state := candidateBridgeFixture(t)
			s, tx := candidateBridgeSession(t, p, false)
			ctx := context.Background()
			if e := s.AuditIntent(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}); e != nil {
				t.Fatal(e)
			}
			if _, e := s.WriteBootstrap(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}, s.operationID, s.hash, tx.now); e != nil {
				t.Fatal(e)
			}
			state.lateColumn = column
			if e := s.Recheck(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}, tx.now); e != pd.ErrConflict {
				t.Fatal("changed flattened row retained hash accepted", e)
			}
			if state.cells["config_sha256"] != p.config.SHA256() {
				t.Fatal("counterexample changed hash instead of independent value")
			}
		})
	}
}

func TestBootstrapCandidateAReplayReachesExactOperationAfterExistingConfig(t *testing.T) {
	p, state := candidateBridgeFixture(t)
	// Foreign global facts must be locked/streamed, but unknown material and a
	// legal wide unsigned version must not preempt this target's L3 history read.
	state.otherConfigs = [][]driver.Value{{int64(2), "installation_foreign", "18446744073709551615", "foreign-config", false, "unknown-material", "foreign-identity"}}
	first, tx := candidateBridgeSession(t, p, false)
	ctx := context.Background()
	if e := first.AuditIntent(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}); e != nil {
		t.Fatal(e)
	}
	if _, e := first.WriteBootstrap(ctx, tx, p.request, pd.BootstrapConsumptionFacts{}, first.operationID, first.hash, tx.now); e != nil {
		t.Fatal(e)
	}
	if e := tx.Commit(); e != nil {
		t.Fatal(e)
	}
	retry, read := candidateBridgeSession(t, p, false)
	if e := retry.LockInstallation(ctx, read, p.request); e != nil {
		t.Fatal("existing state rejected before replay branch", e)
	}
	op, e := retry.LockOperation(ctx, read, p.request, retry.hash, retry.operationID)
	if e != nil || !op.Found || op.PublicID != first.operationID || op.RequestHash != first.hash {
		t.Fatal(op, e)
	}
	if len(state.base.committed) != 5 {
		t.Fatal("replay wrote bootstrap rows again", state.base.committed)
	}
}

func TestBootstrapCandidateARejectsMissingAuditIdentity(t *testing.T) {
	p, state := candidateBridgeFixture(t)
	s, tx := candidateBridgeSession(t, p, false)
	state.badAuditID = true
	if e := s.AuditIntent(context.Background(), tx, p.request, pd.BootstrapConsumptionFacts{}); e != pd.ErrUnavailable {
		t.Fatal("zero audit identity accepted", e)
	}
	if len(state.base.committed) != 0 {
		t.Fatal("audit failure committed")
	}
}

type candidateTypedNilContext struct{ context.Context }

func TestBootstrapCandidateTypedNilContextRejectedBeforeAuthorityOrSQL(t *testing.T) {
	p, state := candidateBridgeFixture(t)
	var missing *candidateTypedNilContext
	if _, err := p.bootstrap(missing, p.db, p.grant, p.config, false); err != ErrRegistrationUnavailable {
		t.Fatal("typed nil context reached consumer", err)
	}
	if len(state.phases) != 0 || len(state.queries) != 0 {
		t.Fatal("invalid context reached authority or SQL", state.phases, state.queries)
	}
}
