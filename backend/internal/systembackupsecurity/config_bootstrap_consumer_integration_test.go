package systembackupsecurity

// These tests call the real A service and D consumer together through an
// in-memory SQL driver. The named synthetic authority proves no deployment,
// provider permission, or InnoDB locking property.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const consumerIntegrationTime = "2006-01-02T15:04:05.000000Z"

type consumerIntegrationState struct {
	retainedWrite                          pd.BootstrapSQL
	retainedRead                           pd.BootstrapReadSQL
	grantFile, nonRBACFile                 string
	registryFiles                          map[string]string
	mutateFileKind, mutateFileMode         string
	mutateFileAtAuthorize, fileMutated     bool
	zeroDomainCAS                          bool
	bridge                                 *candidateBridgeState
	rows                                   map[string][]map[string]driver.Value
	now                                    time.Time
	request                                pd.BootstrapConsumptionRequest
	evidence                               pd.ResultEvidence
	commits, rollbacks, reserves, rechecks int
	deny, late                             bool
	queries                                []string
	reportFile                             string
	lateCapacity, expireCapacity           bool
	grantReads, registryReads              int
	grantRevoked                           bool
}

type consumerIntegrationConnector struct{ state *consumerIntegrationState }

// MySQL compares BIGINT columns numerically with C1 decimal-string bound
// parameters. Hashes, immutable bytes, identities and timestamps stay exact.
func consumerIntegrationSQLValueEqual(column string, actual, parameter driver.Value) bool {
	switch column {
	case "epoch", "row_version", "generation", "domain_epoch", "grant_generation", "target_generation", "result_version", "charged_bytes":
		counter := func(v driver.Value) (uint64, bool) {
			switch value := v.(type) {
			case int64:
				return uint64(value), value >= 0
			case uint64:
				return value, true
			case string:
				n, err := pd.ZeroCounter(value).Uint64()
				return n, err == nil
			case []byte:
				n, err := pd.ZeroCounter(string(value)).Uint64()
				return n, err == nil
			default:
				return 0, false
			}
		}
		left, leftOK := counter(actual)
		right, rightOK := counter(parameter)
		return leftOK && rightOK && left == right
	default:
		return reflect.DeepEqual(actual, parameter)
	}
}

func (c consumerIntegrationConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c consumerIntegrationConnector) Connect(context.Context) (driver.Conn, error) {
	return &consumerIntegrationConn{candidateBridgeConn: candidateBridgeConn{bootstrapConn: bootstrapConn{c.state.bridge.base}, state: c.state.bridge}, integration: c.state}, nil
}

type consumerIntegrationConn struct {
	candidateBridgeConn
	integration *consumerIntegrationState
}
type consumerIntegrationRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *consumerIntegrationRows) Columns() []string { return r.columns }
func (*consumerIntegrationRows) Close() error        { return nil }
func (r *consumerIntegrationRows) Next(out []driver.Value) error {
	if r.index == len(r.rows) {
		return io.EOF
	}
	copy(out, r.rows[r.index])
	r.index++
	return nil
}
func consumerIntegrationClone(rows map[string][]map[string]driver.Value) map[string][]map[string]driver.Value {
	out := map[string][]map[string]driver.Value{}
	for table, list := range rows {
		for _, row := range list {
			copy := map[string]driver.Value{}
			for key, value := range row {
				if b, ok := value.([]byte); ok {
					value = append([]byte(nil), b...)
				}
				copy[key] = value
			}
			out[table] = append(out[table], copy)
		}
	}
	return out
}

type consumerIntegrationTx struct {
	base       driver.Tx
	state      *consumerIntegrationState
	before     map[string][]map[string]driver.Value
	cells      map[string]driver.Value
	configured bool
	reserves   int
}

func (c *consumerIntegrationConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	base, err := c.candidateBridgeConn.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	s := c.integration
	cells := map[string]driver.Value{}
	for key, value := range s.bridge.cells {
		cells[key] = value
	}
	return &consumerIntegrationTx{base: base, state: s, before: consumerIntegrationClone(s.rows), cells: cells, configured: s.bridge.state, reserves: s.reserves}, nil
}
func (c *consumerIntegrationConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (t *consumerIntegrationTx) Commit() error { t.state.commits++; return t.base.Commit() }
func (t *consumerIntegrationTx) Rollback() error {
	t.state.rollbacks++
	t.state.rows = t.before
	t.state.bridge.cells = t.cells
	t.state.bridge.state = t.configured
	t.state.reserves = t.reserves
	return t.base.Rollback()
}

func consumerIntegrationSelect(q string, args []driver.NamedValue, rows map[string][]map[string]driver.Value) (driver.Rows, error) {
	parts := strings.SplitN(q, " FROM ", 2)
	if len(parts) != 2 {
		return nil, errors.New("integration select syntax")
	}
	projection := strings.TrimPrefix(parts[0], "SELECT ")
	rest := strings.SplitN(parts[1], " WHERE ", 2)
	table := rest[0]
	selected := rows[table]
	if len(rest) == 2 {
		where := strings.Split(strings.TrimSuffix(rest[1], " FOR UPDATE"), " ORDER BY ")[0]
		conditions := strings.Split(where, " AND ")
		filtered := []map[string]driver.Value{}
		for _, row := range selected {
			match := true
			argument := 0
			for _, condition := range conditions {
				pair := strings.SplitN(condition, "=", 2)
				if len(pair) != 2 {
					return nil, errors.New("integration where syntax")
				}
				key, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
				var want driver.Value
				if value == "?" {
					if argument >= len(args) {
						return nil, errors.New("integration missing argument")
					}
					want = args[argument].Value
					argument++
				} else {
					want = strings.Trim(value, "'")
					if value == "1" {
						want = int64(1)
					}
				}
				if !reflect.DeepEqual(row[key], want) {
					match = false
				}
			}
			if match {
				filtered = append(filtered, row)
			}
		}
		selected = filtered
	}
	var columns []string
	if projection == "*" {
		for key := range rows[table][0] {
			columns = append(columns, key)
		}
		sort.Strings(columns)
	} else {
		for _, column := range strings.Split(projection, ",") {
			columns = append(columns, strings.TrimSpace(column))
		}
	}
	out := &consumerIntegrationRows{columns: columns}
	for _, row := range selected {
		values := make([]driver.Value, len(columns))
		for i, key := range columns {
			values[i] = row[key]
		}
		out.rows = append(out.rows, values)
	}
	return out, nil
}

func (c *consumerIntegrationConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.integration
	s.queries = append(s.queries, q)
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return registrationRow(s.now), nil
	}
	if strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)") {
		return registrationRow(s.bridge.base.grant.ServerUUID, s.bridge.base.grant.Database, s.now, int64(0)), nil
	}
	if strings.HasPrefix(q, "SELECT c.config_sha256,s.active_config_version") {
		return registrationRow(s.bridge.base.grant.ConfigSHA256, int64(1), false, s.bridge.base.grant.MatrixKey), nil
	}
	if q == "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE" {
		if s.bridge.state {
			return registrationRow(s.bridge.base.grant.InstallationID), nil
		}
		return &registrationTestRows{width: 1}, nil
	}
	if strings.Contains(q, " FROM system_backup_producer_") || strings.HasPrefix(q, "SELECT * FROM system_backup_v2_evidence") || strings.Contains(q, " FROM system_backup_v2_operations WHERE") || strings.Contains(q, " FROM audit_logs WHERE id=") {
		return consumerIntegrationSelect(q, args, s.rows)
	}
	if strings.Contains(q, " FROM system_backup_v2_metadata_reservations WHERE id=1") {
		return consumerIntegrationSelect(q, args, s.rows)
	}
	if strings.HasPrefix(q, "SELECT * FROM system_backup_v2_configs") {
		return consumerIntegrationSelect(q, args, map[string][]map[string]driver.Value{"system_backup_v2_configs": {s.bridge.cells}})
	}
	if strings.HasPrefix(q, "SELECT * FROM system_backup_v2_installation_state") {
		g := s.bridge.base.grant
		return consumerIntegrationSelect(q, args, map[string][]map[string]driver.Value{"system_backup_v2_installation_state": {{"origin_installation_id": g.InstallationID, "active_config_version": int64(1), "matrix_key": g.MatrixKey}}})
	}
	if strings.HasPrefix(q, "SELECT public_id,result_config_version") {
		return consumerIntegrationSelect(q, args, s.rows)
	}
	return c.candidateBridgeConn.QueryContext(ctx, q, args)
}

func (c *consumerIntegrationConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.integration
	s.queries = append(s.queries, q)
	if q == "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)" {
		if len(s.rows["system_backup_v2_metadata_reservations"]) == 0 {
			s.rows["system_backup_v2_metadata_reservations"] = []map[string]driver.Value{{"id": int64(1), "sample_at": args[0].Value, "reserved_bytes": int64(0)}}
		}
		return driver.RowsAffected(1), nil
	}
	if q == "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?" {
		row := s.rows["system_backup_v2_metadata_reservations"][0]
		if !reflect.DeepEqual(row["sample_at"], args[1].Value) || !reflect.DeepEqual(row["reserved_bytes"], args[2].Value) {
			return driver.RowsAffected(0), nil
		}
		row["reserved_bytes"] = row["reserved_bytes"].(int64) + args[0].Value.(int64)
		s.reserves++
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(q, "UPDATE system_backup_producer_") {
		if s.zeroDomainCAS && strings.HasPrefix(q, "UPDATE system_backup_producer_domains ") {
			return driver.RowsAffected(0), nil
		}
		parts := strings.SplitN(strings.TrimPrefix(q, "UPDATE "), " SET ", 2)
		table := parts[0]
		parts = strings.SplitN(parts[1], " WHERE ", 2)
		sets := strings.Split(parts[0], ", ")
		where := strings.Split(parts[1], " AND ")
		affected := int64(0)
		for _, row := range s.rows[table] {
			match := true
			for i, condition := range where {
				key := strings.TrimSuffix(condition, " <=> ?")
				if !consumerIntegrationSQLValueEqual(key, row[key], args[len(sets)+i].Value) {
					match = false
				}
			}
			if match {
				for i, set := range sets {
					row[strings.TrimSuffix(set, " = ?")] = args[i].Value
				}
				affected++
			}
		}
		return driver.RowsAffected(affected), nil
	}
	result, err := c.candidateBridgeConn.ExecContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	g := s.bridge.base.grant
	if strings.HasPrefix(q, "INSERT INTO system_backup_v2_operations") {
		s.rows["system_backup_v2_operations"] = []map[string]driver.Value{{"public_id": args[0].Value, "origin_installation_id": g.InstallationID, "operation_type": "config_update", "target_type": "system", "target_public_id": g.InstallationID, "actor_type": "admin", "actor_id": args[3].Value, "endpoint": args[4].Value, "idempotency_key": args[5].Value, "request_hash": args[6].Value, "external_action_public_ids_canonical_json": []byte("[]"), "external_action_public_ids_size_bytes": int64(2), "external_action_public_ids_sha256": registrationHash("[]"), "status": "succeeded", "result_config_version": int64(1), "http_status": int64(201)}}
	}
	if strings.HasPrefix(q, "INSERT INTO audit_logs") {
		id, _ := result.LastInsertId()
		s.rows["audit_logs"] = append(s.rows["audit_logs"], map[string]driver.Value{"id": id, "user_id": args[0].Value, "action": args[1].Value, "resource_type": "system_backup", "details": args[2].Value, "resource_id": nil, "created_at": s.now})
	}
	return result, nil
}

type consumerIntegrationAuthority struct {
	state       *consumerIntegrationState
	capacity    *BootstrapCandidateCapacity
	prepared    *PreparedBootstrapCandidateCapacity
	reservation *BootstrapCandidateCapacityReservation
}

func (s *consumerIntegrationState) mutateOriginalFile() error {
	if s.fileMutated || s.mutateFileKind == "" {
		return nil
	}
	s.fileMutated = true
	path := s.registryFiles[s.mutateFileKind]
	if s.mutateFileKind == "grant" {
		path = s.grantFile
	}
	if s.mutateFileMode == "removed" {
		return os.Remove(path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}

func (a *consumerIntegrationAuthority) PrepareBootstrapCandidates(ctx context.Context, g OfflineBootstrapGrant, config BootstrapConfig, r pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	if !reflect.DeepEqual(r, a.state.request) {
		return PreparedBootstrapCandidateAuthority{}, pd.ErrGuardRequired
	}
	prepared, err := a.capacity.PrepareAttempt(ctx, g, config)
	if err != nil {
		return PreparedBootstrapCandidateAuthority{}, err
	}
	session := &consumerIntegrationAuthority{state: a.state, capacity: a.capacity, prepared: prepared}
	return PreparedBootstrapCandidateAuthority{Session: session, CapacityObservedAt: prepared.CapacityObservedAt()}, nil
}
func (a *consumerIntegrationAuthority) Authorize(_ context.Context, _ pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, _ pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	if a.state.mutateFileAtAuthorize {
		if err := a.state.mutateOriginalFile(); err != nil {
			return pd.BootstrapConsumptionAdmission{}, err
		}
	}
	if a.state.deny {
		return pd.BootstrapConsumptionAdmission{}, pd.ErrGuardRequired
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	until := pd.Timestamp(now.Add(time.Hour).Format(consumerIntegrationTime))
	return pd.BootstrapConsumptionAdmission{BindingHash: hash, IdentityExpiresAt: until, DependencyExpiresAt: until}, err
}
func (*consumerIntegrationAuthority) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return nil
}
func (*consumerIntegrationAuthority) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return nil
}
func (a *consumerIntegrationAuthority) Reserve(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	a.state.retainedWrite = tx
	if a.prepared == nil {
		return pd.ErrGuardRequired
	}
	var err error
	a.reservation, err = a.prepared.Reserve(ctx, tx)
	return err
}
func (a *consumerIntegrationAuthority) LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	return []pd.ResultEvidence{a.state.evidence}, nil
}
func (a *consumerIntegrationAuthority) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, _ pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts, _ time.Time) error {
	a.state.retainedRead = tx
	a.state.rechecks++
	if !a.state.mutateFileAtAuthorize {
		if err := a.state.mutateOriginalFile(); err != nil {
			return err
		}
	}
	if a.state.late {
		a.state.bridge.cells["alert_profile"] = "synthetic-late-corruption"
	}
	if a.state.lateCapacity {
		a.state.rows["system_backup_v2_metadata_reservations"][0]["reserved_bytes"] = int64(0)
	}
	if a.state.expireCapacity {
		a.state.now = a.state.now.Add(6 * time.Second)
	}
	if !facts.Replayed {
		if a.reservation == nil {
			return pd.ErrGuardRequired
		}
		return a.reservation.Recheck(ctx, tx)
	}
	return nil
}

func consumerIntegrationSeed(t *testing.T, s *consumerIntegrationState, record any) {
	t.Helper()
	row, err := pd.EncodeStoredRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	cells := map[string]driver.Value{}
	for key, value := range row.Columns {
		if n, ok := value.(uint64); ok {
			if n > 1<<63-1 {
				t.Fatal("integration fixture exceeds its signed-driver counter range")
			}
			value = int64(n)
		}
		cells[key] = value
	}
	s.rows[row.Table] = append(s.rows[row.Table], cells)
}
func consumerIntegrationPendingHash(t *testing.T, r pd.ResultRequest) pd.Hash {
	t.Helper()
	raw, _ := json.Marshal(struct {
		Scope      pd.Scope
		RunID      pd.ID
		EvidenceID pd.EvidenceID
	}{r.Scope, r.RunID, r.Evidence.EvidenceID})
	frame, err := pd.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	domain := "system-backup-producer-pending-reference.c1"
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(domain)))
	hash := sha256.New()
	hash.Write(size[:])
	hash.Write([]byte(domain))
	hash.Write(frame)
	return pd.Hash(hex.EncodeToString(hash.Sum(nil)))
}

func consumerIntegrationFixture(t *testing.T) (ConfigBootstrapService, OfflineBootstrapGrant, []byte, *consumerIntegrationState) {
	t.Helper()
	plan, bridge := candidateBridgeFixture(t)
	_, grantInput, configRaw, pinnedSources, _ := admissionFixture(t)
	config, err := DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	selection := plan.request.Candidates[0]
	var configFields map[string]json.RawMessage
	if json.Unmarshal(config.CanonicalJSON(), &configFields) != nil {
		t.Fatal("config fields")
	}
	selection.Request.Admission.Unconfigured.CandidateHash = pd.Hash(config.SHA256())
	selection.Request.Admission.Unconfigured.RegistrySetHash = pd.Hash(registrationHash(string(configFields["registries"])))
	selection.Request.Admission.Unconfigured.RefSetHash = pd.Hash(registrationHash(string(configFields["references"])))
	plan, err = NewConfigBootstrapCandidates(plan.db, grantInput, configRaw, []pd.BootstrapCandidateSelection{selection}, &candidateBridgeAuthority{bridge})
	if err != nil {
		t.Fatal(err)
	}
	bridge.base.grant = grantInput
	r := plan.request.Candidates[0].Request
	observed, _ := r.ObservedAt.Time()
	now := observed.Add(2 * time.Second)
	s := &consumerIntegrationState{bridge: bridge, rows: map[string][]map[string]driver.Value{}, now: now, request: plan.request}
	s.rows["system_backup_v2_metadata_reservations"] = []map[string]driver.Value{{"id": int64(1), "sample_at": now.Add(-time.Microsecond), "reserved_bytes": int64(0)}}
	data, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Records []struct {
			Definition string
			Value      json.RawMessage
		}
	}
	if json.Unmarshal(data, &vectors) != nil {
		t.Fatal("record vectors")
	}
	var domain pd.DomainRecord
	var grant pd.GrantRecord
	var run pd.RunRecord
	var history pd.HistoricalBindingRecord
	for _, v := range vectors.Records {
		var out any
		switch v.Definition {
		case "DomainRecord":
			out = &domain
		case "GrantRecord":
			out = &grant
		case "RunRecord":
			out = &run
		case "HistoricalBindingRecord":
			out = &history
		}
		if out != nil {
			if err := pd.DecodeRecord(v.Value, out); err != nil {
				t.Fatal(err)
			}
		}
	}
	digests, err := pd.ResultHashes(r)
	if err != nil {
		t.Fatal(err)
	}
	domain.Scope, domain.Admission, domain.Epoch = r.Scope, r.Admission, r.DomainEpoch
	domain.AdmissionExpiresAt = pd.Timestamp(now.Add(time.Hour).Format(consumerIntegrationTime))
	grant.Scope, grant.Admission, grant.GrantID, grant.Generation, grant.DomainEpoch = r.Scope, r.Admission, r.GrantID, r.GrantGeneration, r.DomainEpoch
	grant.Target, grant.Purpose = r.Target, r.Purpose
	run.Scope, run.RunID, run.GrantID, run.GrantGeneration = r.Scope, r.RunID, r.GrantID, r.GrantGeneration
	run.TargetHash, run.TargetGeneration, run.InputHash, run.EvidenceID = digests.Target, r.TargetGeneration, r.InputHash, r.Evidence.EvidenceID
	run.ObservedAt, run.ObservationExpiresAt = &r.ObservedAt, &r.ObservationExpiresAt
	run.State = "committed"
	history.Scope, history.Admission, history.RunID, history.GrantID, history.GrantGeneration, history.DomainEpoch = r.Scope, r.Admission, r.RunID, r.GrantID, r.GrantGeneration, r.DomainEpoch
	history.TargetHash, history.InputHash = digests.Target, r.InputHash
	history.Evidence = r.Evidence
	history.Evidence.ImmutableVersion = nil
	history.ObservedAt, history.ObservationExpiresAt = r.ObservedAt, r.ObservationExpiresAt
	history.OwnerWriteExpiresAt = run.OwnerWriteExpiresAt
	target := pd.TargetRecord{Scope: r.Scope, TargetHash: digests.Target, Target: r.Target, Generation: r.TargetGeneration, CurrentRunID: r.RunID, ResultVersion: "1", RowVersion: "2"}
	receipt := pd.ReceiptRecord{Scope: r.Scope, ReceiptKeyHash: digests.Key, RequestHash: digests.Request, Request: r, ResultVersion: "1", CommittedAt: pd.Timestamp(observed.Add(time.Second).Format(consumerIntegrationTime)), RetentionExpiresAt: history.RetentionExpiresAt, ChargedBytes: "1"}
	for _, record := range []any{&domain, &grant, &run, &history, &target, &receipt} {
		consumerIntegrationSeed(t, s, record)
	}
	for kind, key := range map[string]pd.Hash{"bootstrap_candidate": digests.Key, "producer_receipt": digests.Key, "hold": consumerIntegrationPendingHash(t, r)} {
		consumerIntegrationSeed(t, s, &pd.ReferenceRecord{Scope: r.Scope, EvidenceID: r.Evidence.EvidenceID, ReferenceKind: kind, ReferenceKeyHash: key, ProtectedUntil: history.RetentionExpiresAt, CreatedAt: history.CreatedAt})
	}
	s.evidence = pd.ResultEvidence{Evidence: r.Evidence, RowVersion: r.ExpectedEvidenceVersion, State: "ready", Failure: "none", RetentionExpiresAt: history.RetentionExpiresAt, ProtectedUntil: history.RetentionExpiresAt}
	b := r.Evidence
	retention, _ := history.RetentionExpiresAt.Time()
	version, _ := r.ExpectedEvidenceVersion.SQLInt64()
	content, _ := b.ContentBytes.SQLInt64()
	object, _ := b.ObjectBytes.SQLInt64()
	s.rows["system_backup_v2_evidence"] = []map[string]driver.Value{{"id": int64(101), "schema_version": "system-backup-evidence.v1", "public_id": string(b.EvidenceID), "owner_target_type": b.OwnerType, "owner_target_public_id": string(b.OwnerID), "evidence_type": b.EvidenceType, "storage_state": "ready", "evidence_failure_code": "none", "storage_provider_role": "evidence", "storage_identity_hash": string(b.StoreIdentityHash), "storage_ref_version": string(b.StoreRefVersion), "storage_relative_key_hash": string(b.RelativeKeyHash), "storage_relative_key": string(history.RelativeKey), "storage_immutable_version": string(*b.ImmutableVersion), "content_checksum": string(b.ContentHash), "content_size_bytes": content, "object_checksum": string(b.ObjectHash), "object_size_bytes": object, "redaction_classification": b.Classification, "encryption": "envelope_v1", "envelope_framing_version": "system-backup-evidence-envelope.v1", "kek_identity_hash": string(b.KEKIdentityHash), "kek_version": string(b.KEKVersion), "row_version": version, "expires_at": retention, "protected_until": retention, "claim_owner": nil, "claim_expires_at": nil, "inline_payload": nil, "chunk_count": int64(1), "plaintext_chunk_size_bytes": int64(1048576), "chunk_list_root": strings.Repeat("a", 64), "envelope_hash": strings.Repeat("b", 64), "media_type": "application/json", "created_at": observed}}
	s.rows["system_backup_v2_evidence_chunks"] = []map[string]driver.Value{{"evidence_id": int64(101), "chunk_index": int64(0), "plaintext_offset": int64(0), "plaintext_length": content, "plaintext_sha256": string(b.ContentHash), "object_frame_offset": int64(0), "object_frame_length": object, "ciphertext_sha256": string(b.ObjectHash), "gcm_nonce": []byte("synthetic-nonce"), "gcm_tag": []byte("synthetic-tag")}}
	db := sql.OpenDB(consumerIntegrationConnector{s})
	t.Cleanup(func() { db.Close() })
	plan.db = db
	s.reportFile = filepath.Join(t.TempDir(), "original-capacity-report.json")
	reportBytes, _ := json.Marshal(CapacityReport{ServerUUID: plan.grant.ServerUUID, Database: plan.grant.Database, ObservedAt: now, AllocatedBytes: 0, AvailableBytes: 2199023255552})
	if err := os.WriteFile(s.reportFile, reportBytes, 0600); err != nil {
		t.Fatal(err)
	}
	capacity, err := NewBootstrapCandidateCapacity(DatabaseIdentity{plan.grant.ServerUUID, plan.grant.Database}, s.reportFile)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, expires := now.Add(-time.Hour), now.Add(48*time.Hour)
	materialDir := t.TempDir()
	s.grantFile = filepath.Join(materialDir, "original-grant.json")
	s.registryFiles = map[string]string{}
	grantBytes, err := json.Marshal(BootstrapGrantFile{"system-backup-offline-bootstrap-grant.v1", notBefore, expires, plan.grant})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.grantFile, grantBytes, 0600); err != nil {
		t.Fatal(err)
	}
	profile := BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: plan.grant.InstallationID, ExpectedServerUUID: plan.grant.ServerUUID, ExpectedDatabase: plan.grant.Database, ConfigSHA256: plan.grant.ConfigSHA256, GrantFile: s.grantFile, GrantSHA256: registrationHash(string(grantBytes)), RegistryDirectory: filepath.Join(materialDir, "registries")}
	for _, ref := range plan.config.Registries() {
		raw, err := pinnedSources.RegistryBytes(ref.Kind, ref.Version, ref.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(profile.RegistryDirectory, ref.Kind, ref.Version, ref.SHA256+".json")
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		s.registryFiles[ref.Kind] = path
		if ref.Kind != "rbac_bindings" && s.nonRBACFile == "" {
			s.nonRBACFile = path
		}
	}
	pinned, err := NewBootstrapCandidateFileAuthority(profile, &consumerIntegrationAuthority{state: s, capacity: capacity})
	if err != nil {
		t.Fatal(err)
	}
	fileAuthority := pinned.(*bootstrapCandidateFileAuthority)
	fileAuthority.snapshot.clock = func() time.Time { return s.now }
	readGrant := fileAuthority.snapshot.readGrant
	readRegistry := fileAuthority.snapshot.registryBytes
	fileAuthority.snapshot.readGrant = func() (OfflineBootstrapGrant, time.Time, time.Time, error) { s.grantReads++; return readGrant() }
	fileAuthority.snapshot.registryBytes = func(kind, version, digest string) ([]byte, error) {
		s.registryReads++
		return readRegistry(kind, version, digest)
	}
	plan.authority = pinned
	return ConfigBootstrapService{DB: db, Candidates: plan}, plan.grant, plan.config.CanonicalJSON(), s
}

func TestBootstrapCandidateServiceConsumerIntegration(t *testing.T) {
	for _, scenario := range []string{"commit_replay", "late_failure_rollback", "commit_unknown", "replay_missing_capacity_report", "late_capacity_rollback", "capacity_wait_rollback", "initial_missing_capacity_report", "domain_cas_conflict", "late_grant_removed", "late_grant_replaced", "late_rbac_removed", "late_rbac_replaced", "grant_removed_in_authorize", "replay_missing_non_rbac_registry", "initial_missing_non_rbac_registry", "late_non_rbac_removed", "late_non_rbac_replaced", "replay_rbac_removed", "replay_rbac_replaced"} {
		t.Run(scenario, func(t *testing.T) {
			svc, g, raw, s := consumerIntegrationFixture(t)
			before := consumerIntegrationClone(s.rows)
			s.late = scenario == "late_failure_rollback"
			s.lateCapacity = scenario == "late_capacity_rollback"
			s.expireCapacity = scenario == "capacity_wait_rollback"
			s.zeroDomainCAS = scenario == "domain_cas_conflict"
			switch scenario {
			case "late_grant_removed":
				s.mutateFileKind, s.mutateFileMode = "grant", "removed"
			case "late_grant_replaced":
				s.mutateFileKind, s.mutateFileMode = "grant", "replaced"
			case "late_rbac_removed":
				s.mutateFileKind, s.mutateFileMode = "rbac_bindings", "removed"
			case "late_rbac_replaced":
				s.mutateFileKind, s.mutateFileMode = "rbac_bindings", "replaced"
			case "grant_removed_in_authorize":
				s.mutateFileKind, s.mutateFileMode = "grant", "removed"
				s.mutateFileAtAuthorize = true
			case "late_non_rbac_removed", "late_non_rbac_replaced":
				for kind, path := range s.registryFiles {
					if path == s.nonRBACFile {
						s.mutateFileKind = kind
					}
				}
				s.mutateFileMode = strings.TrimPrefix(scenario, "late_non_rbac_")
			}
			if scenario == "initial_missing_capacity_report" {
				if err := os.Remove(s.reportFile); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "initial_missing_non_rbac_registry" {
				if err := os.Remove(s.nonRBACFile); err != nil {
					t.Fatal(err)
				}
			}
			s.bridge.base.commitUnknown = scenario == "commit_unknown"
			first, err := svc.Bootstrap(context.Background(), g, raw)
			if s.mutateFileAtAuthorize {
				if err == nil || first != (ConfigBootstrapResult{}) || !s.fileMutated || s.commits != 0 || s.rechecks != 0 || !reflect.DeepEqual(before, s.rows) {
					t.Fatal("L2 source revocation bypassed current file authority", first, err)
				}
				return
			}
			if s.zeroDomainCAS {
				if err == nil || first != (ConfigBootstrapResult{}) || s.commits != 0 || s.rollbacks != 1 || !reflect.DeepEqual(before, s.rows) || s.reserves != 0 {
					t.Fatal("zero-row domain CAS escaped atomic rollback", first, err)
				}
				return
			}
			if scenario == "initial_missing_capacity_report" {
				if err == nil || first != (ConfigBootstrapResult{}) || s.commits != 0 || s.rechecks != 0 || !reflect.DeepEqual(before, s.rows) {
					t.Fatal("first consumption bypassed missing capacity", first, err)
				}
				return
			}
			if scenario == "initial_missing_non_rbac_registry" {
				if err == nil || first != (ConfigBootstrapResult{}) || s.commits != 0 || s.rechecks != 0 || s.reserves != 0 || !reflect.DeepEqual(before, s.rows) {
					t.Fatal("first consumption bypassed missing registry", first, err)
				}
				return
			}
			if scenario == "late_failure_rollback" || s.lateCapacity || s.expireCapacity || strings.HasPrefix(scenario, "late_grant_") || strings.HasPrefix(scenario, "late_rbac_") || strings.HasPrefix(scenario, "late_non_rbac_") {
				if err == nil || first != (ConfigBootstrapResult{}) || s.commits != 0 || s.rollbacks != 1 || s.rechecks != 1 || !reflect.DeepEqual(before, s.rows) || len(s.bridge.cells) != 0 || s.reserves != 0 {
					t.Fatal("late failure did not roll all owners back", first, err, s.commits, s.rollbacks, s.queries)
				}
				return
			}
			if scenario == "commit_unknown" {
				if !errors.Is(err, ErrRegistrationCommitUnknown) || first != (ConfigBootstrapResult{}) {
					t.Fatal("unknown commit exposed success", first, err)
				}
			} else if err != nil || first.Version != 1 || first.Replayed {
				t.Fatal("full service chain failed", first, err, s.queries)
			}
			if s.commits != 1 || s.reserves != 1 || len(s.bridge.base.committed) != 5 {
				t.Fatal("not one atomic bootstrap", s.commits, s.reserves, s.bridge.base.committed)
			}
			if s.rows["system_backup_v2_metadata_reservations"][0]["reserved_bytes"] != int64(8192+65536) {
				t.Fatal("concrete capacity reservation cost changed")
			}
			if s.grantReads < 1 || s.registryReads < 1 || s.rechecks != 1 {
				t.Fatal("original pinned sources were bypassed", s.grantReads, s.registryReads)
			}
			var domain pd.DomainRecord
			stored := s.rows["system_backup_producer_domains"][0]
			var record pd.StoredRecord
			record.Table = "system_backup_producer_domains"
			record.Columns = map[string]any{}
			for key, value := range stored {
				record.Columns[key] = value
			}
			if err := pd.DecodeStoredRecord(record, svc.Candidates.request.Scope, &domain); err != nil || domain.State != "closed" || domain.Epoch != "2" {
				t.Fatal("epoch did not close atomically", domain, err)
			}
			stable := consumerIntegrationClone(s.rows)
			if scenario == "replay_missing_capacity_report" {
				if err := os.Remove(s.reportFile); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "replay_missing_non_rbac_registry" {
				if err := os.Remove(s.nonRBACFile); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(scenario, "replay_rbac_") {
				s.mutateFileKind = "rbac_bindings"
				s.mutateFileMode = strings.TrimPrefix(scenario, "replay_rbac_")
				if err := s.mutateOriginalFile(); err != nil {
					t.Fatal(err)
				}
			}
			s.now = s.now.Add(24 * time.Hour)
			s.bridge.base.commitUnknown = false
			retry, err := svc.Bootstrap(context.Background(), g, raw)
			if strings.HasPrefix(scenario, "replay_rbac_") {
				if err == nil || retry != (ConfigBootstrapResult{}) || s.commits != 1 || s.reserves != 1 || !reflect.DeepEqual(stable, s.rows) {
					t.Fatal("historical retry bypassed current RBAC file", retry, err)
				}
				return
			}
			if err != nil || !retry.Replayed || retry.OperationPublicID != s.bridge.base.op || s.reserves != 1 || !reflect.DeepEqual(stable, s.rows) || len(s.bridge.base.committed) != 5 {
				t.Fatal("same-key retry reconsumed", retry, err, s.queries)
			}
			if s.grantReads < 2 || s.registryReads < 2 || s.rechecks != 2 {
				t.Fatal("historical retry bypassed original sources", s.grantReads, s.registryReads)
			}
			queryCount := len(s.queries)
			if _, err := s.retainedRead.SampleTime(context.Background()); !errors.Is(err, pd.ErrGuardRequired) {
				t.Fatal("retained final read clock escaped", err)
			}
			if rows, err := s.retainedRead.QueryContext(context.Background(), "SELECT 1"); !errors.Is(err, pd.ErrGuardRequired) || rows != nil {
				t.Fatal("retained final read query escaped", err)
			}
			if err := s.retainedRead.QueryRowContext(context.Background(), "SELECT 1").Scan(new(int)); err == nil {
				t.Fatal("retained final row escaped")
			}
			if pd.SameBootstrapTransaction(s.retainedWrite, s.retainedRead) || len(s.queries) != queryCount {
				t.Fatal("closed final view retained transaction identity or dispatched SQL")
			}
			s.deny = true
			if out, err := svc.Bootstrap(context.Background(), g, raw); err == nil || out != (ConfigBootstrapResult{}) {
				t.Fatal("replay bypassed current authority", out, err)
			}
			s.deny = false
			if err := os.Remove(s.grantFile); err != nil {
				t.Fatal(err)
			}
			commits := s.commits
			if out, err := svc.Bootstrap(context.Background(), g, raw); err == nil || out != (ConfigBootstrapResult{}) || s.commits != commits {
				t.Fatal("historical retry bypassed original grant revocation", out, err)
			}
		})
	}
}
