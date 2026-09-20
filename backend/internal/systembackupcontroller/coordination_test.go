package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordedCoordinationTx struct {
	gate         GateSnapshot
	lease        MutationLeaseSnapshot
	outstanding  uint64
	lockGateErr  error
	lockLeaseErr error
	countErr     error
	execErr      error
	execErrors   []error
	commitErr    error
	rows         int64
	execRows     []int64
	order        []string
	queries      []string
	args         [][]any
}

func (t *recordedCoordinationTx) LockGate(ctx context.Context, key GateKey) (GateSnapshot, error) {
	t.order = append(t.order, "lock_gate")
	if t.lockGateErr != nil {
		return GateSnapshot{}, t.lockGateErr
	}
	return t.gate, nil
}

func (t *recordedCoordinationTx) LockMutationLease(ctx context.Context, leaseID string) (MutationLeaseSnapshot, error) {
	t.order = append(t.order, "lock_lease")
	if t.lockLeaseErr != nil {
		return MutationLeaseSnapshot{}, t.lockLeaseErr
	}
	return t.lease, nil
}

func (t *recordedCoordinationTx) CountOutstandingMutationLeases(ctx context.Context, key GateKey, throughGeneration uint64) (uint64, error) {
	t.order = append(t.order, "count_leases")
	if t.countErr != nil {
		return 0, t.countErr
	}
	return t.outstanding, nil
}

func (t *recordedCoordinationTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	index := len(t.queries)
	t.order = append(t.order, "exec")
	t.queries = append(t.queries, query)
	t.args = append(t.args, args)
	if index < len(t.execErrors) && t.execErrors[index] != nil {
		return nil, t.execErrors[index]
	}
	if t.execErr != nil {
		return nil, t.execErr
	}
	rows := t.rows
	if index < len(t.execRows) {
		rows = t.execRows[index]
	}
	return fixedResult(rows), nil
}

func (t *recordedCoordinationTx) Commit() error {
	t.order = append(t.order, "commit")
	return t.commitErr
}

func (t *recordedCoordinationTx) Rollback() error {
	t.order = append(t.order, "rollback")
	return nil
}

type recordedReadiness struct {
	err   error
	calls int
}

func (r *recordedReadiness) VerifyParticipantsPaused(ctx context.Context, executor CoordinationTransaction, key GateKey, generation uint64) error {
	r.calls++
	if tx, ok := executor.(*recordedCoordinationTx); ok {
		tx.order = append(tx.order, "verify_participants")
	}
	return r.err
}

type recordedRecoveryReadiness struct {
	err   error
	calls int
}

func (r *recordedRecoveryReadiness) VerifyParticipantsRunning(ctx context.Context, executor CoordinationTransaction, key GateKey, generation uint64) error {
	r.calls++
	if tx, ok := executor.(*recordedCoordinationTx); ok {
		tx.order = append(tx.order, "verify_participants_running")
	}
	return r.err
}

func validGateKey() GateKey {
	return GateKey{InstallationID: "installation_primary", Scope: "system-backup:capture"}
}

func validGatePolicy() GatePolicy {
	return GatePolicy{LockTTL: DefaultMaintenanceLockTTL, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: DefaultQuiesceMaxHold}
}

func acquiringGateToken() GateToken {
	return GateToken{GateSnapshot: GateSnapshot{
		Key: validGateKey(), State: GateAcquiring, Generation: 5, FencingToken: 7, Owner: "controller:pod-1", RowVersion: 11,
	}}
}

func validMutationPolicy() MutationLeasePolicy {
	return MutationLeasePolicy{TTL: DefaultMutationLeaseTTL, HeartbeatInterval: DefaultMutationHeartbeat}
}

func validMutationToken() MutationLeaseToken {
	return MutationLeaseToken{
		LeaseID: "11111111-1111-4111-8111-111111111111", Key: validGateKey(), Owner: "api:pod-1", Generation: 4, RowVersion: 1,
	}
}

func TestGatePolicyUsesV12Bounds(t *testing.T) {
	if err := validGatePolicy().Validate(); err != nil {
		t.Fatalf("default gate policy rejected: %v", err)
	}
	for _, policy := range []GatePolicy{
		{LockTTL: MinMaintenanceLockTTL - time.Second, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: MinQuiesceMaxHold},
		{LockTTL: MaxMaintenanceLockTTL + time.Second, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: DefaultQuiesceMaxHold},
		{LockTTL: DefaultMaintenanceLockTTL, AcquisitionTimeout: MinGateAcquisitionTimeout - time.Second, MaxHold: DefaultQuiesceMaxHold},
		{LockTTL: DefaultMaintenanceLockTTL, AcquisitionTimeout: MaxGateAcquisitionTimeout + time.Second, MaxHold: DefaultQuiesceMaxHold},
		{LockTTL: DefaultMaintenanceLockTTL, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: MinQuiesceMaxHold - time.Second},
		{LockTTL: DefaultMaintenanceLockTTL, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: MaxQuiesceMaxHold + time.Second},
		{LockTTL: MinMaintenanceLockTTL, AcquisitionTimeout: MinGateAcquisitionTimeout, MaxHold: MinMaintenanceLockTTL},
		{LockTTL: DefaultMaintenanceLockTTL + time.Millisecond, AcquisitionTimeout: DefaultGateAcquisitionTime, MaxHold: DefaultQuiesceMaxHold},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid gate policy accepted: %#v", policy)
		}
	}
}

func TestBeginGateAcquisitionLocksThenAdvancesGeneration(t *testing.T) {
	key := validGateKey()
	tx := &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateIdle, Generation: 4, FencingToken: 7, RowVersion: 10}}
	token, err := BeginGateAcquisition(context.Background(), tx, key, "controller:pod-1", 10, validGatePolicy())
	if err != nil {
		t.Fatalf("BeginGateAcquisition returned error: %v", err)
	}
	if token.State != GateAcquiring || token.Generation != 5 || token.FencingToken != 7 || token.RowVersion != 11 {
		t.Fatalf("unexpected acquiring token: %#v", token)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "exec", "exec", "commit"}) {
		t.Fatalf("gate acquisition order = %#v", tx.order)
	}
	query := tx.queries[0]
	for _, required := range []string{
		"gate_state = 'acquiring'", "generation = generation + 1", "UTC_TIMESTAMP(6)",
		"lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND))",
		"acquisition_deadline_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)",
		"gate_state = 'idle' AND generation = ? AND row_version = ?",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("acquire gate SQL missing %q: %s", required, query)
		}
	}
	if strings.Contains(query, "NOW()") || strings.Contains(query, "system_maintenance_mutation_leases") {
		t.Fatalf("gate CAS bypasses row-lock protocol: %s", query)
	}
	if !strings.Contains(tx.queries[1], "INSERT INTO system_backup_events") || !strings.Contains(tx.queries[1], "'gate_changed'") {
		t.Fatalf("gate acquisition event = %s", tx.queries[1])
	}
}

func TestBeginGateAcquisitionRejectsStaleSnapshotAndRollsBack(t *testing.T) {
	key := validGateKey()
	tx := &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateAcquiring, Generation: 5, Owner: "other", RowVersion: 10}}
	_, err := BeginGateAcquisition(context.Background(), tx, key, "controller:pod-1", 10, validGatePolicy())
	if !errors.Is(err, ErrGateTransitionRejected) {
		t.Fatalf("stale gate error = %v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "rollback"}) {
		t.Fatalf("stale gate order = %#v", tx.order)
	}

	tx = &recordedCoordinationTx{rows: 1, lockGateErr: sql.ErrNoRows}
	if _, err := BeginGateAcquisition(context.Background(), tx, key, "controller:pod-1", 10, validGatePolicy()); !errors.Is(err, ErrGateTransitionRejected) {
		t.Fatalf("missing gate error = %v", err)
	}
}

func TestGateTransitionEventFailureRollsBackStateMutation(t *testing.T) {
	key := validGateKey()
	tx := &recordedCoordinationTx{
		rows:       1,
		gate:       GateSnapshot{Key: key, State: GateIdle, Generation: 4, FencingToken: 7, RowVersion: 10},
		execErrors: []error{nil, errors.New("event unavailable")},
	}
	if _, err := BeginGateAcquisition(context.Background(), tx, key, "controller:pod-1", 10, validGatePolicy()); err == nil || !strings.Contains(err.Error(), "record system backup gate transition event") {
		t.Fatalf("BeginGateAcquisition error=%v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "exec", "exec", "rollback"}) {
		t.Fatalf("event failure order=%#v", tx.order)
	}
}

func TestAdvanceGateHeldRequiresLeaseDrainAndParticipantProof(t *testing.T) {
	token := acquiringGateToken()
	tx := &recordedCoordinationTx{rows: 1, gate: token.GateSnapshot}
	readiness := &recordedReadiness{}
	held, err := AdvanceGateHeld(context.Background(), tx, token, validGatePolicy(), readiness)
	if err != nil {
		t.Fatalf("AdvanceGateHeld returned error: %v", err)
	}
	if held.State != GateHeld || held.FencingToken != 8 || held.RowVersion != 12 {
		t.Fatalf("unexpected held token: %#v", held)
	}
	if readiness.calls != 1 || !reflect.DeepEqual(tx.order, []string{"lock_gate", "count_leases", "verify_participants", "exec", "exec", "commit"}) {
		t.Fatalf("held proof order = %#v, readiness calls = %d", tx.order, readiness.calls)
	}
	for _, required := range []string{
		"gate_state = 'held'", "fencing_token = fencing_token + 1", "lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND))", "absolute_hold_deadline_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)",
		"lease_expires_at > UTC_TIMESTAMP(6) AND acquisition_deadline_at > UTC_TIMESTAMP(6)",
	} {
		if !strings.Contains(tx.queries[0], required) {
			t.Fatalf("held SQL missing %q: %s", required, tx.queries[0])
		}
	}

	tx = &recordedCoordinationTx{rows: 1, gate: token.GateSnapshot, outstanding: 1}
	readiness = &recordedReadiness{}
	if _, err := AdvanceGateHeld(context.Background(), tx, token, validGatePolicy(), readiness); !errors.Is(err, ErrGateHoldNotReady) {
		t.Fatalf("outstanding lease error = %v", err)
	}
	if readiness.calls != 0 || !reflect.DeepEqual(tx.order, []string{"lock_gate", "count_leases", "rollback"}) {
		t.Fatalf("outstanding lease reached participant/fence: %#v", tx.order)
	}

	tx = &recordedCoordinationTx{rows: 1, gate: token.GateSnapshot}
	readiness = &recordedReadiness{err: errors.New("participant ack missing")}
	if _, err := AdvanceGateHeld(context.Background(), tx, token, validGatePolicy(), readiness); !errors.Is(err, ErrGateHoldNotReady) {
		t.Fatalf("participant readiness error = %v", err)
	}
	if len(tx.queries) != 0 {
		t.Fatalf("participant rejection advanced fence: %#v", tx.queries)
	}
}

func TestGateRenewAbortAndReleaseKeepExactFence(t *testing.T) {
	policy := validGatePolicy()
	acquiring := acquiringGateToken()
	exec := &recordedExec{rows: 1}
	renewed, err := RenewGate(context.Background(), exec, acquiring, policy)
	if err != nil || renewed.RowVersion != acquiring.RowVersion+1 {
		t.Fatalf("renew acquiring gate = %#v, %v", renewed, err)
	}
	if !strings.Contains(exec.queries[0], "lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), acquisition_deadline_at)") || !strings.Contains(exec.queries[0], "acquisition_deadline_at > UTC_TIMESTAMP(6)") {
		t.Fatalf("acquiring renewal lacks acquisition deadline: %s", exec.queries[0])
	}

	exec = &recordedExec{rows: 1}
	if _, err := AbortGateAcquisition(context.Background(), exec, renewed); err != nil {
		t.Fatalf("AbortGateAcquisition: %v", err)
	}
	for _, required := range []string{"gate_state = 'idle'", "generation = ?", "fencing_token = ?", "lock_owner = ?", "lease_expires_at > UTC_TIMESTAMP(6)"} {
		if !strings.Contains(exec.queries[0], required) {
			t.Fatalf("abort SQL missing %q: %s", required, exec.queries[0])
		}
	}

	held := acquiring
	held.State = GateHeld
	held.FencingToken = 8
	exec = &recordedExec{rows: 1}
	held, err = RenewGate(context.Background(), exec, held, policy)
	if err != nil || !strings.Contains(exec.queries[0], "lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), absolute_hold_deadline_at)") || !strings.Contains(exec.queries[0], "absolute_hold_deadline_at > UTC_TIMESTAMP(6)") {
		t.Fatalf("renew held gate = %#v, %v, SQL=%s", held, err, exec.queries[0])
	}
	exec = &recordedExec{rows: 1}
	releasing, err := BeginGateRelease(context.Background(), exec, held)
	if err != nil || releasing.State != GateReleasing {
		t.Fatalf("BeginGateRelease = %#v, %v", releasing, err)
	}
	exec = &recordedExec{rows: 1}
	releasing, err = RenewGate(context.Background(), exec, releasing, policy)
	if err != nil {
		t.Fatalf("renew releasing gate: %v", err)
	}
	if !strings.Contains(exec.queries[0], "lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)") || strings.Contains(exec.queries[0], "absolute_hold_deadline_at > UTC_TIMESTAMP(6)") {
		t.Fatalf("releasing renewal remained bounded by elapsed hold deadline: %s", exec.queries[0])
	}
	exec = &recordedExec{rows: 1}
	version, err := FinishGateRelease(context.Background(), exec, releasing)
	if err != nil || version != releasing.RowVersion+1 {
		t.Fatalf("FinishGateRelease version=%d error=%v", version, err)
	}
	if !strings.Contains(exec.queries[0], "fencing_token = ?") || strings.Contains(exec.queries[0], "fencing_token = 0") {
		t.Fatalf("release did not preserve exact fence: %s", exec.queries[0])
	}
}

func TestRecoverGateReleaseFencesExpiredHolderAndOnlyMovesTowardResume(t *testing.T) {
	key := validGateKey()
	held := GateSnapshot{Key: key, State: GateHeld, Generation: 5, FencingToken: 8, Owner: "controller:old", RowVersion: 20}
	tx := &recordedCoordinationTx{rows: 1, gate: held}
	recovered, err := RecoverGateRelease(context.Background(), tx, key, "controller:new", held.RowVersion, validGatePolicy())
	if err != nil {
		t.Fatalf("RecoverGateRelease held: %v", err)
	}
	if recovered.State != GateReleasing || recovered.Generation != held.Generation || recovered.FencingToken != held.FencingToken+1 || recovered.Owner != "controller:new" || recovered.RowVersion != held.RowVersion+1 {
		t.Fatalf("unexpected recovered token: %#v", recovered)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "exec", "exec", "commit"}) {
		t.Fatalf("recover held order = %#v", tx.order)
	}
	for _, required := range []string{
		"gate_state = 'releasing'", "fencing_token = fencing_token + 1", "release_started_at = COALESCE(release_started_at, UTC_TIMESTAMP(6))",
		"lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6)",
	} {
		if !strings.Contains(tx.queries[0], required) {
			t.Fatalf("held recovery SQL missing %q: %s", required, tx.queries[0])
		}
	}

	releasing := held
	releasing.State = GateReleasing
	tx = &recordedCoordinationTx{rows: 1, gate: releasing}
	if _, err := RecoverGateRelease(context.Background(), tx, key, "controller:new", releasing.RowVersion, validGatePolicy()); err != nil {
		t.Fatalf("RecoverGateRelease releasing: %v", err)
	}
	if strings.Contains(tx.queries[0], "absolute_hold_deadline_at <= UTC_TIMESTAMP(6)") || !strings.Contains(tx.queries[0], "lease_expires_at <= UTC_TIMESTAMP(6)") {
		t.Fatalf("live releasing owner could be stolen by hold deadline: %s", tx.queries[0])
	}

	acquiring := held
	acquiring.State = GateAcquiring
	acquiring.FencingToken = 0
	tx = &recordedCoordinationTx{rows: 1, gate: acquiring}
	if _, err := RecoverGateRelease(context.Background(), tx, key, "controller:new", acquiring.RowVersion, validGatePolicy()); !errors.Is(err, ErrGateTransitionRejected) {
		t.Fatalf("acquiring recovery must require participant-running proof: %v", err)
	}
	if len(tx.queries) != 0 {
		t.Fatalf("acquiring recovery mutated gate: %#v", tx.queries)
	}
}

func TestRecoverGateIdleRequiresParticipantRunningProofAndExpiredCAS(t *testing.T) {
	key := validGateKey()
	acquiring := GateSnapshot{Key: key, State: GateAcquiring, Generation: 5, FencingToken: 7, Owner: "controller:old", RowVersion: 20}
	tx := &recordedCoordinationTx{rows: 1, gate: acquiring}
	readiness := &recordedRecoveryReadiness{}
	version, err := RecoverGateIdle(context.Background(), tx, key, acquiring.RowVersion, readiness)
	if err != nil {
		t.Fatalf("RecoverGateIdle: %v", err)
	}
	if version != acquiring.RowVersion+1 || readiness.calls != 1 {
		t.Fatalf("recovered version=%d readiness calls=%d", version, readiness.calls)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "verify_participants_running", "exec", "exec", "commit"}) {
		t.Fatalf("recover idle order = %#v", tx.order)
	}
	for _, required := range []string{
		"gate_state = 'idle'", "gate_state = 'acquiring'", "generation = ?", "fencing_token = ?", "lock_owner = ?", "row_version = ?",
		"lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6)",
	} {
		if !strings.Contains(tx.queries[0], required) {
			t.Fatalf("recover idle SQL missing %q: %s", required, tx.queries[0])
		}
	}

	tx = &recordedCoordinationTx{rows: 1, gate: acquiring}
	readiness = &recordedRecoveryReadiness{err: errors.New("participant still paused")}
	if _, err := RecoverGateIdle(context.Background(), tx, key, acquiring.RowVersion, readiness); !errors.Is(err, ErrGateRecoveryNotReady) {
		t.Fatalf("missing running proof error = %v", err)
	}
	if len(tx.queries) != 0 || !reflect.DeepEqual(tx.order, []string{"lock_gate", "verify_participants_running", "rollback"}) {
		t.Fatalf("missing proof mutated acquiring gate: order=%#v queries=%#v", tx.order, tx.queries)
	}

	tx = &recordedCoordinationTx{rows: 0, gate: acquiring}
	readiness = &recordedRecoveryReadiness{}
	if _, err := RecoverGateIdle(context.Background(), tx, key, acquiring.RowVersion, readiness); !errors.Is(err, ErrGateTransitionRejected) {
		t.Fatalf("live acquiring recovery error = %v", err)
	}
}

func TestMutationLeasePolicyUsesV12Bounds(t *testing.T) {
	if err := validMutationPolicy().Validate(); err != nil {
		t.Fatalf("default mutation policy rejected: %v", err)
	}
	for _, policy := range []MutationLeasePolicy{
		{TTL: MinMutationLeaseTTL - time.Second, HeartbeatInterval: MinMutationHeartbeatInterval},
		{TTL: MaxMutationLeaseTTL + time.Second, HeartbeatInterval: DefaultMutationHeartbeat},
		{TTL: DefaultMutationLeaseTTL, HeartbeatInterval: MinMutationHeartbeatInterval - time.Second},
		{TTL: DefaultMutationLeaseTTL, HeartbeatInterval: DefaultMutationLeaseTTL/3 + time.Second},
		{TTL: DefaultMutationLeaseTTL + time.Millisecond, HeartbeatInterval: DefaultMutationHeartbeat},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid mutation policy accepted: %#v", policy)
		}
	}
}

func TestAcquireMutationLeaseLocksIdleGateBeforeInsert(t *testing.T) {
	key := validGateKey()
	tx := &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateIdle, Generation: 4, RowVersion: 10}}
	request := MutationLeaseRequest{
		LeaseID: "11111111-1111-4111-8111-111111111111", Key: key, OperationIdentity: "update.instance", RequestID: "request:1", Owner: "api:pod-1", ExpectedGeneration: 4,
	}
	token, err := AcquireMutationLease(context.Background(), tx, request, validMutationPolicy())
	if err != nil {
		t.Fatalf("AcquireMutationLease returned error: %v", err)
	}
	if token.Generation != 4 || token.RowVersion != 1 {
		t.Fatalf("unexpected mutation token: %#v", token)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "exec", "commit"}) {
		t.Fatalf("mutation acquisition order = %#v", tx.order)
	}
	query := tx.queries[0]
	for _, required := range []string{"INSERT INTO system_maintenance_mutation_leases", "gate_generation", "UTC_TIMESTAMP(6)", "DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)"} {
		if !strings.Contains(query, required) {
			t.Fatalf("mutation insert missing %q: %s", required, query)
		}
	}

	tx = &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateAcquiring, Generation: 5, Owner: "controller:pod-1", RowVersion: 11}}
	if _, err := AcquireMutationLease(context.Background(), tx, request, validMutationPolicy()); !errors.Is(err, ErrMutationLeaseRejected) {
		t.Fatalf("non-idle gate mutation error = %v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "rollback"}) {
		t.Fatalf("rejected mutation touched rows: %#v", tx.order)
	}
}

func TestMutationLeaseCommitValidationRenewAndActiveRelease(t *testing.T) {
	token := validMutationToken()
	gate := GateSnapshot{Key: token.Key, State: GateIdle, Generation: token.Generation, RowVersion: 10}
	lease := MutationLeaseSnapshot{LeaseID: token.LeaseID, Key: token.Key, Owner: token.Owner, Generation: token.Generation, RowVersion: token.RowVersion, Live: true}

	tx := &recordedCoordinationTx{rows: 1, gate: gate, lease: lease}
	if err := ValidateMutationLeaseForCommit(context.Background(), tx, token); err != nil {
		t.Fatalf("ValidateMutationLeaseForCommit: %v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease"}) {
		t.Fatalf("commit validation lock order = %#v", tx.order)
	}

	tx = &recordedCoordinationTx{rows: 1, gate: gate, lease: lease}
	renewed, err := RenewMutationLease(context.Background(), tx, token, validMutationPolicy())
	if err != nil || renewed.RowVersion != token.RowVersion+1 {
		t.Fatalf("RenewMutationLease = %#v, %v", renewed, err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "exec", "commit"}) {
		t.Fatalf("mutation renewal order = %#v", tx.order)
	}
	if !strings.Contains(tx.queries[0], "expires_at > UTC_TIMESTAMP(6)") {
		t.Fatalf("mutation renewal lacks live CAS: %s", tx.queries[0])
	}

	lease.RowVersion = renewed.RowVersion
	gate.State = GateAcquiring
	gate.Generation++
	gate.Owner = "controller:pod-1"
	tx = &recordedCoordinationTx{rows: 1, gate: gate, lease: lease}
	if err := ReleaseMutationLease(context.Background(), tx, renewed); err != nil {
		t.Fatalf("ReleaseMutationLease during acquisition: %v", err)
	}
	if !reflect.DeepEqual(tx.order, []string{"lock_gate", "lock_lease", "exec", "commit"}) {
		t.Fatalf("mutation release order = %#v", tx.order)
	}
	if !strings.HasPrefix(tx.queries[0], "DELETE FROM system_maintenance_mutation_leases") {
		t.Fatalf("mutation release is not exact delete: %s", tx.queries[0])
	}

	lease.Live = false
	tx = &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: token.Key, State: GateIdle, Generation: token.Generation}, lease: lease}
	if err := ValidateMutationLeaseForCommit(context.Background(), tx, renewed); !errors.Is(err, ErrMutationLeaseLost) {
		t.Fatalf("expired commit validation error = %v", err)
	}

	tx = &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: token.Key, State: GateIdle, Generation: token.Generation}, lockLeaseErr: sql.ErrNoRows}
	if err := ValidateMutationLeaseForCommit(context.Background(), tx, renewed); !errors.Is(err, ErrMutationLeaseLost) {
		t.Fatalf("missing mutation lease validation error = %v", err)
	}
}

func TestCanceledCoordinationDoesNotLockOrMutate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := validGateKey()
	tx := &recordedCoordinationTx{rows: 1, gate: GateSnapshot{Key: key, State: GateIdle, Generation: 4, RowVersion: 10}}
	if _, err := BeginGateAcquisition(ctx, tx, key, "controller:pod-1", 10, validGatePolicy()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled gate error = %v", err)
	}
	request := MutationLeaseRequest{LeaseID: "11111111-1111-4111-8111-111111111111", Key: key, OperationIdentity: "update.instance", RequestID: "request:1", Owner: "api:pod-1", ExpectedGeneration: 4}
	if _, err := AcquireMutationLease(ctx, tx, request, validMutationPolicy()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled mutation error = %v", err)
	}
	if len(tx.order) != 0 || len(tx.queries) != 0 {
		t.Fatalf("canceled coordination touched persistence: order=%#v queries=%#v", tx.order, tx.queries)
	}
}
