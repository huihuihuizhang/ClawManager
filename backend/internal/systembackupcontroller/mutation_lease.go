package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	MinMutationLeaseTTL          = 6 * time.Second
	DefaultMutationLeaseTTL      = 30 * time.Second
	MaxMutationLeaseTTL          = 120 * time.Second
	MinMutationHeartbeatInterval = 2 * time.Second
	DefaultMutationHeartbeat     = 10 * time.Second
)

var (
	mutationLeaseIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	operationIdentityPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:-]{0,127}$`)
	requestIDPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

	ErrMutationLeaseRejected = errors.New("system backup mutation lease rejected")
	ErrMutationLeaseLost     = errors.New("system backup mutation lease lost")
)

type MutationLeasePolicy struct {
	TTL               time.Duration
	HeartbeatInterval time.Duration
}

func (p MutationLeasePolicy) Validate() error {
	if p.TTL%time.Second != 0 || p.HeartbeatInterval%time.Second != 0 {
		return errors.New("mutation lease durations must be whole seconds")
	}
	if p.TTL < MinMutationLeaseTTL || p.TTL > MaxMutationLeaseTTL {
		return fmt.Errorf("mutation lease TTL must be between %s and %s", MinMutationLeaseTTL, MaxMutationLeaseTTL)
	}
	if p.HeartbeatInterval < MinMutationHeartbeatInterval || p.HeartbeatInterval > p.TTL/3 {
		return fmt.Errorf("mutation lease heartbeat must be between %s and TTL/3", MinMutationHeartbeatInterval)
	}
	return nil
}

type MutationLeaseRequest struct {
	LeaseID            string
	Key                GateKey
	OperationIdentity  string
	RequestID          string
	Owner              string
	ExpectedGeneration uint64
}

func (r MutationLeaseRequest) validate() error {
	if err := r.Key.validate(); err != nil {
		return err
	}
	if !mutationLeaseIDPattern.MatchString(r.LeaseID) {
		return errors.New("invalid system backup mutation lease ID")
	}
	if !operationIdentityPattern.MatchString(r.OperationIdentity) {
		return errors.New("invalid system backup mutation operation identity")
	}
	if !requestIDPattern.MatchString(r.RequestID) {
		return errors.New("invalid system backup mutation request ID")
	}
	if !controllerOwnerPattern.MatchString(r.Owner) {
		return errors.New("invalid system backup mutation lease owner")
	}
	if r.ExpectedGeneration < 1 {
		return errors.New("expected gate generation must be at least 1")
	}
	return nil
}

type MutationLeaseToken struct {
	LeaseID    string
	Key        GateKey
	Owner      string
	Generation uint64
	RowVersion uint64
}

func (t MutationLeaseToken) validate() error {
	if !mutationLeaseIDPattern.MatchString(t.LeaseID) {
		return errors.New("invalid system backup mutation lease ID")
	}
	if err := t.Key.validate(); err != nil {
		return err
	}
	if !controllerOwnerPattern.MatchString(t.Owner) || t.Generation < 1 || t.RowVersion < 1 {
		return errors.New("invalid system backup mutation lease token")
	}
	return nil
}

func mutationLeaseMatches(snapshot MutationLeaseSnapshot, token MutationLeaseToken) bool {
	return snapshot.LeaseID == token.LeaseID && snapshot.Key == token.Key && snapshot.Owner == token.Owner && snapshot.Generation == token.Generation && snapshot.RowVersion == token.RowVersion
}

// AcquireMutationLease holds the gate row FOR UPDATE while it confirms
// idle+generation and inserts the lease. A concurrent controller acquisition
// must take the same row lock and therefore cannot pass between those steps.
func AcquireMutationLease(ctx context.Context, tx CoordinationTransaction, request MutationLeaseRequest, policy MutationLeasePolicy) (MutationLeaseToken, error) {
	if err := ctx.Err(); err != nil {
		return MutationLeaseToken{}, err
	}
	if tx == nil {
		return MutationLeaseToken{}, errors.New("nil system backup coordination transaction")
	}
	if err := request.validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	gate, err := tx.LockGate(ctx, request.Key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MutationLeaseToken{}, ErrMutationLeaseRejected
		}
		return MutationLeaseToken{}, err
	}
	if gate.State != GateIdle || gate.Owner != "" || gate.Generation != request.ExpectedGeneration {
		return MutationLeaseToken{}, ErrMutationLeaseRejected
	}
	result, err := tx.ExecContext(ctx,
		"INSERT INTO system_maintenance_mutation_leases (lease_id, origin_installation_id, scope, operation_identity, request_id, lease_owner, gate_generation, lease_ttl_seconds, heartbeat_at, expires_at, row_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), 1)",
		request.LeaseID, request.Key.InstallationID, request.Key.Scope, request.OperationIdentity, request.RequestID, request.Owner, request.ExpectedGeneration, gateSeconds(policy.TTL), gateSeconds(policy.TTL),
	)
	if err != nil {
		return MutationLeaseToken{}, fmt.Errorf("acquire system backup mutation lease: %w", err)
	}
	inserted, err := exactlyOneRow(result)
	if err != nil {
		return MutationLeaseToken{}, err
	}
	if !inserted {
		return MutationLeaseToken{}, ErrMutationLeaseRejected
	}
	if err := tx.Commit(); err != nil {
		return MutationLeaseToken{}, fmt.Errorf("commit system backup mutation lease: %w", err)
	}
	committed = true
	return MutationLeaseToken{LeaseID: request.LeaseID, Key: request.Key, Owner: request.Owner, Generation: request.ExpectedGeneration, RowVersion: 1}, nil
}

// ValidateMutationLeaseForCommit must run inside the same transaction as the
// caller's business write. It locks gate then lease and does not commit; the
// caller retains responsibility for its own business row and transaction.
func ValidateMutationLeaseForCommit(ctx context.Context, tx CoordinationTransaction, token MutationLeaseToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx == nil {
		return errors.New("nil system backup coordination transaction")
	}
	if err := token.validate(); err != nil {
		return err
	}
	gate, err := tx.LockGate(ctx, token.Key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMutationLeaseLost
		}
		return err
	}
	if gate.State != GateIdle || gate.Owner != "" || gate.Generation != token.Generation {
		return ErrMutationLeaseLost
	}
	lease, err := tx.LockMutationLease(ctx, token.LeaseID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMutationLeaseLost
		}
		return err
	}
	if !mutationLeaseMatches(lease, token) || !lease.Live {
		return ErrMutationLeaseLost
	}
	return nil
}

func RenewMutationLease(ctx context.Context, tx CoordinationTransaction, token MutationLeaseToken, policy MutationLeasePolicy) (MutationLeaseToken, error) {
	if err := ctx.Err(); err != nil {
		return MutationLeaseToken{}, err
	}
	if tx == nil {
		return MutationLeaseToken{}, errors.New("nil system backup coordination transaction")
	}
	if err := token.validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return MutationLeaseToken{}, err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)
	if err := ValidateMutationLeaseForCommit(ctx, tx, token); err != nil {
		return MutationLeaseToken{}, err
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE system_maintenance_mutation_leases SET lease_ttl_seconds = ?, heartbeat_at = UTC_TIMESTAMP(6), expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), row_version = row_version + 1 WHERE lease_id = ? AND origin_installation_id = ? AND scope = ? AND lease_owner = ? AND gate_generation = ? AND row_version = ? AND expires_at > UTC_TIMESTAMP(6)",
		gateSeconds(policy.TTL), gateSeconds(policy.TTL), token.LeaseID, token.Key.InstallationID, token.Key.Scope, token.Owner, token.Generation, token.RowVersion,
	)
	if err != nil {
		return MutationLeaseToken{}, fmt.Errorf("renew system backup mutation lease: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return MutationLeaseToken{}, err
	}
	if !matched {
		return MutationLeaseToken{}, ErrMutationLeaseLost
	}
	if err := tx.Commit(); err != nil {
		return MutationLeaseToken{}, fmt.Errorf("commit system backup mutation lease renewal: %w", err)
	}
	committed = true
	token.RowVersion++
	return token, nil
}

// ReleaseMutationLease also locks the gate first. Release is allowed while a
// gate is acquiring so an old-generation writer can actively prove it stopped;
// expiry alone never deletes the blocker row or authorizes held state.
func ReleaseMutationLease(ctx context.Context, tx CoordinationTransaction, token MutationLeaseToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx == nil {
		return errors.New("nil system backup coordination transaction")
	}
	if err := token.validate(); err != nil {
		return err
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)
	if _, err := tx.LockGate(ctx, token.Key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMutationLeaseLost
		}
		return err
	}
	lease, err := tx.LockMutationLease(ctx, token.LeaseID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMutationLeaseLost
		}
		return err
	}
	if !mutationLeaseMatches(lease, token) {
		return ErrMutationLeaseLost
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM system_maintenance_mutation_leases WHERE lease_id = ? AND origin_installation_id = ? AND scope = ? AND lease_owner = ? AND gate_generation = ? AND row_version = ?",
		token.LeaseID, token.Key.InstallationID, token.Key.Scope, token.Owner, token.Generation, token.RowVersion,
	)
	if err != nil {
		return fmt.Errorf("release system backup mutation lease: %w", err)
	}
	deleted, err := exactlyOneRow(result)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrMutationLeaseLost
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit system backup mutation lease release: %w", err)
	}
	committed = true
	return nil
}
