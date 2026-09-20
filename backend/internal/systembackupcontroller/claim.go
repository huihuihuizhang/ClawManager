// Package systembackupcontroller contains D-owned controller coordination
// primitives. It deliberately has no runner, Kubernetes Job, provider,
// catalog, credential, or owner-verifier implementation.
package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	MinClaimTTL          = 15 * time.Second
	DefaultClaimTTL      = 30 * time.Second
	MaxClaimTTL          = 300 * time.Second
	MinHeartbeatInterval = 5 * time.Second
	DefaultHeartbeat     = 10 * time.Second
	MinReconcileInterval = time.Second
	DefaultReconcile     = 10 * time.Second
	MaxReconcileInterval = 60 * time.Second
)

var controllerOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

var (
	ErrClaimNotAcquired = errors.New("system backup claim not acquired")
	ErrClaimLost        = errors.New("system backup claim lost")
)

// LeasePolicy mirrors the closed v12 controller claim ranges. The heartbeat
// must be no greater than one third of the TTL so a healthy controller has at
// least two renewal opportunities before expiry.
type LeasePolicy struct {
	TTL               time.Duration
	HeartbeatInterval time.Duration
	ReconcileInterval time.Duration
}

func (p LeasePolicy) Validate() error {
	if p.TTL < MinClaimTTL || p.TTL > MaxClaimTTL {
		return fmt.Errorf("claim TTL must be between %s and %s", MinClaimTTL, MaxClaimTTL)
	}
	if p.HeartbeatInterval < MinHeartbeatInterval || p.HeartbeatInterval > p.TTL/3 {
		return fmt.Errorf("claim heartbeat must be between %s and TTL/3", MinHeartbeatInterval)
	}
	if p.ReconcileInterval < MinReconcileInterval || p.ReconcileInterval > MaxReconcileInterval {
		return fmt.Errorf("reconcile interval must be between %s and %s", MinReconcileInterval, MaxReconcileInterval)
	}
	return nil
}

type TargetKind string

const (
	TargetBackup         TargetKind = "backup"
	TargetDrill          TargetKind = "drill"
	TargetPreflight      TargetKind = "preflight"
	TargetArtifactVerify TargetKind = "artifact_verify"
	TargetOperation      TargetKind = "operation"
)

type targetDescriptor struct {
	table       string
	ownerColumn string
	leaseColumn string
	heartbeat   string
	activeSQL   string
	idPrefix    string
}

var targetDescriptors = map[TargetKind]targetDescriptor{
	TargetBackup: {
		table:       "system_backups",
		ownerColumn: "controller_owner",
		leaseColumn: "controller_lease_expires_at",
		heartbeat:   "heartbeat_at",
		activeSQL:   "status IN ('pending','preparing','ready_for_capture','acquiring_gate','capturing','validating','publishing','finalization_unknown','canceling')",
		idPrefix:    "sbk_",
	},
	TargetDrill: {
		table:       "system_restore_drills",
		ownerColumn: "controller_owner",
		leaseColumn: "controller_lease_expires_at",
		heartbeat:   "heartbeat_at",
		activeSQL:   "status IN ('pending','preflighting','provisioning','restoring','normalizing','verifying','canceling')",
		idPrefix:    "sdr_",
	},
	TargetPreflight: {
		table:       "system_backup_preflights",
		ownerColumn: "controller_owner",
		leaseColumn: "controller_lease_expires_at",
		heartbeat:   "heartbeat_at",
		activeSQL:   "status IN ('pending','running','canceling')",
		idPrefix:    "spf_",
	},
	TargetArtifactVerify: {
		table:       "system_backup_artifact_verifications",
		ownerColumn: "controller_owner",
		leaseColumn: "controller_lease_expires_at",
		heartbeat:   "heartbeat_at",
		activeSQL:   "status IN ('pending','running','canceling')",
		idPrefix:    "sav_",
	},
	TargetOperation: {
		table:       "system_backup_operations",
		ownerColumn: "claim_owner",
		leaseColumn: "claim_expires_at",
		heartbeat:   "",
		activeSQL:   "status IN ('pending','running')",
		idPrefix:    "sop_",
	},
}

// Target identifies an already-selected control-plane row. Candidate listing
// is intentionally outside this primitive; acquisition itself is always one
// conditional UPDATE and cannot be implemented as SELECT followed by an
// unconditional write.
type Target struct {
	Kind     TargetKind
	PublicID string
}

func (t Target) descriptor() (targetDescriptor, error) {
	descriptor, ok := targetDescriptors[t.Kind]
	if !ok {
		return targetDescriptor{}, fmt.Errorf("unsupported system backup target kind %q", t.Kind)
	}
	publicIDPattern := regexp.MustCompile("^" + regexp.QuoteMeta(descriptor.idPrefix) + `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if len(t.PublicID) != 40 || !strings.HasPrefix(t.PublicID, descriptor.idPrefix) || !publicIDPattern.MatchString(t.PublicID) {
		return targetDescriptor{}, fmt.Errorf("invalid %s public ID", t.Kind)
	}
	return descriptor, nil
}

// Executor is satisfied by *sql.DB, *sql.Conn, and *sql.Tx. A caller that
// already pinned a database connection can therefore keep claim coordination
// on that connection without this package owning connection lifecycle.
type Executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type ClaimToken struct {
	Target     Target
	Owner      string
	RowVersion uint64
}

func validateMutation(ctx context.Context, executor Executor, target Target, owner string, expectedRowVersion uint64) (targetDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return targetDescriptor{}, err
	}
	if executor == nil {
		return targetDescriptor{}, errors.New("nil system backup claim executor")
	}
	descriptor, err := target.descriptor()
	if err != nil {
		return targetDescriptor{}, err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return targetDescriptor{}, errors.New("invalid system backup controller owner")
	}
	if expectedRowVersion < 1 {
		return targetDescriptor{}, errors.New("expected row version must be at least 1")
	}
	return descriptor, nil
}

func intervalMicros(value time.Duration) (int64, error) {
	if value <= 0 || value%time.Microsecond != 0 {
		return 0, errors.New("database interval must be a positive whole number of microseconds")
	}
	return value.Microseconds(), nil
}

func heartbeatAssignment(descriptor targetDescriptor) string {
	if descriptor.heartbeat == "" {
		return ""
	}
	return ", " + descriptor.heartbeat + " = UTC_TIMESTAMP(6)"
}

// AcquireClaimInInstallation atomically acquires an unowned, self-owned, or
// expired row within one installation. All freshness decisions and lease
// timestamps use the database clock, never the process clock.
func AcquireClaimInInstallation(ctx context.Context, executor Executor, installationID string, target Target, owner string, expectedRowVersion uint64, policy LeasePolicy) (ClaimToken, error) {
	if !installationIDPattern.MatchString(installationID) {
		return ClaimToken{}, errors.New("invalid system backup claim installation ID")
	}
	if err := policy.Validate(); err != nil {
		return ClaimToken{}, err
	}
	descriptor, err := validateMutation(ctx, executor, target, owner, expectedRowVersion)
	if err != nil {
		return ClaimToken{}, err
	}
	ttlMicros, err := intervalMicros(policy.TTL)
	if err != nil {
		return ClaimToken{}, err
	}

	query := fmt.Sprintf(
		"UPDATE %s SET %s = ?, %s = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)%s, row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND %s AND (next_reconcile_at IS NULL OR next_reconcile_at <= UTC_TIMESTAMP(6)) AND (%s IS NULL OR %s = ? OR %s <= UTC_TIMESTAMP(6))",
		descriptor.table,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		heartbeatAssignment(descriptor),
		descriptor.activeSQL,
		descriptor.ownerColumn,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
	)
	result, err := executor.ExecContext(ctx, query, owner, ttlMicros, installationID, target.PublicID, expectedRowVersion, owner)
	if err != nil {
		return ClaimToken{}, fmt.Errorf("acquire %s claim: %w", target.Kind, err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return ClaimToken{}, err
	}
	if !matched {
		return ClaimToken{}, ErrClaimNotAcquired
	}
	return ClaimToken{Target: target, Owner: owner, RowVersion: expectedRowVersion + 1}, nil
}

// RenewClaimInInstallation refuses an expired, stolen or cross-installation
// lease. A zero-row CAS is surfaced as ErrClaimLost.
func RenewClaimInInstallation(ctx context.Context, executor Executor, installationID string, token ClaimToken, policy LeasePolicy) (ClaimToken, error) {
	if !installationIDPattern.MatchString(installationID) {
		return ClaimToken{}, errors.New("invalid system backup claim installation ID")
	}
	if err := policy.Validate(); err != nil {
		return ClaimToken{}, err
	}
	descriptor, err := validateMutation(ctx, executor, token.Target, token.Owner, token.RowVersion)
	if err != nil {
		return ClaimToken{}, err
	}
	ttlMicros, err := intervalMicros(policy.TTL)
	if err != nil {
		return ClaimToken{}, err
	}
	query := fmt.Sprintf(
		"UPDATE %s SET %s = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND)%s, row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND %s = ? AND %s > UTC_TIMESTAMP(6) AND %s",
		descriptor.table,
		descriptor.leaseColumn,
		heartbeatAssignment(descriptor),
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		descriptor.activeSQL,
	)
	result, err := executor.ExecContext(ctx, query, ttlMicros, installationID, token.Target.PublicID, token.RowVersion, token.Owner)
	if err != nil {
		return ClaimToken{}, fmt.Errorf("renew %s claim: %w", token.Target.Kind, err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return ClaimToken{}, err
	}
	if !matched {
		return ClaimToken{}, ErrClaimLost
	}
	token.RowVersion++
	return token, nil
}

// ReleaseClaimInInstallation clears only the caller's live lease within the
// named installation and schedules the row by database time. It does not
// mutate task status or invoke an owner component.
func ReleaseClaimInInstallation(ctx context.Context, executor Executor, installationID string, token ClaimToken, retryAfter time.Duration) (uint64, error) {
	if !installationIDPattern.MatchString(installationID) {
		return 0, errors.New("invalid system backup claim installation ID")
	}
	descriptor, err := validateMutation(ctx, executor, token.Target, token.Owner, token.RowVersion)
	if err != nil {
		return 0, err
	}
	retryMicros, err := intervalMicros(retryAfter)
	if err != nil {
		return 0, err
	}
	if retryAfter < MinReconcileInterval || retryAfter > MaxReconcileInterval {
		return 0, fmt.Errorf("claim retry delay must be between %s and %s", MinReconcileInterval, MaxReconcileInterval)
	}
	query := fmt.Sprintf(
		"UPDATE %s SET %s = NULL, %s = NULL, next_reconcile_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND), row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND %s = ? AND %s > UTC_TIMESTAMP(6) AND %s",
		descriptor.table,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		descriptor.ownerColumn,
		descriptor.leaseColumn,
		descriptor.activeSQL,
	)
	result, err := executor.ExecContext(ctx, query, retryMicros, installationID, token.Target.PublicID, token.RowVersion, token.Owner)
	if err != nil {
		return 0, fmt.Errorf("release %s claim: %w", token.Target.Kind, err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, ErrClaimLost
	}
	return token.RowVersion + 1, nil
}

func exactlyOneRow(result sql.Result) (bool, error) {
	if result == nil {
		return false, errors.New("system backup claim mutation returned a nil result")
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read system backup claim result: %w", err)
	}
	if rows > 1 {
		return false, fmt.Errorf("system backup claim mutation affected %d rows", rows)
	}
	return rows == 1, nil
}
