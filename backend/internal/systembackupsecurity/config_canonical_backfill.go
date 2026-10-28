package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

var errConfigMaintenanceCommitUnknown = errors.New("config_maintenance_commit_unknown")

// Private candidate boundaries, not a grant/issuer protocol. Deployment must
// independently authenticate the stable actor, exact purpose-specific grant,
// original archive and reviewed schema/catalog/migration pins. Admission and
// Recheck use local/SQL work only and MUST NOT commit the supplied transaction.
// Observation is a separate CURRENT permission for the ORIGINAL request,
// including after its write grant expires or is revoked.
type configMaintenanceAuthority interface {
	AuthorizeWrite(context.Context, *sql.Tx, configMaintenanceScope, []byte, time.Time) (configMaintenanceAdmission, error)
	AuthorizeObservation(context.Context, *sql.Tx, configMaintenanceScope, []byte, time.Time) (configMaintenanceAdmission, error)
	Reserve(context.Context, *sql.Tx, configMaintenanceScope, configMaintenanceBudget, time.Time) (ConfigMutationCapacityReservation, error)
}

type configMaintenanceAdmission interface {
	Recheck(context.Context, *sql.Tx, time.Time) error
	ValidUntil() time.Time
}

// Known payload bounds only. The mandatory deployment reservation must ALSO
// account for actual physical row/index/audit overhead, existing allocation,
// concurrent reservations and installation-lifetime receipt/audit retention.
// These lengths are not a physical-capacity estimate or a source attestation.
type configMaintenanceBudget struct {
	canonicalWriteBytes, receiptMaxBytes, intentBytes, resultBytes int
}

type configCanonicalBackfillService struct {
	db                  *sql.DB
	database            DatabaseIdentity
	installation, actor string
	authority           configMaintenanceAuthority
}

type configMaintenanceResult struct {
	canonical []byte
	replayed  bool
}

func (configMaintenanceResult) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
func (r configMaintenanceResult) bytes() []byte              { return append([]byte(nil), r.canonical...) }

// No production constructor, HTTP handler, grant loader or default authority.
// The service remains private until its deployment adapters are reviewed.
func newConfigCanonicalBackfillService(db *sql.DB, database DatabaseIdentity, installation, actor string, authority configMaintenanceAuthority) (*configCanonicalBackfillService, error) {
	if db == nil || !database.valid() || !configMutationInstallation.MatchString(installation) || !providerHashPattern.MatchString(actor) || nilConfigMutationBoundary(authority) {
		return nil, ErrRegistrationUnavailable
	}
	return &configCanonicalBackfillService{db: db, database: database, installation: installation, actor: actor, authority: authority}, nil
}

func cloneConfigMaintenanceScope(s configMaintenanceScope) configMaintenanceScope {
	s.canonical = append([]byte(nil), s.canonical...)
	return s
}

func configMaintenanceClock(ctx context.Context, tx *sql.Tx, database DatabaseIdentity, notBefore time.Time) (time.Time, error) {
	var server, name string
	var now time.Time
	var offset int64
	if ctx == nil || ctx.Err() != nil || tx == nil || !database.valid() || tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &name, &now, &offset) != nil || server != database.ServerUUID || name != database.Database || offset != 0 || !configMaintenanceSQLTime(now) || now.Before(notBefore) || ctx.Err() != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return now, nil
}

func configMaintenanceAdmissionUntil(admission configMaintenanceAdmission, now time.Time) (time.Time, error) {
	if nilConfigMutationBoundary(admission) {
		return time.Time{}, ErrRegistrationPermission
	}
	until := admission.ValidUntil() // Freeze once; never adopt a later extension.
	if until.IsZero() || !now.Before(until) {
		return time.Time{}, ErrRegistrationPermission
	}
	return until, nil
}

func (s *configCanonicalBackfillService) begin(ctx context.Context, key string, raw, original []byte) (*sql.Tx, configMaintenanceScope, []byte, time.Time, error) {
	zero := configMaintenanceScope{}
	if s == nil || s.db == nil || nilConfigMutationBoundary(s.authority) || ctx == nil || ctx.Err() != nil {
		return nil, zero, nil, time.Time{}, ErrRegistrationUnavailable
	}
	if len(raw) < 2 || len(raw) > 262144 || len(original) < 2 || len(original) > 262144 {
		return nil, zero, nil, time.Time{}, ErrConfigMutation
	}
	// Before ALL authentication, source, SQL and capacity callbacks.
	request, source := append([]byte(nil), raw...), append([]byte(nil), original...)
	scope, err := newConfigMaintenanceScope(s.database, s.installation, s.actor, key, request)
	if err != nil || len(source) < 2 || len(source) > 262144 || int64(len(source)) != scope.identity.ConfigSize || registrationHash(string(source)) != scope.identity.ConfigSHA {
		return nil, zero, nil, time.Time{}, ErrConfigMutation
	}
	values, err := DecodeConfigValues(source)
	if err != nil || !bytes.Equal(values.CanonicalJSON(), source) {
		return nil, zero, nil, time.Time{}, ErrConfigMutation
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, zero, nil, time.Time{}, ErrRegistrationUnavailable
	}
	now, err := configMaintenanceClock(ctx, tx, s.database, time.Time{})
	if err != nil {
		_ = tx.Rollback()
		return nil, zero, nil, time.Time{}, err
	}
	return tx, scope, source, now, nil
}

// Final capacity and grant/source checks precede pure SQL snapshot validation.
// A fresh target/UTC sample follows every callback. No authority/provider work
// is allowed after that observation and before commit.
func (s *configCanonicalBackfillService) finish(ctx context.Context, tx *sql.Tx, admission configMaintenanceAdmission, until time.Time, reservation ConfigMutationCapacityReservation, capacityUntil time.Time, receipt *configMaintenanceReceiptSnapshot, notBefore time.Time) error {
	now, err := configMaintenanceClock(ctx, tx, s.database, notBefore)
	if err != nil {
		return err
	}
	if !now.Before(until) {
		return ErrRegistrationPermission
	}
	if !nilConfigMutationBoundary(reservation) {
		if !now.Before(capacityUntil) {
			return ErrRegistrationUnavailable
		}
		if err := reservation.Recheck(ctx, tx, now); err != nil {
			return registrationBoundaryError(err)
		}
	}
	if err := admission.Recheck(ctx, tx, now); err != nil {
		return registrationBoundaryError(err)
	}
	if receipt != nil {
		observedAt, err := receipt.recheckAt(ctx, tx)
		if err != nil {
			return err
		}
		if observedAt.After(now) {
			now = observedAt
		}
	}
	last, err := configMaintenanceClock(ctx, tx, s.database, now)
	if err != nil {
		return err
	}
	if !last.Before(until) {
		return ErrRegistrationPermission
	}
	if !nilConfigMutationBoundary(reservation) && !last.Before(capacityUntil) {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (s *configCanonicalBackfillService) commit(ctx context.Context, tx *sql.Tx, receipt configMaintenanceReceiptSnapshot, replayed bool) (configMaintenanceResult, error) {
	if ctx.Err() != nil {
		return configMaintenanceResult{}, ErrRegistrationUnavailable
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		// No automatic retry, new audit or speculative result after ambiguity.
		return configMaintenanceResult{}, errConfigMaintenanceCommitUnknown
	}
	return configMaintenanceResult{canonical: receipt.bytes(), replayed: replayed}, nil
}

// apply is an explicitly requested write attempt. Replay additionally requires
// current observation admission. A caller with ONLY observation authority uses
// observe instead; no write-grant fallback or automatic retry is performed.
func (s *configCanonicalBackfillService) apply(ctx context.Context, key string, raw, original []byte) (configMaintenanceResult, error) {
	zero := configMaintenanceResult{}
	tx, scope, source, now, err := s.begin(ctx, key, raw, original)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	admission, err := s.authority.AuthorizeWrite(ctx, tx, cloneConfigMaintenanceScope(scope), append([]byte(nil), source...), now)
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	until, err := configMaintenanceAdmissionUntil(admission, now)
	if err != nil {
		return zero, err
	}
	row, err := readLockedConfigBackfillRow(ctx, tx, s.database, s.installation, scope.identity.Version, source)
	if err != nil {
		return zero, err
	}
	existing, err := loadConfigMaintenanceReceipt(ctx, tx, scope, row)
	if err == nil {
		return s.observeExisting(ctx, tx, scope, source, existing)
	}
	if !errors.Is(err, errConfigMaintenanceReceiptMissing) {
		return zero, err
	}
	var absence configMaintenanceReceiptAbsence
	if !errors.As(err, &absence) || absence.observedAt.Before(row.observedAt) {
		return zero, ErrRegistrationUnavailable
	}
	row.observedAt = absence.observedAt
	wrote := row.canonical == configBackfillCanonicalNull
	receiptID, err := registrationID("")
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	intent, err := canonicalConfigMaintenanceAudit(scope, receiptID, receiptID, "intent", wrote)
	if err != nil {
		return zero, err
	}
	result, err := canonicalConfigMaintenanceAudit(scope, receiptID, receiptID, "result", wrote)
	if err != nil {
		return zero, err
	}
	// Actual audit IDs are returned by INSERT. Reserve against the maximum
	// legal ID widths without inventing an ID or querying MAX(id).
	maxReceipt, err := canonicalConfigMaintenanceReceipt(configMaintenanceReceiptPolicy{scope: scope, receiptID: receiptID, requestID: receiptID, wrote: wrote, intentID: 2147483646, resultID: 2147483647, createdAt: row.observedAt})
	if err != nil {
		return zero, err
	}
	budget := configMaintenanceBudget{receiptMaxBytes: len(maxReceipt), intentBytes: len(intent), resultBytes: len(result)}
	if wrote {
		budget.canonicalWriteBytes = len(source)
	}
	reservation, err := s.authority.Reserve(ctx, tx, cloneConfigMaintenanceScope(scope), budget, row.observedAt)
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	if nilConfigMutationBoundary(reservation) {
		return zero, ErrRegistrationUnavailable
	}
	capacityUntil := reservation.ValidUntil()
	if !row.observedAt.Before(capacityUntil) {
		return zero, ErrRegistrationUnavailable
	}
	if err := recheckLockedConfigBackfillRow(ctx, tx, row); err != nil {
		return zero, err
	}
	audit := func(phase string, body []byte) (int64, error) {
		// Published 001 stores audit_logs.created_at as TIMESTAMP(0).
		// Supply a whole-second value; fractional input can round into the next
		// second and incorrectly appear later than the microsecond receipt.
		r, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,resource_id,details,created_at) VALUES(NULL,?,'system_backup',NULL,?,UTC_TIMESTAMP())", "system_backup.config_canonical_backfill."+phase, string(body))
		if !configMutationOne(r, err) {
			return 0, ErrProviderEvidenceStorage
		}
		id, err := r.LastInsertId()
		if err != nil || id < 1 || id > 2147483647 {
			return 0, ErrProviderEvidenceStorage
		}
		return id, nil
	}
	intentID, err := audit("intent", intent)
	if err != nil {
		return zero, err
	}
	if wrote {
		r, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_configs SET canonical_config_json=? WHERE id=? AND origin_installation_id=? AND version=? AND canonical_config_json IS NULL AND config_sha256=? AND config_size_bytes=?", append([]byte(nil), source...), row.rowID, s.installation, scope.identity.Version, scope.identity.ConfigSHA, scope.identity.ConfigSize)
		if !configMutationOne(r, err) {
			return zero, ErrProviderEvidenceStorage
		}
	}
	resultID, err := audit("result", result)
	if err != nil {
		return zero, err
	}
	receipt, err := stageConfigMaintenanceReceipt(ctx, tx, scope, row, receiptID, receiptID, intentID, resultID)
	if err != nil {
		return zero, err
	}
	if len(receipt.raw) > budget.receiptMaxBytes {
		return zero, ErrRegistrationUnavailable
	}
	if err := s.finish(ctx, tx, admission, until, reservation, capacityUntil, &receipt, receipt.observedAt); err != nil {
		return zero, err
	}
	return s.commit(ctx, tx, receipt, false)
}

func (s *configCanonicalBackfillService) observeExisting(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, source []byte, receipt configMaintenanceReceiptSnapshot) (configMaintenanceResult, error) {
	zero := configMaintenanceResult{}
	admission, err := s.authority.AuthorizeObservation(ctx, tx, cloneConfigMaintenanceScope(scope), append([]byte(nil), source...), receipt.observedAt)
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	until, err := configMaintenanceAdmissionUntil(admission, receipt.observedAt)
	if err != nil {
		return zero, err
	}
	if err := s.finish(ctx, tx, admission, until, nil, time.Time{}, &receipt, receipt.observedAt); err != nil {
		return zero, err
	}
	return s.commit(ctx, tx, receipt, true)
}

// Independent observation never INSERTs, UPDATEs or reserves write capacity.
// Missing means the caller may decide on a NEW authorized attempt; it is not a
// license for this method to retry a mutation after an uncertain COMMIT.
func (s *configCanonicalBackfillService) observe(ctx context.Context, key string, raw, original []byte) (configMaintenanceResult, error) {
	zero := configMaintenanceResult{}
	tx, scope, source, now, err := s.begin(ctx, key, raw, original)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	admission, err := s.authority.AuthorizeObservation(ctx, tx, cloneConfigMaintenanceScope(scope), append([]byte(nil), source...), now)
	if err != nil {
		return zero, registrationBoundaryError(err)
	}
	until, err := configMaintenanceAdmissionUntil(admission, now)
	if err != nil {
		return zero, err
	}
	row, err := readLockedConfigBackfillRow(ctx, tx, s.database, s.installation, scope.identity.Version, source)
	if err != nil {
		return zero, err
	}
	receipt, err := loadConfigMaintenanceReceipt(ctx, tx, scope, row)
	if err != nil && !errors.Is(err, errConfigMaintenanceReceiptMissing) {
		return zero, err
	}
	var snapshot *configMaintenanceReceiptSnapshot
	if err == nil {
		snapshot = &receipt
	} else {
		var absence configMaintenanceReceiptAbsence
		if !errors.As(err, &absence) || absence.observedAt.Before(row.observedAt) {
			return zero, ErrRegistrationUnavailable
		}
		row.observedAt = absence.observedAt
	}
	if finalErr := s.finish(ctx, tx, admission, until, nil, time.Time{}, snapshot, row.observedAt); finalErr != nil {
		return zero, finalErr
	}
	if err != nil {
		return zero, err
	}
	return s.commit(ctx, tx, receipt, true)
}
