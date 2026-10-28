package systembackupread

import (
	"context"
	"regexp"
	"time"
)

// ControlHealthSnapshot is the D-owned contribution from the candidate health
// store, not a complete OverviewResource. Missing rows/schemas/adapters fail
// unavailable instead of being relabeled unknown or healthy.
type ControlHealthSnapshot struct {
	controller, database string
	checkedAt, expiresAt time.Time
}

func (ControlHealthSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (h ControlHealthSnapshot) ControllerHealth() string   { return h.controller }
func (h ControlHealthSnapshot) DatabaseHealth() string     { return h.database }
func (h ControlHealthSnapshot) CheckedAt() time.Time       { return h.checkedAt }

var healthWriterOwner = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

const controlHealthSQL = `SELECT h.schema_version,h.origin_installation_id,h.config_version,h.writer_epoch,h.writer_owner,
h.observation_sequence,h.controller_health,h.database_health,h.observed_at,h.expires_at,c.controller_reconcile_interval_seconds
FROM system_backup_v2_control_health h JOIN system_backup_v2_configs c
ON c.origin_installation_id=h.origin_installation_id AND c.version=h.config_version
WHERE h.origin_installation_id=?`

func readControlHealth(ctx context.Context, q overviewReadSQL, state OverviewInstallationState) (ControlHealthSnapshot, error) {
	var zero ControlHealthSnapshot
	var schema, installation, owner, controller, database string
	var config, epoch, sequence, interval uint64
	var checked, expiry time.Time
	if err := q.QueryRowContext(ctx, controlHealthSQL, state.InstallationID).Scan(&schema, &installation, &config, &epoch, &owner,
		&sequence, &controller, &database, &checked, &expiry, &interval); err != nil {
		return zero, ErrUnavailable
	}
	if schema != "system-backup-control-health.v1" || installation != state.InstallationID || config != state.ConfigVersion ||
		epoch == 0 || epoch > maxJSONSafeInteger || sequence > maxJSONSafeInteger || !healthWriterOwner.MatchString(owner) ||
		interval < 1 || interval > 60 || checked.IsZero() || checked.After(state.ObservedAt) ||
		expiry.Sub(checked) != time.Duration(3*interval)*time.Second {
		return zero, ErrUnavailable
	}
	if sequence == 0 {
		if controller != "unknown" || database != "unknown" {
			return zero, ErrUnavailable
		}
	} else if (controller != "healthy" && controller != "degraded") || (database != "healthy" && database != "degraded") {
		return zero, ErrUnavailable
	}
	if !state.ObservedAt.Before(expiry) {
		controller, database = "stale", "stale"
	}
	return ControlHealthSnapshot{controller: controller, database: database, checkedAt: checked.UTC(), expiresAt: expiry.UTC()}, nil
}

// This read uses the same installation/config lock, repeatable-read snapshot,
// current A authorization and confirmed commit as future overview composition.
// Production HTTP remains unavailable until all other Owner facts exist.
func (r *Reader) ReadControlHealth(ctx context.Context) (ControlHealthSnapshot, error) {
	return readOverviewInTransaction(ctx, r, func(ctx context.Context, q overviewReadSQL, control OverviewControlSnapshot) (ControlHealthSnapshot, error) {
		return readControlHealth(ctx, q, control.state)
	})
}
