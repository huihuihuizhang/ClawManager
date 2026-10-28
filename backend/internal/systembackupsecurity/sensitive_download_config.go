package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"time"
)

// SensitiveDownloadConfig is the exact current canonical/materialized L1
// snapshot, not a caller's config or a write grant. Missing canonical schema or
// bytes fails closed. It is local to the original transaction and nonce scope.
type SensitiveDownloadConfig struct {
	scope *SensitiveDownloadNonceScope
	row   configMutationRow
}

func (*SensitiveDownloadConfig) MarshalJSON() ([]byte, error) { return nil, ErrRegistrationUnavailable }
func (*SensitiveDownloadConfig) String() string               { return "SensitiveDownloadConfig" }
func (*SensitiveDownloadConfig) GoString() string             { return "SensitiveDownloadConfig" }
func (c *SensitiveDownloadConfig) Values() ConfigValues {
	if c == nil {
		return ConfigValues{}
	}
	return c.row.values
}
func (c *SensitiveDownloadConfig) Version() int64 {
	if c == nil {
		return 0
	}
	return c.row.version
}
func (c *SensitiveDownloadConfig) InstallationID() string {
	if c == nil || c.scope == nil {
		return ""
	}
	return c.scope.installation
}

// ObservedAt is the latest SQL sample known to this original locked scope; it
// is a monotonic floor, not an authority or a way to refresh config deadlines.
func (c *SensitiveDownloadConfig) ObservedAt() time.Time {
	if c == nil || c.scope == nil || c.scope.state == nil {
		return time.Time{}
	}
	s := c.scope
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.failed {
		return time.Time{}
	}
	if s.state.lastObserved.After(s.observedAt) {
		return s.state.lastObserved
	}
	return s.observedAt
}
func (c *SensitiveDownloadConfig) MaxAge() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.row.values.snapshot.numbers["strong_auth_max_age_seconds"]) * time.Second
}
func (c *SensitiveDownloadConfig) ClockSkew() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.row.values.snapshot.numbers["strong_auth_clock_skew_seconds"]) * time.Second
}
func (c *SensitiveDownloadConfig) ControlRetention() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.row.values.snapshot.numbers["control_metadata_retention_seconds"]) * time.Second
}

// LoadConfig must run in L1, before identity/operation/owner locks. It verifies
// every materialized config cell against independently decoded canonical bytes.
func (s *SensitiveDownloadNonceScope) LoadConfig(ctx context.Context, tx *sql.Tx) (*SensitiveDownloadConfig, error) {
	if s == nil || s.state == nil {
		return nil, ErrRegistrationUnavailable
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.failed || s.state.candidatesLocked {
		return nil, ErrRegistrationUnavailable
	}
	s.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != s.tx {
		return nil, ErrRegistrationUnavailable
	}
	row, err := readConfigMutationRow(ctx, tx, s.installation, s.configVersion)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	active := ""
	for _, r := range row.values.References() {
		if r.Purpose == "nonce_hmac" {
			active = r.Version
		}
	}
	if active != s.active {
		return nil, ErrRegistrationUnavailable
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, s.observedAt)
	if err != nil {
		return nil, err
	}
	s.state.lastObserved, s.state.failed = now, false
	return &SensitiveDownloadConfig{scope: s, row: row}, nil
}

// Recheck touches only the original held installation/config rows and frozen
// history set. Callback changes cannot refresh or replace the original config.
func (c *SensitiveDownloadConfig) Recheck(ctx context.Context, tx *sql.Tx) error {
	if c == nil || c.scope == nil || c.scope.state == nil {
		return ErrRegistrationUnavailable
	}
	s := c.scope
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.failed {
		return ErrRegistrationUnavailable
	}
	s.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != s.tx {
		return ErrRegistrationUnavailable
	}
	var version int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.installation).Scan(&version) != nil || version != c.row.version {
		return ErrRegistrationUnavailable
	}
	row, err := readConfigMutationRow(ctx, tx, s.installation, version)
	if err != nil || row.rowVersion != c.row.rowVersion || row.values.SHA256() != c.row.values.SHA256() || !bytes.Equal(row.values.CanonicalJSON(), c.row.values.CanonicalJSON()) {
		return ErrRegistrationUnavailable
	}
	versions, err := retainedNonceVersions(ctx, tx, s.active, s.observedAt)
	if err != nil || len(versions) != len(s.versions) {
		return ErrRegistrationUnavailable
	}
	for i, v := range versions {
		if v != s.versions[i] {
			return ErrRegistrationUnavailable
		}
	}
	floor := s.observedAt
	if s.state.lastObserved.After(floor) {
		floor = s.state.lastObserved
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, floor)
	if err != nil {
		return err
	}
	s.state.lastObserved, s.state.failed = now, false
	return nil
}
