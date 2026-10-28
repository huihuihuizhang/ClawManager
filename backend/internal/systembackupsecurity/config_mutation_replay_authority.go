package systembackupsecurity

import (
	"context"
	"database/sql"
	"path/filepath"
	"time"
)

// SQLConfigMutationReplayAuthorizer composes the actual credential-bound SQL
// session/revocation checker, full canonical/materialized current config and
// exact file-backed RBAC registry. It issues no provider/KEK capability and
// neither commits, refreshes sessions, consumes proof nor writes an audit.
type SQLConfigMutationReplayAuthorizer struct {
	installation string
	database     DatabaseIdentity
	sessions     *SQLLoginSessions
	files        RegistrationFiles
}

func NewSQLConfigMutationReplayAuthorizer(installation string, database DatabaseIdentity, sessions *SQLLoginSessions, registryDirectory string) (*SQLConfigMutationReplayAuthorizer, error) {
	if !configMutationInstallation.MatchString(installation) || !database.valid() || sessions == nil || sessions.db == nil || sessions.installation != installation || sessions.identity != database || !filepath.IsAbs(registryDirectory) {
		return nil, ErrRegistrationUnavailable
	}
	return &SQLConfigMutationReplayAuthorizer{installation, database, sessions, RegistrationFiles{RegistryDirectory: filepath.Clean(registryDirectory)}}, nil
}

// AuthorizeReplay follows the writer's installation/config/user/receipt lock
// order in the CALLER transaction. Original immutable risk comes from the
// uniquely matching SQL audit intent, never the response body or HTTP flags.
// Current config and session are checked each time, including after rotation.
func (a *SQLConfigMutationReplayAuthorizer) AuthorizeReplay(ctx context.Context, tx *sql.Tx, input ConfigMutationResponseReplayPreparation, notBefore time.Time) error {
	f := input.Facts()
	if a == nil || ctx == nil || ctx.Err() != nil || tx == nil || a.sessions == nil || f.Installation != a.installation || f.Database != a.database || notBefore.Before(f.AuthorizedAt) || !notBefore.Before(f.ValidUntil) {
		return ErrRegistrationUnavailable
	}
	if _, err := NewConfigMutationResponseReplayPreparation(f); err != nil {
		return ErrRegistrationUnavailable
	}
	if a.database.check(ctx, tx) != nil {
		return ErrRegistrationUnavailable
	}
	if err := lockRegistrationInstallations(ctx, tx); err != nil {
		return registrationBoundaryError(err)
	}
	var version, rowVersion int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version,row_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", a.installation).Scan(&version, &rowVersion) != nil || rowVersion < 1 || rowVersion >= 9007199254740991 {
		return ErrRegistrationUnavailable
	}
	current, err := readConfigMutationRow(ctx, tx, a.installation, version)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if err = a.sessions.CheckConfigMutationSession(ctx, tx, a.installation, f.Actor, notBefore); err != nil {
		return registrationBoundaryError(err)
	}
	pin := configMutationRBACPin(current.values)
	raw, err := a.files.RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer wipeSecret(raw)
	// Require configure before exposing or accepting an idempotency result.
	if _, err = VerifyConfigMutationRBAC(a.installation, f.Actor, current.values, current.values, raw, raw, ConfigMutationRisk{}); err != nil {
		return registrationBoundaryError(err)
	}
	scope := ConfigMutationService{InstallationID: a.installation}
	p, err := scope.lookup(ctx, tx, f.Actor, ConfigMutationRequest{endpoint: f.Endpoint}, f.IdempotencyKey, f.RequestHash)
	if err != nil {
		return registrationBoundaryError(err)
	}
	if p == nil || p.publicID != f.Operation || p.version != f.Version || p.evidenceID != f.EvidenceID || p.responseHash != f.ResponseHash {
		return ErrRegistrationUnavailable
	}
	if _, err = VerifyConfigMutationRBAC(a.installation, f.Actor, current.values, current.values, raw, raw, p.risk); err != nil {
		return registrationBoundaryError(err)
	}
	now, err := configMutationClock(ctx, tx)
	if err != nil || now.Before(notBefore) || now.Before(f.AuthorizedAt) || !now.Before(f.ValidUntil) || ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	if !configMutationSessionAt(f.Actor, now) {
		return ErrRegistrationPermission
	}
	return nil
}
