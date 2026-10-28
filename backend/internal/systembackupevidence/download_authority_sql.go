package systembackupevidence

import (
	"context"
	"time"

	"clawreef/internal/systembackupsecurity"
)

func (a *SQLDownloadAuthority) authorize(ctx context.Context) (grant downloadGrant, resultErr error) {
	deny := func() (downloadGrant, error) { return downloadGrant{}, ErrDenied }
	committed := committedDownloadFrom(ctx)
	defer func() {
		if committed != nil && resultErr != nil {
			committed.fail()
		}
	}()
	if a == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(a.c.ExpiresAt) || a.journal != nil && a.journal.Check() != nil || committed != nil && !committed.live(ctx, a) {
		return deny()
	}
	actor, ok := ctx.Value(a).(systembackupsecurity.RegistrationActor)
	if !ok || actor.UserID <= 0 || !time.Now().Before(actor.SessionExpiresAt) {
		return deny()
	}
	access, ok := ctx.Value(evidenceAccessKey{}).(evidenceAccess)
	if !ok || !idPattern.MatchString(access.ID) {
		return deny()
	}
	if _, ok = evidenceAccessFrom(ctx, "download", access.ID); !ok {
		return deny()
	}
	c, s := a.c, a.c.Registry
	// Load immutable hash-pinned bytes outside the SQL transaction. A config
	// change during this read is detected by the locked version/hash checks.
	raw, err := (systembackupsecurity.RegistrationFiles{RegistryDirectory: c.RegistryDirectory}).RegistryBytes("rbac_bindings", c.RBACVersion, c.RBACSHA256)
	if err != nil {
		return deny()
	}
	defer wipe(raw)
	tx, _, err := s.begin(ctx)
	if err != nil {
		return deny()
	}
	defer tx.Rollback()
	var originalConfig *systembackupsecurity.SensitiveDownloadConfig
	if committed != nil {
		originalConfig, err = committed.checkConfig(ctx, tx)
		if err != nil {
			return deny()
		}
	} else {
		rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
		if err != nil {
			return deny()
		}
		found, count := false, 0
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				rows.Close()
				return deny()
			}
			count++
			if count > 10000 {
				rows.Close()
				return deny()
			}
			found = found || id == s.Installation
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil || closeErr != nil || !found {
			return deny()
		}
		var version int64
		if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.Installation).Scan(&version) != nil || version != c.ConfigVersion {
			return deny()
		}
	}
	var configHash, rbacVersion, rbacHash string
	var store, read KeyRef
	if tx.QueryRowContext(ctx, `SELECT config_sha256,rbac_bindings_registry_version,rbac_bindings_registry_sha256,evidence_store_identity_hash,evidence_store_ref_version,evidence_read_identity_hash,evidence_read_ref_version
FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, s.Installation, c.ConfigVersion).Scan(&configHash, &rbacVersion, &rbacHash, &store.Identity, &store.Version, &read.Identity, &read.Version) != nil ||
		configHash != c.ConfigSHA256 || rbacVersion != c.RBACVersion || rbacHash != c.RBACSHA256 || store != c.Store || read != c.Read {
		return deny()
	}
	// Disabling scheduled backups does not revoke retained-evidence downloads.
	// Read permissions, session validity and current credential mappings still do.
	var sessionUntil time.Time
	if committed != nil {
		sessionUntil, err = committed.checkSession(ctx, tx)
	} else {
		sessionUntil, err = systembackupsecurity.CheckRegistrationSessionUntil(ctx, tx, s.Installation, actor)
	}
	if err != nil {
		return deny()
	}
	if committed != nil {
		if committed.checkOperationReceipt(ctx, tx) != nil {
			return deny()
		}
	}
	i := Identity{Installation: s.Installation, ID: access.ID}
	if committed != nil {
		i = committed.record.Manifest.Identity
	} else {
		if tx.QueryRowContext(ctx, "SELECT owner_target_type,owner_target_public_id FROM system_backup_v2_evidence WHERE public_id=?", access.ID).Scan(&i.OwnerType, &i.OwnerID) != nil {
			return deny()
		}
	}
	if s.Policy.LockScope(ctx, tx, s.Installation, i) != nil {
		return deny()
	}
	if committed != nil && (committed.checkNonce(ctx, tx) != nil || committed.checkIntent(ctx, tx) != nil || committed.checkOwner(ctx, tx) != nil) {
		return deny()
	}
	r, err := s.load(ctx, tx, access.ID)
	if err != nil || r.Manifest.Identity.OwnerType != i.OwnerType || r.Manifest.Identity.OwnerID != i.OwnerID || r.State != "ready" || !r.Ref.valid(true) ||
		r.Claim != access.Claim || r.RowVersion != access.RowVersion || r.Ref.Identity != c.Store.Identity || r.Ref.Version != c.Store.Version {
		return deny()
	}
	if committed != nil && !committed.sameCurrent(r) {
		return deny()
	}
	key, err := keyFor(c.Root, r.Manifest.Identity)
	if err != nil || key != r.Ref.RelativeKey {
		return deny()
	}
	required := permissions(r.Manifest.Identity.Classification)
	if systembackupsecurity.AuthorizeEvidencePermissions(raw, c.RBACSHA256, c.RBACVersion, s.Installation, actor, required) != nil || s.Policy.Authorize(ctx, tx, downloadActor(actor), r, required) != nil {
		return deny()
	}
	until := earlier(earlier(earlier(c.ExpiresAt, actor.SessionExpiresAt), sessionUntil), r.ClaimUntil)
	if committed != nil {
		until = earlier(until, earlier(committed.deadlineAt, committed.rows.nonceExpiresAt))
	}
	if r.Manifest.Identity.Type == "job_log_chunk" {
		until = earlier(until, r.ExpiresAt)
	}
	if committed != nil {
		currentSessionUntil, err := committed.checkSession(ctx, tx)
		if err != nil || committed.recheckOriginal(ctx, tx, s) != nil {
			return deny()
		}
		until = earlier(until, currentSessionUntil)
	}
	if originalConfig != nil && originalConfig.Recheck(ctx, tx) != nil {
		return deny()
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(until) || actor.SessionIssuedAt.IsZero() || actor.SessionIssuedAt.After(now) ||
		time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second || !time.Now().Before(until) || ctx.Err() != nil {
		return deny()
	}
	if committed != nil && (!downloadAdmissionContentTime(now) || now.Before(committed.admittedAt) || !committed.live(ctx, a)) {
		return deny()
	}
	principal := hash(canonical(struct {
		Installation string
		Actor        systembackupsecurity.RegistrationActor
	}{s.Installation, actor}))
	lease := hash(canonical(struct {
		Access                   evidenceAccess
		Manifest                 Manifest
		Ref                      Ref
		ClaimUntil, SessionUntil time.Time
		ConfigVersion            int64
		ConfigHash, RBACHash     string
	}{access, r.Manifest, r.Ref, r.ClaimUntil, sessionUntil, c.ConfigVersion, c.ConfigSHA256, c.RBACSHA256}))
	if committed != nil {
		lease = hash(canonical(struct{ Base, Operation, Request string }{lease, committed.operationID, committed.request.RequestHash()}))
	}
	if tx.Commit() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return deny()
	}
	if committed != nil && !committed.live(ctx, a) {
		return deny()
	}
	return downloadGrant{record: r, actor: downloadActor(actor), until: until, principal: principal, lease: lease}, nil
}
