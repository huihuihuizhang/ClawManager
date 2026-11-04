package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"time"

	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
)

// Explicit issuer comparison for the original/new Forward pairing. The key
// must come from the independently pinned deployment core, never either grant.
func (p *PinnedExecutionIdentity) CheckDeploymentInViewWithIssuer(ctx context.Context, view reg.SQLReadView, public ed25519.PublicKey) error {
	if p == nil || len(public) != ed25519.PublicKeySize || !bytes.Equal(p.public, public) {
		return ErrExecutionAuthority
	}
	return p.CheckDeploymentInView(ctx, view)
}

// CheckDeploymentInView is the same original workload/file/key/time check as
// CheckDeployment, using the caller's actual SQL view. It grants no task,
// config inheritance or native readiness, and never opens another connection.
func (p *PinnedExecutionIdentity) CheckDeploymentInView(ctx context.Context, view reg.SQLReadView) error {
	if p == nil || ctx == nil || ctx.Err() != nil || view == nil {
		return ErrExecutionAuthority
	}
	value := reflect.ValueOf(view)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil() {
		return ErrExecutionAuthority
	}
	var now time.Time
	var account, server, database string
	if view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&now, &account, &server, &database) != nil {
		return ErrExecutionAuthority
	}
	a := d.Authority{InstallationID: p.grant.InstallationID, ClaimOwner: p.grant.ControllerOwner, ConfigVersion: p.grant.ConfigVersion, ConfigSHA256: p.grant.ConfigSHA256}
	if p.current(a, now) != nil || account != p.grant.DatabaseAccount || server != p.grant.ServerUUID || database != p.grant.Database {
		return ErrExecutionAuthority
	}
	for _, key := range append(append([]ExecutionRecordKey(nil), p.grant.RecordKeys...), p.grant.CaptureKeys...) {
		raw, err := readExecutionFile(filepath.Join(p.keyDirectory, key.Ref), 32)
		valid := err == nil && len(raw) == 32 && recordHash(raw) == key.SHA256
		clear(raw)
		if !valid {
			return ErrExecutionAuthority
		}
	}
	var after time.Time
	if view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&after) != nil || after.Before(now) || p.current(a, after) != nil || ctx.Err() != nil {
		return ErrExecutionAuthority
	}
	return nil
}
