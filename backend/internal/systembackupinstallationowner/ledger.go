package systembackupinstallationowner

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"time"
)

type ledgerRead interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type ownerLedgerState struct {
	headRevision, headRow, grantRow uint64
	headHash                        string
}

// L2 only: caller already owns original installation/domain/admin prefix.
// No operation/config/evidence lock is acquired here. Revokers lock head then
// grant in the same order, and never lock producer/config/operation afterwards.
func readOwnerLedger(ctx context.Context, q ledgerRead, a *AuthenticatedRecord, now time.Time) (ownerLedgerState, error) {
	var out ownerLedgerState
	if ctx == nil || ctx.Err() != nil || a == nil || !validTime(now) {
		return out, ErrOwner
	}
	p, r := a.pin, a.record
	var username, role, provider string
	var active bool
	if q.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, r.Actor.UserID).Scan(&username, &role, &active, &provider) != nil || username != r.Actor.Username || role != "admin" || !active || provider != "local" {
		return out, ErrOwner
	}
	var headRaw, headSignature []byte
	var headHash, headState string
	var headRevision uint64
	if q.QueryRowContext(ctx, `SELECT head_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=? FOR SHARE`, p.InstallationID, p.EnrollmentID).Scan(&headRevision, &headHash, &headRaw, &headSignature, &headState, &out.headRow) != nil || headState != "active" || out.headRow == 0 || digest(headRaw) != headHash {
		return out, ErrOwner
	}
	h, e := verifyHead(headRaw, headSignature, p)
	if e != nil || h.Revision != headRevision || now.Before(h.NotBefore) || !now.Before(h.Until) {
		return out, ErrOwner
	}
	var raw, sig []byte
	var grantHash, state string
	if q.QueryRowContext(ctx, `SELECT record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_installation_owner_grants WHERE installation_id=? AND enrollment_id=? AND grant_id=? AND record_revision=? FOR SHARE`, p.InstallationID, p.EnrollmentID, p.GrantID, p.GrantRevision).Scan(&grantHash, &raw, &sig, &state, &out.grantRow) != nil || state != "active" || out.grantRow == 0 || grantHash != p.RecordSHA256 || !bytes.Equal(raw, a.raw) || !bytes.Equal(sig, a.signature) {
		return out, ErrOwner
	}
	if _, e = VerifyRecord(raw, sig, p); e != nil || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return out, ErrOwner
	}
	var account, server, database string
	if q.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`).Scan(&account, &server, &database) != nil || account != p.DatabaseAccount || server != p.ServerUUID || database != p.Database {
		return out, ErrOwner
	}
	out.headRevision, out.headHash = h.Revision, headHash
	return out, nil
}
func sameContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	return va.Comparable() && vb.Comparable() && !(va.Kind() == reflect.Pointer && va.IsNil()) && !(vb.Kind() == reflect.Pointer && vb.IsNil()) && a == b
}
