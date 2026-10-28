package control

import (
	"bytes"
	"context"
	_ "embed"

	"clawreef/internal/systembackup/recovery"
)

//go:embed upgrade-provider-gateway.sql
var GatewaySchema string

// GatewayDispatch uses a dedicated control DB; it does not depend on a source
// task row. Claims are permanent for the immutable root/key and action identity.
// There is intentionally no reset/delete/retry API or expiry-based reclamation.
type GatewayDispatch struct{ Store SQLStore }

func (j GatewayDispatch) Reserve(ctx context.Context, location recovery.Locator, r recovery.Request) (bool, error) {
	if location.Validate() != nil || r.Validate() != nil || r.Target.Validate() != nil {
		return false, ErrInvalid
	}
	b, e := recovery.Marshal(r)
	if e != nil {
		return false, ErrInvalid
	}
	scope, _ := recovery.Marshal([]any{r.Target, location})
	token, e := NewID()
	if e != nil {
		return false, e
	}
	tx, e := j.Store.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	n, e := now(ctx, tx)
	if e != nil || n >= r.Deadline {
		return false, ErrFence
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_gateway_dispatch(scope_hash,key_hash,action_id,request_json,reservation_id,created_at_ms) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE scope_hash=VALUES(scope_hash)", recovery.Hash(scope), recovery.Hash([]byte(r.Key)), r.ActionID, b, token, n)
	if e != nil {
		return false, ErrNotReady
	}
	var stored []byte
	var owner string
	if tx.QueryRowContext(ctx, "SELECT request_json,reservation_id FROM system_backup_gateway_dispatch WHERE scope_hash=? AND key_hash=? FOR UPDATE", recovery.Hash(scope), recovery.Hash([]byte(r.Key))).Scan(&stored, &owner) != nil || !bytes.Equal(stored, b) {
		return false, ErrConflict
	}
	n, e = now(ctx, tx)
	if e != nil || n >= r.Deadline {
		return false, ErrFence
	}
	if tx.Commit() != nil {
		return false, ErrNotReady
	}
	return owner == token, nil
}
