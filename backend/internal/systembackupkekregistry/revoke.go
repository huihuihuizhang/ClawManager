package systembackupkekregistry

import (
	"context"
	"reflect"
)

// Revoke persists an independently authenticated purpose invalidation in the
// caller's original transaction. It never releases retained references or
// authorizes deletion of historical unwrap material.
func (b *Bound) Revoke(ctx context.Context, prepared PreparedRevocation) error {
	if ctx == nil || ctx.Err() != nil || b == nil || b.tx == nil || !present(prepared) || b.epoch != b.original.Epoch || prepared.ExpectedEpoch() != b.epoch {
		return ErrKEKFacts
	}
	pin, rev := prepared.Reference(), prepared.Revocation()
	if !kekHash.MatchString(pin.IdentityHash) || pin.Version == "" ||
		(rev.Purpose != GenerateRevocation && rev.Purpose != UnwrapRevocation) ||
		rev.Source.SourceID == "" || rev.Source.RecordID == "" || rev.Source.RecordVersion == "" ||
		!kekHash.MatchString(rev.Source.ContentSHA256) || rev.SourceRevision == "" || rev.ObservedAt.IsZero() {
		return ErrKEKFacts
	}
	var old *Revocation
	var rowVersion uint64
	for _, fact := range b.original.Bindings {
		if fact.Binding.ConfigRef == pin {
			if fact.Binding.Retention != nil {
				return ErrKEKFacts
			}
			rowVersion = fact.RowVersion
			if rev.Purpose == GenerateRevocation {
				old = fact.GenerateRevoked
			} else {
				old = fact.UnwrapRevoked
			}
			break
		}
	}
	if rowVersion == 0 || (old != nil && !reflect.DeepEqual(*old, rev)) {
		return ErrKEKFacts
	}
	now, err := b.sqlNow(ctx)
	if err != nil || rev.ObservedAt.After(now) || !now.Before(prepared.ValidUntil()) || prepared.Recheck(ctx, b.tx, b.Snapshot(), now) != nil {
		return ErrKEKFacts
	}
	if old != nil {
		return nil
	}
	raw, _, err := hashJSON(rev)
	if err != nil || len(raw) > 65535 {
		return ErrKEKFacts
	}
	column := "generate_revocation_json"
	if rev.Purpose == UnwrapRevocation {
		column = "unwrap_revocation_json"
	}
	result, err := b.tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_bindings SET `+column+`=?,row_version=row_version+1 WHERE installation_id=? AND identity_hash=? AND registry_version=? AND row_version=? AND `+column+` IS NULL`, raw, b.installationID, pin.IdentityHash, pin.Version, rowVersion)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrKEKFacts
	}
	return b.advance(ctx)
}

// RequireUnrevoked returns an error for an absent or invalidated purpose. A
// fresh current authority remains mandatory even when this fact is clear.
func (b *Bound) RequireUnrevoked(pin ReferencePin, purpose RevocationPurpose) error {
	if b == nil || b.epoch != b.original.Epoch || !kekHash.MatchString(pin.IdentityHash) || pin.Version == "" {
		return ErrKEKFacts
	}
	for _, fact := range b.original.Bindings {
		if fact.Binding.ConfigRef == pin {
			if fact.Binding.Retention != nil {
				return ErrKEKFacts
			}
			switch purpose {
			case GenerateRevocation:
				if fact.GenerateRevoked == nil {
					return nil
				}
			case UnwrapRevocation:
				if fact.UnwrapRevoked == nil {
					return nil
				}
			}
			return ErrKEKFacts
		}
	}
	return ErrKEKFacts
}
