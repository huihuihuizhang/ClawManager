package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// ReadCurrentOriginalUnwrapTx authenticates comparison data in the caller's
// original view. The caller owns its task/domain locks and KEK fence/binding
// checks. This performs only the existing locked owner read and validators;
// it grants no provider operation, creates no mapping and starts no transaction.
func ReadCurrentOriginalUnwrapTx(ctx context.Context, view reg.SQLReadView, binding reg.Binding, issuer ed25519.PublicKey, now time.Time) (OriginalRecord, error) {
	if ctx == nil || ctx.Err() != nil || nilSource(view) || now.IsZero() {
		return OriginalRecord{}, ErrAuthorityWrite
	}
	return currentVerifierOriginalMapping(ctx, view, binding, issuer, now, true)
}
