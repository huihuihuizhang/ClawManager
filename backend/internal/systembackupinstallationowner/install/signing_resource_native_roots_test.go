//go:build systembackup_mysql

package install

import (
	"context"
	"testing"
)

// These roots exercise actual TLS MySQL with explicit test issuer declarations.
// Production issuance/provider observation and retained terminal admission are
// deliberately outside their evidence scope; see native declaration helper.
func TestSigningResourceSQLNativeDeclaredInstallReplayAndRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
	defer cancel()
	f := newNativeSigningSQLFixture(t, ctx)
	inputs := nativeSignerOriginalDeclarationInputs(t, ctx, f)
	runNativeSignerLifecycle(t, ctx, f, inputs)
}

func TestSigningResourceSQLNativeDeclaredRollbackLostACKAndResolve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
	defer cancel()
	f := newNativeSigningSQLFixture(t, ctx)
	inputs := nativeSignerOriginalDeclarationInputs(t, ctx, f)
	runNativeSignerRollbackAndLostACK(t, ctx, f, inputs)
}

func TestSigningResourceSQLNativeDeclaredConsumerRevokeLockOrder(t *testing.T) {
	for _, blocked := range []string{"head:acceptance_record", "grant:catalog_record"} {
		t.Run(blocked, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
			defer cancel()
			f := newNativeSigningSQLFixture(t, ctx)
			inputs := nativeSignerOriginalDeclarationInputs(t, ctx, f)
			runNativeSignerLockCase(t, ctx, cancel, f, inputs, blocked)
		})
	}
}
