//go:build systembackup_mysql

package install

import (
	"context"
	"testing"
)

// Actual A original issuance feeds D's REAL full177 SQL installer/resolve and
// SELECT-only consumer. Kube/Vault are explicitly controlled; this root proves
// no complete terminal/main/provider/backup/site acceptance on its own.
func TestSigningResourceSQLNativeActualOriginalIssuerInstallAndReadback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
	defer cancel()
	f := newNativeSigningSQLFixture(t, ctx)
	pins, bundles := issueSigningResourcesForNativeTarget(t, ctx, f.n.f)
	inputs := nativeSignerIssuedInputs(t, f, pins, bundles)
	installed, err := f.n.f.i.ImportSigningResourceSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, inputs)
	if err != nil || len(installed.Items) != 2 {
		t.Fatal("actual A-issued purpose grants did not import into native SQL", err)
	}
	for n, item := range installed.Items {
		if item.Purpose != inputs[n].Pin.Purpose || item.Replayed || item.Comparison.State != "active" || item.Comparison.HeadRevision != 1 || item.Comparison.HeadRowVersion != 1 || item.Comparison.GrantRevision != 1 || item.Comparison.GrantRowVersion != 1 || item.Comparison.PermissionEpoch != 1 || item.Comparison.GrantID != inputs[n].Pin.GrantID || item.Comparison.GrantSHA256 != inputs[n].Pin.GrantSHA256 {
			t.Fatal("native original import comparison", item.Purpose)
		}
	}
	resolved, err := f.n.f.i.ResolveSigningResourceSQLAuthority(ctx, f.n.f.password, f.n.f.enrollment, inputs)
	if err != nil || len(resolved.Items) != 2 {
		t.Fatal("actual original bundles did not resolve", err)
	}
	for n, item := range resolved.Items {
		if item.Purpose != installed.Items[n].Purpose || item.Comparison != installed.Items[n].Comparison {
			t.Fatal("resolve changed original four-row tuple")
		}
	}
	nativeSignerExactFour(t, ctx, f, inputs)
	consumer := nativeSignerConsumer(t, ctx, f, inputs, true)
	if err := consumer.Rollback(); err != nil {
		t.Fatal("close actual SELECT-only consumer readback", err)
	}
	t.Log("actual enrolled A issuer -> native original two-purpose import -> exact resolve -> four raw rows and SELECT-only current consumer; controlled Kube/Vault, no full backup/site claim")
}
