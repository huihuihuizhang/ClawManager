package systembackupinstallationowner

import (
	"context"
	"testing"
	"time"
)

func TestCaptureSigningBootstrapOriginalUsesOneCurrentGuard(t *testing.T) {
	p, state, tx, ctx := newOwnerSQLFixture(t)
	if p.AuthorizeBootstrapOriginal(ctx, tx, p.grant, p.config, state.now) != nil {
		t.Fatal("original L2 not reached")
	}
	guard := p.guard
	if guard == nil || p.AuthorizeBootstrapOriginal(ctx, tx, p.grant, p.config, state.now) != nil || p.guard != guard {
		t.Fatal("original L2 guard was replaced")
	}
	state.grantState = "revoked"
	if p.AuthorizeBootstrapOriginal(ctx, tx, p.grant, p.config, state.now) == nil {
		t.Fatal("revoked original source authorized retry")
	}
}
func TestCaptureSigningBootstrapOriginalKeepsHistoryIndependentOfProbe(t *testing.T) {
	p, state, tx, ctx := newOwnerSQLFixture(t)
	if p.observation != nil {
		t.Fatal("fixture unexpectedly has physical resource permission")
	}
	if p.AuthorizeBootstrapOriginal(ctx, tx, p.grant, p.config, state.now) != nil {
		t.Fatal("current history identity required an old probe")
	}
	if p.Recheck(ctx, tx, state.now) == nil {
		t.Fatal("missing probe granted new resource consumption")
	}
	p2, state2, tx2, ctx2 := newOwnerSQLFixture(t)
	wrong, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if p2.AuthorizeBootstrapOriginal(wrong, tx2, p2.grant, p2.config, state2.now) == nil || p2.AuthorizeBootstrapOriginal(ctx2, tx2, p2.grant, p2.config, state2.now) == nil {
		t.Fatal("wrong context did not latch failure")
	}
}
