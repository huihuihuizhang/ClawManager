package systembackupsecurity

import (
	"context"
	"testing"
)

// The complete historical ROW MODEL is not native concurrency evidence.
func TestSQLSigningStatePrefixUsesRealOwnerBeforeAnyLineageStage(t *testing.T) {
	f, m, db, s := enabledSigningFixture(t)
	ctx := context.Background()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if s.LockSigningStatePrefix(ctx, tx) != nil || m.lineageReads != 1 {
		t.Fatal("original v1 state prefix not acquired first")
	}
	input := signingSQLInput(t, f.task, f.mounts[0].Binding)
	if s.StageSigningInput(ctx, tx, f.mounts[0].Binding.Purpose, input) != nil {
		t.Fatal("same original transaction could not stage after prefix")
	}
	if tx.Rollback() != nil || len(m.base.evidence) != 0 {
		t.Fatal("rollback retained staged result")
	}
}
func TestSQLSigningStatePrefixKeepsOriginalV1TaskV1Scope(t *testing.T) {
	f, m, db, s := enabledSigningFixture(t)
	m.base.grant.ConfigVersion = 1
	m.base.grant.ConfigSHA256 = m.old.SHA256()
	ctx := context.Background()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	input := signingSQLInput(t, f.task, f.mounts[0].Binding)
	if s.StageSigningInput(ctx, tx, f.mounts[0].Binding.Purpose, input) != nil {
		t.Fatal("original v1==task1 scope changed into v2-only permission")
	}
	if m.lineageReads != 1 {
		t.Fatal("legacy same-tuple path fabricated full enabled-only lineage")
	}
}
