package systembackupexecution

import (
	"context"
	"testing"
	"time"
)

func TestDatabaseSourceIssueUsesOriginalSequenceContextAndFailureLatchComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	sequence, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil {
		t.Fatal(err)
	}
	queries := f.model.queries.Load()
	child, finish := context.WithCancel(ctx)
	defer finish()
	if _, err := sequence.IssueDatabaseSourceGrant(child, "missing", hash([]byte("missing"))); err == nil || f.model.queries.Load() != queries {
		t.Fatal("foreign child context performed source issuance work", err)
	}
	if _, err := sequence.IssueDatabaseSourceGrant(ctx, "missing", hash([]byte("missing"))); err == nil || f.model.queries.Load() != queries {
		t.Fatal("original context revived failed database source phase", err)
	}
	if f.model.executions.Load() != 0 {
		t.Fatal("database grant wrapper mutated SQL")
	}
}
