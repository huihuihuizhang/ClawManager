package systembackupexecution

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestTeamsSourcePreparationDoesNotPublishOrReadPrivateKeyComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	s, e := PrepareOriginalCaptureSourceSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, "missing-private-key")
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{s.materials.Redis.GrantFile, s.materials.Objects.GrantFile, s.materials.Discovery.GrantFile} {
		if _, e = os.Lstat(file); !os.IsNotExist(e) {
			t.Fatal("preflight/query published a grant")
		}
	}
	child, finish := context.WithCancel(ctx)
	defer finish()
	queries := f.model.queries.Load()
	if e = s.ValidateTeamsSource(child); e == nil || f.model.queries.Load() != queries {
		t.Fatal("foreign context accessed original source")
	}
	if _, e = s.IssueTeamsSourceGrant(ctx); e == nil || f.model.queries.Load() != queries {
		t.Fatal("failed sequence revived")
	}
	if f.model.executions.Load() != 0 {
		t.Fatal("preflight wrote SQL")
	}
}

func TestTeamsMissingDeclarationFailsBeforePrivateKeyOrGrantEmissionComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	s, e := PrepareOriginalCaptureSourceSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, "missing-private-key")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ValidateTeamsSource(ctx); e == nil || !s.failed {
		t.Fatal("missing Teams declaration approved")
	}
	for _, file := range []string{s.materials.Redis.GrantFile, s.materials.Objects.GrantFile} {
		if _, e = os.Lstat(file); !os.IsNotExist(e) {
			t.Fatal("missing Teams preflight emitted another domain grant")
		}
	}
}
