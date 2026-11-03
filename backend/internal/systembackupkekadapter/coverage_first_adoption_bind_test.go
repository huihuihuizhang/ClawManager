package systembackupkekadapter

import (
	"context"
	"testing"
)

func TestFirstAdoptionBindRejectsDetachedOriginalTransaction(t *testing.T) {
	ctx := context.Background()
	owner := &SQLCoverageOwnerPreparation{}
	for _, tc := range []struct {
		name  string
		owner *SQLCoverageOwnerPreparation
		cut   *OriginalAdoptionControlCut
	}{
		{"no-owner", nil, nil},
		{"no-cut", owner, nil},
		{"detached-cut", owner, &OriginalAdoptionControlCut{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound, auth, err := tc.owner.BindFirstAdoptionControls(ctx, tc.cut)
			if err == nil || bound != nil || auth != nil {
				t.Fatal("unbound original transaction escaped")
			}
		})
	}
}
