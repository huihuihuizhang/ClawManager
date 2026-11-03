package install

import (
	"context"
	"testing"
)

func TestOriginalOwnerAdoptionEntryRejectsMissingOriginalSources(t *testing.T) {
	for _, tc := range []struct {
		name     string
		p        *PreparedOriginalAdoptionSQLCut
		h        *OriginalWriterHold
		coverage *PreparedOriginalAdoptionCoverage
	}{
		{"nil", nil, nil, nil},
		{"zero", &PreparedOriginalAdoptionSQLCut{}, &OriginalWriterHold{}, &PreparedOriginalAdoptionCoverage{}},
		{"unowned_set", &PreparedOriginalAdoptionSQLCut{}, &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}, &PreparedOriginalAdoptionCoverage{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.p.CommitOriginalOwnerAdoption(context.Background(), tc.h, nil, nil, tc.coverage); err == nil || got.State != "" {
				t.Fatal("missing genuine owner/source committed adoption")
			}
			if got, err := tc.p.CommitOriginalAdoption(context.Background(), tc.h, nil, nil, tc.coverage); err == nil || got.State != "" {
				t.Fatal("compatibility wrapper bypassed owner authentication")
			}
		})
	}
}
