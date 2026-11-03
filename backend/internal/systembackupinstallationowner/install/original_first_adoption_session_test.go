package install

import (
	"context"
	"testing"
	"time"
)

func TestOriginalFirstAdoptionSessionRejectsFabricatedHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name string
		hold *OriginalWriterHold
	}{
		{"nil", nil},
		{"zero", &OriginalWriterHold{}},
		{"unowned_set", &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := tc.hold.PrepareOriginalFirstAdoption(ctx, nil, EnrollmentPin{}); err == nil || p != nil {
				t.Fatal("fabricated original hold became source preparation")
			}
		})
	}
}

func TestOriginalFirstAdoptionSessionCannotBeReconstituted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name    string
		session *PreparedOriginalFirstAdoption
	}{
		{"nil", nil},
		{"zero", &PreparedOriginalFirstAdoption{}},
		{"unowned_coverage", &PreparedOriginalFirstAdoption{ctx: ctx, prep: &PreparedOriginalAdoptionSQLCut{}, hold: &OriginalWriterHold{}, coverage: &PreparedOriginalAdoptionCoverage{}, until: time.Now().Add(time.Minute)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.session.local(ctx) {
				t.Fatal("DTO/zero fields became a genuine original session")
			}
		})
	}
}
