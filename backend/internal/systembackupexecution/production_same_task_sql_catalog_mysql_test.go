package systembackupexecution

import (
	"context"
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
)

// Separate read-only SQL adapter regression, never an alternative worker,
// candidate, successful capture task or owner-complete evidence.
func TestProductionBusinessCatalogOriginalTLSMetadataEquivalenceMySQL(t *testing.T) {
	f := newDOriginalSixPartTask(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	want, err := domain.Catalog(ctx, f.service.Source)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	started := time.Now()
	got, err := domain.CaptureBusinessSourceGuarded(ctx, f.service.Source, domain.Limits{MaxRows: f.sourceSpec.MaxRows, MaxBytes: f.sourceSpec.MaxMemoryBytes}, f.database, f.server, func(context.Context) error { checks++; return nil }, *f.sourceSpec.SchemaCensus)
	if err != nil {
		t.Fatal("actual original read-only business capture", err)
	}
	metadata := append([]domain.Table{}, got.Tables...)
	for index := range metadata {
		metadata[index].Rows = nil
	}
	if !reflect.DeepEqual(metadata, want) || checks > 1000 {
		t.Fatal("actual original full schema/PK/FK/unique/default shape differs", checks)
	}
	if domain.VerifyBusinessCapturedSnapshot(got, *f.sourceSpec.CaptureSchema) != nil {
		t.Fatal("actual original frozen schema verification rejected")
	}
	t.Log("actual complete business SQL metadata guards/elapsed", checks, time.Since(started))
}
