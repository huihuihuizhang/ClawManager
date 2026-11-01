package domain

import (
	"context"
	"reflect"
	"testing"

	resources "clawreef/internal/systembackupresources"
)

func TestNorthboundOwnerCommonNormalizePreservesDeletedReferencesAndAllCells(t *testing.T) {
	source, target, p := fixture()
	owner := northboundOwnerFixture()
	source.Tables = append(source.Tables, owner)
	target = append(target, owner)
	a := TableAdapter{SchemaSHA256: SchemaDigest(owner), Normalizer: NorthboundOwner067Normalizer, Columns: map[string]string{}}
	for _, c := range owner.Columns {
		a.Columns[c.Name] = "preserve"
	}
	p.Dependencies = map[string]TableAdapter{owner.Name: a}
	before, _ := Digest(source)
	plan, e := Normalize(context.Background(), source, target, p)
	if e != nil {
		t.Fatal("actual common Normalize", e)
	}
	if !reflect.DeepEqual(find(plan.Data, owner.Name).Rows, owner.Rows) {
		t.Fatal("owner identity/bitmap/uint64/NULL/decimal/private history changed")
	}
	if after, _ := Digest(source); after != before {
		t.Fatal("source archive changed")
	}
	if e = VerifyNorthboundQuarantine(context.Background(), plan.Data); e != nil {
		t.Fatal("independent expected-row validation", e)
	}
	delete(p.Dependencies, owner.Name)
	if _, e = Normalize(context.Background(), source, target, p); e == nil {
		t.Fatal("unreviewed owner table restored through generic preserve")
	}
}

// Export only test data/conversion for the separate opt-in real MySQL tests.
// None of these values creates a target observation, CAS candidate or authority.
func NorthboundOwnerNativeRowForTest() Row { return cloneRow(northboundOwnerFixture().Rows[0]) }
func NorthboundNativeBridgeSourceForTest(ctx context.Context, s Snapshot) (resources.NorthboundRestoreSource, error) {
	return northboundBridgeSource(ctx, s)
}
