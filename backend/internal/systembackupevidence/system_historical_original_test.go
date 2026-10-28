package systembackupevidence

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This fixture supplies D's transaction owner for byte reconstruction only;
// it is not a production historical identity or permission authority.
type systemHistoricalTestPolicy struct{ until time.Time }

func (p systemHistoricalTestPolicy) LockAndAuthorize(context.Context, pd.SQL, pd.Scope) (pd.GuardPlan, error) {
	return pd.GuardPlan{BindingHash: pd.Hash(strings.Repeat("a", 64)), Deadlines: []time.Time{p.until}}, nil
}
func (systemHistoricalTestPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func TestSystemHistoricalOriginalReconstructsOnlyCommittedABytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stages []string
		change func(*dIntegrationFixture, *pd.HistoricalBindingRecord)
		accept bool
	}{
		{name: "pending", stages: []string{"pending"}, accept: true},
		{name: "ready", stages: []string{"pending", "claim", "finish"}, accept: true},
		{name: "missing_row", stages: []string{"pending"}, change: func(f *dIntegrationFixture, _ *pd.HistoricalBindingRecord) { f.d.row = nil }},
		{name: "changed_envelope", stages: []string{"pending"}, change: func(f *dIntegrationFixture, _ *pd.HistoricalBindingRecord) {
			f.d.row["envelope_hash"] = strings.Repeat("f", 64)
		}},
		{name: "missing_chunk", stages: []string{"pending"}, change: func(f *dIntegrationFixture, _ *pd.HistoricalBindingRecord) { f.d.chunks = nil }},
		{name: "changed_chunk", stages: []string{"pending"}, change: func(f *dIntegrationFixture, _ *pd.HistoricalBindingRecord) {
			f.d.chunks[0]["ciphertext_sha256"] = strings.Repeat("f", 64)
		}},
		{name: "changed_D_manifest", stages: []string{"pending"}, change: func(_ *dIntegrationFixture, h *pd.HistoricalBindingRecord) {
			h.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDIntegrationFixture(t)
			f.advance(tc.stages...)
			history := f.history
			if tc.change != nil {
				tc.change(f, &history)
			}
			runner, err := pd.NewTransactions(f.db, f.history.Scope, systemHistoricalTestPolicy{until: f.until})
			if err != nil {
				t.Fatal(err)
			}
			var record Record
			receipt, err := runner.Run(context.Background(), func(ctx context.Context, tx *pd.Transaction) error {
				var loadErr error
				record, loadErr = loadSystemHistoricalRecord(ctx, tx, history, f.channel)
				return loadErr
			})
			if !tc.accept {
				if err == nil || receipt.Committed() || !reflect.DeepEqual(record, Record{}) {
					t.Fatal("untrusted historical or A bytes reconstructed", err)
				}
				return
			}
			if err != nil || !receipt.Committed() || !reflect.DeepEqual(record.Manifest, f.prepared.Manifest()) || record.Manifest.Identity != f.prepared.Manifest().Identity || record.State != f.d.row["storage_state"] {
				t.Fatal("exact historical original not reconstructed", err)
			}
			if tc.name == "ready" && record.Ref.ImmutableVersion != "Exact.Version/1" {
				t.Fatal("ready immutable version lost")
			}
		})
	}
}
