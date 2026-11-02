package domain

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

// This is the actual capture path on the existing SQL model, NOT real MySQL RR
// or a provider. Every original guard must run in the same order with timing on.
func TestCaptureTimingDoesNotChangeQueryGuardsOrFailureResults(t *testing.T) {
	source, _, _ := fixture()
	for i := range source.Tables {
		if source.Tables[i].Name == "users" {
			for n := 0; n < 12; n++ {
				row := cloneRow(source.Tables[i].Rows[0])
				row["id"] = Text(string(rune('A' + n)))
				row["password_hash"] = Cell{Bytes: []byte{byte(n), 0, 255, byte(n + 1)}}
				source.Tables[i].Rows = append(source.Tables[i].Rows, row)
			}
		}
	}
	type observation struct {
		result                             Snapshot
		err                                error
		events                             []string
		guards, writes, commits, rollbacks int
		samples                            []CaptureTimingSample
	}
	run := func(timed bool, revoke int) observation {
		state := countFixture(source.Tables)
		var out observation
		original := state.sourceQuery
		state.sourceQuery = func(q string) (driver.Rows, bool, error) {
			out.events = append(out.events, q)
			return original(q)
		}
		db := database(state)
		defer db.Close()
		ctx := context.Background()
		var timings CaptureTimings
		if timed {
			ctx = WithCaptureTimings(ctx, &timings)
		}
		out.result, out.err = captureWithCatalogMode(ctx, db, Limits{MaxRows: 100, MaxBytes: 1 << 20}, nil, catalogBusinessGuarded, true, func() error {
			out.guards++
			out.events = append(out.events, "original-authority-check")
			if out.guards == revoke {
				return errors.New("private refusal")
			}
			return nil
		})
		out.writes, out.commits, out.rollbacks = state.writes, state.commits, state.rollbacks
		out.samples = timings.Snapshot()
		return out
	}
	base := run(false, 0)
	if base.err != nil || base.guards == 0 {
		t.Fatal("invalid fixture", base.err)
	}
	for revoke := 0; revoke <= base.guards; revoke++ {
		plain, timed := run(false, revoke), run(true, revoke)
		if !reflect.DeepEqual(plain.result, timed.result) || !reflect.DeepEqual(plain.events, timed.events) || plain.guards != timed.guards || plain.err != timed.err || plain.commits != timed.commits || plain.rollbacks != timed.rollbacks || timed.writes != 0 {
			t.Fatalf("timing changed original boundary %d", revoke)
		}
		guardCalls, failures := uint64(0), uint64(0)
		for _, sample := range timed.samples {
			if sample.Stage == "guard" {
				guardCalls, failures = sample.Calls, sample.Failures
			}
		}
		if guardCalls != uint64(timed.guards) || (revoke != 0 && failures != 1) {
			t.Fatalf("diagnostic changed/miscounted guard %d", revoke)
		}
		if revoke != 0 && (timed.err == nil || !reflect.DeepEqual(timed.result, Snapshot{})) {
			t.Fatalf("revocation returned a partial snapshot at %d", revoke)
		}
	}
	// Scratch reuse must not alias previously captured cells across rows/tables.
	users := find(base.result, "users")
	wantUsers := find(source, "users")
	if !reflect.DeepEqual(users.Rows, wantUsers.Rows) {
		t.Fatal("scan scratch reuse changed captured cell values")
	}
}
