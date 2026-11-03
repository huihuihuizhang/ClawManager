package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Negative boundary doubles only. These produce no physical hold, original
// installed source universe or successful source-read/first-adoption proof.
type unreachableEmptyHistoryAuthority struct{}

func (*unreachableEmptyHistoryAuthority) readOriginalEmptyHistoryInputs(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold) (originalEmptyHistoryReadInputs, error) {
	panic("invalid owner reached source reader")
}
func (*unreachableEmptyHistoryAuthority) recheckOriginalEmptyHistoryBeforeSQL(context.Context, originalEmptyHistoryReadInputs) error {
	panic("invalid owner reached source reader")
}
func (*unreachableEmptyHistoryAuthority) recheckOriginalEmptyHistoryLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time) error {
	panic("invalid owner reached source reader")
}

func TestOriginalEmptyHistorySourceRejectsMissingOriginalOwners(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"nil-preparation", "nil-hold", "nil-set", "nil-authority", "typed-nil-authority", "unprepared-owner"} {
		t.Run(mode, func(t *testing.T) {
			prep := &PreparedOriginalAdoptionSQLCut{}
			hold := &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}
			var authority originalEmptyHistoryAuthority = &unreachableEmptyHistoryAuthority{}
			switch mode {
			case "nil-preparation":
				prep = nil
			case "nil-hold":
				hold = nil
			case "nil-set":
				hold.set = nil
			case "nil-authority":
				authority = nil
			case "typed-nil-authority":
				var missing *unreachableEmptyHistoryAuthority
				authority = missing
			}
			if actual, err := collectOriginalEmptyHistorySource(ctx, prep, hold, authority); err == nil || actual != nil {
				t.Fatal("missing original source/hold minted history")
			}
		})
	}
}

func TestOriginalEmptyHistorySourceZeroIsNeitherEmptyNorSerializable(t *testing.T) {
	for _, seal := range []bool{false, true} {
		s := &originalEmptyHistorySource{}
		if seal {
			s.origin = s
		}
		if s.references() != nil || !s.validUntil().IsZero() {
			t.Fatal("unread source claimed legal empty")
		}
		if _, err := json.Marshal(s); err == nil {
			t.Fatal("private source serialized")
		}
		if _, ok := any(s).(reg.PreparedCoverage); ok {
			t.Fatal("classified source became PreparedCoverage")
		}
		if s.recheckBeforeOriginalHistorySQL(context.Background()) == nil {
			t.Fatal("unread source prefix succeeded")
		}
		if !s.failed {
			t.Fatal("source failure not poisoned")
		}
	}
}
