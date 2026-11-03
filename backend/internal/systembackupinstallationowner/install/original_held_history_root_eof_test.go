package install

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestOriginalHeldHistoryRootEOFRejectsMissingOwners(t *testing.T) {
	for _, mode := range []string{"nil-preparation", "nil-hold", "nil-set", "unprepared-owner"} {
		t.Run(mode, func(t *testing.T) {
			p := &PreparedOriginalAdoptionSQLCut{}
			h := &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}
			switch mode {
			case "nil-preparation":
				p = nil
			case "nil-hold":
				h = nil
			case "nil-set":
				h.set = nil
			}
			if actual, err := readOriginalHeldHistoryRootEOF(context.Background(), p, h, "original-node", "/original-root"); err == nil || actual != nil {
				t.Fatal("missing true original owners minted root EOF")
			}
		})
	}
}

func TestOriginalHeldHistoryRootEOFRejectsUnreadCopiedAndExpired(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"zero", "self-pointer-only", "copied", "expired"} {
		t.Run(mode, func(t *testing.T) {
			r := &originalHeldHistoryRootEOF{}
			switch mode {
			case "self-pointer-only":
				r.origin = r
			case "copied":
				r.origin = &originalHeldHistoryRootEOF{}
			case "expired":
				r.origin = r
				r.until = time.Now().Add(-time.Second)
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("original EOF observation serialized")
			}
			if r.matchesOriginalRootEOFAtSQL(ctx, nil, nil, time.Now()) {
				t.Fatal("unread/expired result survived final SQL")
			}
			if r.recheckBeforeOriginalHistoryRootSQLLocked(ctx) == nil || !r.failed {
				t.Fatal("invalid reader did not fail permanently")
			}
		})
	}
}
