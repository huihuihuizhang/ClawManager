package install

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Invalid-owner sentinels only: these cannot produce an actual source owner,
// classified SQL metadata, held filesystem root or a positive NoS3 witness.
type unreachableFilesystemOnlyAuthority struct{}

func (*unreachableFilesystemOnlyAuthority) readOriginalFilesystemOnlyInputs(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold) (originalEmptyHistoryReadInputs, *originalHistorySQLMetadata, error) {
	panic("invalid owner reached finite authority")
}

func TestOriginalFilesystemOnlyHistoryRejectsOtherSourceForms(t *testing.T) {
	for _, mode := range []string{"artifact", "staging", "catalog", "additional", "raw-root-slot", "unread-held-root"} {
		t.Run(mode, func(t *testing.T) {
			i := originalEmptyHistoryReadInputs{revision: strings.Repeat("a", 64), until: time.Now().Add(time.Minute)}
			switch mode {
			case "artifact":
				i.scopes.Artifact = &a.S3CoverageCensus{}
			case "staging":
				i.scopes.Staging = &a.S3CoverageCensus{}
			case "catalog":
				i.scopes.Catalog = &a.S3CoverageCensus{}
			case "additional":
				i.scopes.Additional = []*a.S3CoverageCensus{nil}
			case "raw-root-slot":
				i.filesystem = []*os.Root{nil}
			case "unread-held-root":
				i.heldFilesystem = []*originalHeldHistoryRootEOF{{}}
			}
			if validOriginalFilesystemOnlyInputs(context.Background(), nil, nil, i) {
				t.Fatal("mixed/unread source accepted by structural guard")
			}
		})
	}
}
func (*unreachableFilesystemOnlyAuthority) recheckOriginalFilesystemOnlyChoice(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold, *originalHistorySQLMetadata, originalEmptyHistoryReadInputs) error {
	panic("invalid owner reached finite choice")
}
func (*unreachableFilesystemOnlyAuthority) recheckOriginalFilesystemOnlyLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time) error {
	panic("invalid owner reached finite SQL")
}

func TestOriginalFilesystemOnlyHistoryRejectsMissingOriginalAuthority(t *testing.T) {
	for _, mode := range []string{"nil-prep", "nil-hold", "nil-set", "nil-authority", "typed-nil-authority", "unprepared-owner"} {
		t.Run(mode, func(t *testing.T) {
			p := &PreparedOriginalAdoptionSQLCut{}
			h := &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}
			var a originalFilesystemOnlyAuthority = &unreachableFilesystemOnlyAuthority{}
			switch mode {
			case "nil-prep":
				p = nil
			case "nil-hold":
				h = nil
			case "nil-set":
				h.set = nil
			case "nil-authority":
				a = nil
			case "typed-nil-authority":
				var missing *unreachableFilesystemOnlyAuthority
				a = missing
			}
			if source, err := collectOriginalFilesystemOnlyHistorySource(context.Background(), p, h, a); err == nil || source != nil {
				t.Fatal("missing genuine authority minted NoS3 source")
			}
		})
	}
}

func TestOriginalFilesystemOnlyHistoryZeroNeverMintsEmptyReferences(t *testing.T) {
	for _, copied := range []bool{false, true} {
		t.Run(map[bool]string{false: "unread", true: "copied"}[copied], func(t *testing.T) {
			s := &originalEmptyHistorySource{}
			s.origin = s
			f := &originalFilesystemOnlyHistory{source: s}
			f.origin = f
			s.filesystemOnly = f
			if copied {
				f.origin = &originalFilesystemOnlyHistory{}
			}
			if s.references() != nil || !s.validUntil().IsZero() {
				t.Fatal("unread finite source claimed empty")
			}
			if s.readActualEmptySources(context.Background()) == nil || !s.failed {
				t.Fatal("zero finite source did not fail permanently")
			}
		})
	}
}
