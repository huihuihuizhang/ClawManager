package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Negative-only fixture; this is NEVER a production consumer-source builder
// or a positive NoS3/whole-holder/PreparedCoverage proof.
type missingOriginalConsumerFixture struct{}

func (*missingOriginalConsumerFixture) readOriginalBackupHistoryConsumers(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold, *originalHistorySQLMetadata) (*originalResolvedBackupHistorySources, error) {
	return nil, ErrInstall
}
func (*missingOriginalConsumerFixture) recheckOriginalBackupHistoryConsumersBeforeSQL(context.Context, *originalResolvedBackupHistorySources) error {
	return ErrInstall
}
func (*missingOriginalConsumerFixture) recheckOriginalBackupHistoryConsumersLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time, *originalResolvedBackupHistorySources) error {
	return ErrInstall
}

func TestOriginalHistorySourceFactoryRejectsMissingActualOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var typedNil *missingOriginalConsumerFixture
	for _, source := range []originalBackupHistoryConsumerSource{nil, typedNil, &missingOriginalConsumerFixture{}} {
		if r, e := prepareOriginalHistorySourceSetLocked(ctx, &PreparedOriginalAdoptionSQLCut{}, &OriginalWriterHold{}, source); e == nil || r != nil {
			t.Fatal("missing original owner authorized")
		}
	}
	p := &PreparedOriginalAdoptionSQLCut{}
	if _, e := p.PrepareOriginalFilesystemHistoryCoverage(ctx, &OriginalWriterHold{}, &missingOriginalConsumerFixture{}); e == nil {
		t.Fatal("zero holder produced coverage")
	}
	if _, e := p.AdoptOriginalFilesystemHistory(ctx, &OriginalWriterHold{}, &missingOriginalConsumerFixture{}, nil, a.OriginalAdoptionControlRecords{}); e == nil {
		t.Fatal("zero holder entered formal adoption")
	}
}

func TestOriginalHistorySourceRevisionBindsEverySourceAndRoot(t *testing.T) {
	makeSource := func() *originalResolvedBackupHistorySources {
		return &originalResolvedBackupHistorySources{metadata: &originalHistorySQLMetadata{revision: strings.Repeat("a", 64)}, hold: &OriginalWriterHold{set: &PreparedOriginalWriterSet{inventorySHA: strings.Repeat("b", 64)}}, consumers: []originalBackupHistoryConsumer{{"original-host", "original_local_history", "original-version-1", strings.Repeat("c", 64)}}, roots: []originalBackupHistoryRoot{{"original-host", strings.Repeat("d", 64), "node", "/original/history"}}}
	}
	original := originalResolvedBackupHistoryRevision(makeSource())
	for _, name := range []string{"consumer", "kind", "version", "source-body", "root-owner", "root-definition", "node", "path", "SQL", "writer-set"} {
		t.Run(name, func(t *testing.T) {
			s := makeSource()
			switch name {
			case "consumer":
				s.consumers[0].id = "other"
			case "kind":
				s.consumers[0].kind = "other"
			case "version":
				s.consumers[0].sourceVersion = "other"
			case "source-body":
				s.consumers[0].sourceSHA256 = strings.Repeat("e", 64)
			case "root-owner":
				s.roots[0].consumerID = "other"
			case "root-definition":
				s.roots[0].definitionSHA256 = strings.Repeat("e", 64)
			case "node":
				s.roots[0].node = "other"
			case "path":
				s.roots[0].path = "/replacement/history"
			case "SQL":
				s.metadata.revision = strings.Repeat("e", 64)
			case "writer-set":
				s.hold.set.inventorySHA = strings.Repeat("e", 64)
			}
			if originalResolvedBackupHistoryRevision(s) == original {
				t.Fatal("original source association lost by hash projection")
			}
		})
	}
}

func TestOriginalHistoryCoverageRequiresActualAuthenticationAndNativeCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var p PreparedOriginalAdoptionCoverage
	p.origin = &p
	if p.bindOriginalHistoryControls(ctx, a.SQLCoverageOwnerConfig{}, a.OriginalAdoptionControlRecords{}) == nil {
		t.Fatal("unauthenticated record transport produced sources")
	}
	if _, e := p.OriginalHistoryInspection(ctx); e == nil {
		t.Fatal("zero source emitted a source inspection")
	}
	if _, e := originalAdoptionNativeUntil(nil); e == nil {
		t.Fatal("missing B observations supplied lifetime")
	}
	if _, e := originalAdoptionNativeUntil(&originalHeldReadiness{}); e == nil {
		t.Fatal("zero B observations supplied lifetime")
	}
	if _, e := json.Marshal(&originalHistorySourceSet{}); e == nil {
		t.Fatal("private authority serialized")
	}
	if _, e := json.Marshal(&originalResolvedBackupHistorySources{}); e == nil {
		t.Fatal("source observation serialized")
	}
}
