package systembackupexecution

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

func TestSourceWriterObservationRetainsOriginalStoppedFixtureMySQL(t *testing.T) {
	f, _ := sourceSQLObservationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := sourceObservationControlCounts(t, f)
	facts, err := f.service.ObserveSourceDependencies(ctx)
	if !errors.Is(err, c.ErrSourceRecoveryStoppedWitnessRequired) || facts.WriterSHA256() != "" || facts.MetadataSHA256() != "" {
		t.Fatal("original stopped SQL fixture produced positive physical facts", err)
	}
	if !reflect.DeepEqual(before, sourceObservationControlCounts(t, f)) {
		t.Fatal("taskless writer observation created task/control records")
	}
}
