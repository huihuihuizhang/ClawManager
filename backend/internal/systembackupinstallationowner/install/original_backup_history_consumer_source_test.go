package install

import (
	"context"
	"reflect"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	corev1 "k8s.io/api/core/v1"
)

func TestOriginalFiniteBackupConsumerSourceOwnerGuards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name string
		p    *PreparedOriginalAdoptionSQLCut
		h    *OriginalWriterHold
	}{
		{"nil", nil, nil},
		{"zero", &PreparedOriginalAdoptionSQLCut{}, &OriginalWriterHold{}},
		{"unowned_set", &PreparedOriginalAdoptionSQLCut{}, &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := tc.p.PrepareOriginalBackupConsumerHistorySource(ctx, tc.h); err == nil || s != nil {
				t.Fatal("source manufactured without original maintenance ownership")
			}
		})
	}
	s := &originalFiniteBackupConsumerSource{}
	if _, err := s.readOriginalBackupHistoryConsumers(ctx, nil, nil, nil); err == nil || s.recheckOriginalBackupHistoryConsumersBeforeSQL(ctx, nil) == nil {
		t.Fatal("zero source accepted")
	}
}

func TestOriginalFiniteBackupConsumerRetainedLayout(t *testing.T) {
	f := a.SQLCoverageCensusFacts{}
	for _, name := range a.RetainedOriginalLegacySourceTables() {
		f.Tables = append(f.Tables, a.SQLCoverageTable{Table: name})
	}
	if !originalRetainedLegacyLayoutMatches(f) {
		t.Fatal("reviewed empty original35 layout refused")
	}
	for _, tc := range []string{"missing", "nonempty_rows", "nonempty_bytes", "duplicate"} {
		t.Run(tc, func(t *testing.T) {
			changed := f
			changed.Tables = append([]a.SQLCoverageTable(nil), f.Tables...)
			switch tc {
			case "missing":
				changed.Tables = changed.Tables[:34]
			case "nonempty_rows":
				changed.Tables[0].Rows = 1
			case "nonempty_bytes":
				changed.Tables[0].Bytes = 1
			case "duplicate":
				changed.Tables = append(changed.Tables, changed.Tables[0])
			}
			if originalRetainedLegacyLayoutMatches(changed) {
				t.Fatal("missing or changed original source inferred empty")
			}
		})
	}
}

func TestOriginalFiniteBackupConsumerFullSourceProjection(t *testing.T) {
	s := &originalFiniteBackupConsumerSource{mountedRevision: "original-pod-deployment-raw", controllerInventory: &originalHistoryControllerInventory{revision: "original-all-controllers-raw"}}
	input := []originalBackupHistoryConsumer{{id: "original-consumer", kind: "original_non_backup_consumer", sourceVersion: "actual-profile", sourceSHA256: "actual-code-startup"}}
	before := append([]originalBackupHistoryConsumer(nil), input...)
	result := s.boundConsumers(input)
	if len(result) != 1 || result[0].sourceSHA256 == input[0].sourceSHA256 || !reflect.DeepEqual(input, before) {
		t.Fatal("raw source not bound or original profile mutated")
	}
	s.mountedRevision += "changed"
	if reflect.DeepEqual(result, s.boundConsumers(input)) {
		t.Fatal("raw original Pod/Deployment change invisible")
	}
	s.mountedRevision = "original-pod-deployment-raw"
	s.controllerInventory.revision += "changed"
	if reflect.DeepEqual(result, s.boundConsumers(input)) {
		t.Fatal("raw retained-controller change invisible")
	}
	s.controllerInventory = nil
	if s.boundConsumers(input) != nil {
		t.Fatal("missing whole-controller source accepted")
	}
}

func TestOriginalFiniteBackupConsumerStatusIdentity(t *testing.T) {
	s := []corev1.ContainerStatus{{Name: "one", ContainerID: "original-container", ImageID: "immutable-original"}}
	if originalContainerStatus(s, "one") != &s[0] || originalContainerStatus(s, "missing") != nil {
		t.Fatal("actual status identity lost")
	}
	s = append(s, s[0])
	if originalContainerStatus(s, "one") != nil {
		t.Fatal("ambiguous original runtime identity accepted")
	}
}
