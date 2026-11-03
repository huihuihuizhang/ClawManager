package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestFirstAdoptionSourceFailureDiagnostic(t *testing.T) {
	err := fmt.Errorf("private wrapper not printable: %w", install.OriginalWriterSourceFailure{InstanceID: 17, Mode: "pro", Status: "stopped", Dependency: "current_stopped_pro_volume_selection_required"})
	got := classifiedAdoptionFailure("source_preflight", err)
	if got.Stage != "source_preflight" || got.InstanceID != 17 || got.Mode != "pro" || got.Status != "stopped" || got.Dependency != "current_stopped_pro_volume_selection_required" {
		t.Fatal("real source stop point lost")
	}
	consumer := classifiedAdoptionFailure("history_preparation", install.OriginalWriterSourceFailure{Dependency: "original_backup_consumer_unclassified:Pod/old-server/sidecar"})
	if consumer.Dependency != "original_backup_consumer_unclassified:Pod/old-server/sidecar" {
		t.Fatal("actual Pod/container origin lost")
	}
}

func TestFirstAdoptionDiagnosticsNeverPrintRawErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"SQL_native", errors.New("mysql://user:RAW_SECRET@server/private; native credential=RAW_SECRET")},
		{"untrusted_dependency", install.OriginalWriterSourceFailure{Mode: "bad\nRAW_SECRET", Status: "bad\nRAW_SECRET", Dependency: "credential=RAW_SECRET\nprivate-body"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if reportStageFailure(&out, "original_preflight_refused_no_source_stop", "source_preflight", tc.err, install.OriginalAdoptionCommitInspection{}, 1) != 1 {
				t.Fatal("failure code changed")
			}
			if strings.Contains(out.String(), "RAW_SECRET") || strings.Contains(out.String(), "private-body") || strings.Contains(out.String(), "mysql://") {
				t.Fatal("raw private error escaped")
			}
		})
	}
}

func TestFirstAdoptionRecoveryFailurePreservesConfirmedCommit(t *testing.T) {
	var out bytes.Buffer
	committed := install.OriginalAdoptionCommitInspection{Version: "original-adoption-commit-inspection.v1", Operation: "original-operation", State: "committed_exact_original_readback", ExpectedSHA256: strings.Repeat("a", 64), ExpectedEpoch: 8}
	if reportStageFailure(&out, "original_sources_not_completely_verified_retains_gates", "source_recovery", errors.New("raw private error"), committed, 3) != 3 {
		t.Fatal("unknown/recovery exit code changed")
	}
	var got adoptionReport
	if json.Unmarshal(out.Bytes(), &got) != nil || got.Adoption != committed || got.SourceRecoveryVerified || got.PageBackupCompleted || got.Failure == nil || got.Failure.Stage != "source_recovery" {
		t.Fatal("confirmed original commit lost or recovery falsely reported")
	}
}

func TestFirstAdoptionDiagnosticLengthBoundary(t *testing.T) {
	for _, n := range []int{0, 1024, 1025} {
		t.Run(fmt.Sprintf("bytes_%d", n), func(t *testing.T) {
			value := strings.Repeat("a", n)
			got := classifiedAdoptionFailure("source_preflight", install.OriginalWriterSourceFailure{Mode: value, Status: value, Dependency: value})
			want := ""
			if n == 1024 {
				want = value
			}
			if got.Mode != want || got.Status != want || got.Dependency != want {
				t.Fatal("diagnostic finite field limit changed")
			}
		})
	}
}
