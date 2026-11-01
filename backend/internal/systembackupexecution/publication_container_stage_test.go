package systembackupexecution

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
)

func TestPublicationContainerDirectoryMarkerCannotReplayOtherOriginalPlanData(t *testing.T) {
	key := bytes.Repeat([]byte{41}, 32)
	plan := publicationContainerPlan{Version: "system-backup-original-publication-container-plan.v1", Installation: "installation_DATA", Backup: "sbk_DATA", Attempt: 1, ConfigVersion: 2, ConfigSHA256: strings.Repeat("a", 64), CaptureSHA256: strings.Repeat("b", 64), CertificateSHA256: strings.Repeat("c", 64), ParentResource: "sbs_DATA", ParentKeyVersion: "key-DATA", ParentOwnerMAC: strings.Repeat("d", 64), Directory: "publication-DATA"}
	before, err := containerDirectoryMarker(plan, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "task", "attempt", "config", "capture", "certificate", "parent-resource", "parent-mac", "directory", "key"} {
		t.Run(mode, func(t *testing.T) {
			changed, other := plan, bytes.Clone(key)
			switch mode {
			case "task":
				changed.Backup += "_other"
			case "attempt":
				changed.Attempt++
			case "config":
				changed.ConfigSHA256 = strings.Repeat("e", 64)
			case "capture":
				changed.CaptureSHA256 = strings.Repeat("e", 64)
			case "certificate":
				changed.CertificateSHA256 = strings.Repeat("e", 64)
			case "parent-resource":
				changed.ParentResource += "_other"
			case "parent-mac":
				changed.ParentOwnerMAC = strings.Repeat("e", 64)
			case "directory":
				changed.Directory += "_other"
			case "key":
				other[0]++
			}
			actual, err := containerDirectoryMarker(changed, other)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(actual, before) != (mode == "current") || bytes.Contains(actual, key) {
				t.Fatal("owner proof replay or private key exposure", mode)
			}
		})
	}
}

func TestPublicationContainerStageComparisonRetainsOriginal104FactsData(t *testing.T) {
	original := publicationCertificateSQLFacts{stage: originalStageResource{owner: originalStageOwner{Resource: "sbs_original", KeyVersion: "key-original"}, mac: strings.Repeat("a", 64), lifecycle: "ready", version: 3}, locationHash: strings.Repeat("b", 64), completed: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), ttl: 3600, taskVersion: 10}
	for _, mode := range []string{"current", "new-current-task-version", "stage-version", "stage-owner", "stage-mac", "completed", "ttl", "location"} {
		t.Run(mode, func(t *testing.T) {
			changed := original
			switch mode {
			case "new-current-task-version":
				changed.taskVersion++
			case "stage-version":
				changed.stage.version++
			case "stage-owner":
				changed.stage.owner.Resource += "_other"
			case "stage-mac":
				changed.stage.mac = strings.Repeat("e", 64)
			case "completed":
				changed.completed = changed.completed.Add(time.Microsecond)
			case "ttl":
				changed.ttl++
			case "location":
				changed.locationHash = strings.Repeat("e", 64)
			}
			if samePublicationContainerStage(original, changed) != (mode == "current" || mode == "new-current-task-version") {
				t.Fatal("original stage or completion facts changed", mode)
			}
		})
	}
}

func TestPublicationContainerOwnedFileHashCancelsWithContextUnawareGuardData(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	body := bytes.Repeat([]byte("opaque original container DATA"), 10000)
	receipt, err := staging.WriteUnpublishedFile(context.Background(), root, "container.enc", func(dst io.Writer) error { _, err := dst.Write(body); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "before", "during", "limit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			if mode == "before" {
				cancel()
			}
			guard := func(context.Context) error {
				checks++
				if mode == "during" && checks == 3 {
					cancel()
				}
				return nil
			}
			limit := MaxPublicationArtifactBytes
			if mode == "limit" {
				limit = receipt.Size - 1
			}
			actual, err := hashOwnedPublicationContainer(ctx, root, receipt.Name, limit, guard)
			if mode == "current" {
				if err != nil || actual != receipt {
					t.Fatal("actual local physical bytes lost", err)
				}
				return
			}
			if err == nil || actual.Name != "" || actual.SHA256 != "" {
				t.Fatal("cancelled or oversized file yielded complete facts")
			}
		})
	}
}
