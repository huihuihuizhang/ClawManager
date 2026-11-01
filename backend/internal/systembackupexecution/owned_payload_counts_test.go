package systembackupexecution

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"

	"clawreef/internal/systembackup/worker"
	w "clawreef/internal/systembackupwire"
)

// The existing local C fixture supplies actual encrypted archive bytes. Its
// local test key is not a current SQL/worker/publisher permission. These cases
// prove count derivation/EOF behavior, not capture or manifest eligibility.
func TestOwnedPayloadCountsRequireCompleteOriginalArchive(t *testing.T) {
	for _, mode := range []string{"current", "candidate-size", "gzip-footer"} {
		t.Run(mode, func(t *testing.T) {
			source, _, _, invocation, candidate, keys := formalObserverFixture(t, func(root *os.Root, _ *worker.Invocation) {
				if err := root.MkdirAll("docs", 0700); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{"data.bin": "data", "docs/report.txt": "observed"} {
					if err := root.WriteFile(name, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
			encrypted, err := source.ReadFile(candidate.Ciphertext.Name)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := source.ReadFile(candidate.Envelope.Name)
			if err != nil {
				t.Fatal(err)
			}
			var compressed []byte
			spec := w.StreamSpec{Request: invocation.ProviderKey.Request, Path: invocation.Request.ArtifactName, MaxPlaintextBytes: invocation.Request.MaxCompressedBytes, MaxFrames: invocation.FormalCapture.MaxFrames}
			if _, err = w.InspectWrappedStream(context.Background(), spec, envelope, bytes.NewReader(encrypted), keys, func(src io.Reader) error {
				var err error
				compressed, err = io.ReadAll(src)
				return err
			}); err != nil {
				t.Fatal("original complete C fixture", err)
			}
			defer clear(compressed)
			if mode == "candidate-size" {
				candidate.Bytes--
			} else if mode == "gzip-footer" {
				compressed = compressed[:len(compressed)-8]
			}
			counts := ownedPayloadCounts{Version: "stale", Complete: true, Items: 900}
			err = inspectOwnedBusinessPayloadCounts(context.Background(), invocation, candidate, bytes.NewReader(compressed), &counts)
			if mode != "current" {
				if err == nil || counts.Complete || counts.Version != "" || counts.Items != 0 || counts.ContentBytes != 0 {
					t.Fatal("invalid/incomplete payload retained successful counts", mode, err, counts)
				}
				return
			}
			if err != nil || !counts.Complete || counts.Version != "system-backup-inert-payload-counts.v1" || counts.Kind != "archive_entry_bytes" || counts.ArchiveEntries != candidate.Files || counts.ContentBytes != candidate.Bytes || counts.ContentBytes != int64(len(`{"fixture":"original private conversation"}`)+len("data")+len("observed")) {
				t.Fatal("counts did not come from complete original archive entries", err, counts)
			}
		})
	}
}

// Named count-mapping DATA. These rows have no current C/SQL authority; they
// exercise the exact gate used by the real complete-capture producer above.
func TestPublicationInputRejectsUnavailablePayloadCountsData(t *testing.T) {
	for _, mode := range []string{"complete", "description-admin", "description-wrong-operation", "description-wrong-domain", "description-imposter", "description-with-missing-business-counts", "unavailable", "default-zero", "wrong-unit", "negative", "sql-omission"} {
		t.Run(mode, func(t *testing.T) {
			operations := []string{"capture-database", "capture-source-redis", "capture-skill-objects", "capture-workspace", "capture-deployment-resources", "capture-secret-bundle"}
			kinds := []string{"sql_raw_cell_bytes", "redis_key_dump_group_bytes", "object_payload_bytes", "archive_entry_bytes", "kubernetes_captured_json_bytes", "kubernetes_captured_json_bytes"}
			parts := make([]publicationVerifiedPart, 0, 6)
			for index, operation := range operations {
				counts := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Kind: kinds[index], Complete: true}
				if index == 0 {
					counts.Items, counts.ContentBytes = 1, 4
					counts.SQLTables = []ownedSQLTableCount{{Table: "named_sql_DATA", Rows: 1, CellBytes: 4}}
				}
				parts = append(parts, publicationVerifiedPart{Part: operation, Operation: operation, RequestedPart: publicationRequestedPart(operation), Counts: counts})
			}
			switch mode {
			case "description-admin", "description-wrong-operation", "description-wrong-domain", "description-with-missing-business-counts":
				part := publicationVerifiedPart{Part: cd.Part, Operation: cd.Operation}
				if mode == "description-wrong-operation" {
					part.Operation = "capture-database"
				}
				if mode == "description-wrong-domain" {
					part.RequestedPart = "mysql"
				}
				if mode == "description-with-missing-business-counts" {
					parts[0].Counts = ownedPayloadCounts{}
				}
				parts = append(parts, part)
			case "description-imposter":
				parts = append(parts, publicationVerifiedPart{Part: "foreign_description_DATA", Operation: cd.Operation})
			case "unavailable":
				parts[3].Counts.Complete = false
				parts[3].Counts.Kind = "skill_workspace_counts_unavailable"
			case "default-zero":
				parts[2].Counts = ownedPayloadCounts{}
			case "wrong-unit":
				parts[1].Counts.Kind = "object_payload_bytes"
			case "negative":
				parts[5].Counts.Items = -1
			case "sql-omission":
				parts[0].Counts.SQLTables = nil
			}
			if got := publicationPayloadCountsComplete(parts); got != (mode == "complete" || mode == "description-admin") {
				t.Fatal("publication input accepted incomplete/unknown count metadata", mode, got)
			}
		})
	}
}
