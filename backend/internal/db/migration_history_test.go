package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// Synthetic provenance is confined to tests; these bytes are NOT recovered
// historical SQL, an operator approval, or evidence for the live installation.
func historyFixture(t *testing.T) (migrationHistoryDocument, fstest.MapFS) {
	t.Helper()
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	doc := migrationHistoryDocument{Version: 1, ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "clawmanager", CatalogSHA256: catalog.Hash,
		ReviewedBy: "synthetic-test-only", ReviewReference: "fixture:review", Decision: "retain_history_without_replay", Pending: []string{reviewedRuntimeMigration}}
	for _, name := range catalog.Filenames {
		if name != reviewedRuntimeMigration {
			doc.ExpectedApplied = append(doc.ExpectedApplied, name)
		}
	}
	sources := fstest.MapFS{}
	for _, name := range []string{"045_update_workbuddy_windows_runtime.sql", "046_add_instance_pvc_name.sql", "047_add_instance_runtime_variant.sql"} {
		data := []byte("-- synthetic test source, never execute: " + name + "\n")
		h := sha256.Sum256(data)
		doc.Historical = append(doc.Historical, migrationHistorySource{Filename: name, SQLSHA256: hex.EncodeToString(h[:]), ProvenanceReference: "fixture:original-build"})
		doc.ExpectedApplied = append(doc.ExpectedApplied, name)
		sources[name] = &fstest.MapFile{Data: data}
	}
	return doc, sources
}

func encodeHistory(t *testing.T, doc migrationHistoryDocument) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return raw, hex.EncodeToString(h[:])
}

func TestHistoricalReviewRejectsUnprovenOrExpandedScope(t *testing.T) {
	for _, name := range []string{"valid", "missing-source", "source-changed", "manifest-changed", "missing-review", "missing-provenance", "wrong-decision", "wrong-catalog", "wrong-database", "duplicate-history", "current-file-alias", "path-traversal", "missing-applied", "duplicate-applied", "expanded-pending", "unknown-field", "trailing-json"} {
		t.Run(name, func(t *testing.T) {
			doc, sources := historyFixture(t)
			switch name {
			case "missing-source":
				delete(sources, doc.Historical[0].Filename)
			case "source-changed":
				sources[doc.Historical[0].Filename].Data = []byte("changed")
			case "missing-review":
				doc.ReviewReference = ""
			case "missing-provenance":
				doc.Historical[0].ProvenanceReference = ""
			case "wrong-decision":
				doc.Decision = "assume_renumbered"
			case "wrong-catalog":
				doc.CatalogSHA256 = strings.Repeat("0", 64)
			case "wrong-database":
				doc.Database = "other/schema"
			case "duplicate-history":
				doc.Historical = append(doc.Historical, doc.Historical[0])
			case "current-file-alias":
				doc.Historical[0].Filename = "050_update_workbuddy_windows_runtime.sql"
			case "path-traversal":
				doc.Historical[0].Filename = "../045_old.sql"
			case "missing-applied":
				doc.ExpectedApplied = doc.ExpectedApplied[1:]
			case "duplicate-applied":
				doc.ExpectedApplied[0] = doc.ExpectedApplied[1]
			case "expanded-pending":
				doc.Pending = append(doc.Pending, "079_add_a_owned_chat_and_risk_tables.sql")
			}
			raw, digest := encodeHistory(t, doc)
			if name == "manifest-changed" {
				raw = append(raw, ' ')
			}
			if name == "unknown-field" || name == "trailing-json" {
				if name == "unknown-field" {
					raw = append([]byte(`{"allow_any":true,`), raw[1:]...)
				} else {
					raw = append(raw, []byte(` {}`)...)
				}
				h := sha256.Sum256(raw)
				digest = hex.EncodeToString(h[:])
			}
			_, err := ParseMigrationHistoryReview(raw, digest, sources)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected review result: %v", err)
			}
		})
	}
}

func TestReviewedInstalledLedgerOnlyApplies080AndRetainsHistory(t *testing.T) {
	for _, name := range []string{"apply-runtime", "retry-applied", "unreviewed-ledger", "extra-entry", "missing-current", "missing-username-migration", "missing-historical", "ledger-missing", "capture-active", "wrong-live-server", "wrong-review-target"} {
		t.Run(name, func(t *testing.T) {
			doc, sources := historyFixture(t)
			raw, digest := encodeHistory(t, doc)
			review, err := ParseMigrationHistoryReview(raw, digest, sources)
			if err != nil {
				t.Fatal(err)
			}
			target := MigrationTarget{ServerUUID: doc.ServerUUID, Database: doc.Database, CatalogSHA256: doc.CatalogSHA256, HistoryReview: review}
			state := &migrationPinState{server: doc.ServerUUID, database: doc.Database, applied: append([]string(nil), doc.ExpectedApplied...)}
			catalog, catalogErr := EmbeddedMigrationCatalog()
			if catalogErr != nil {
				t.Fatal(catalogErr)
			}
			if len(state.applied) != len(catalog.Filenames)-1+len(doc.Historical) {
				t.Fatal("fixture must retain all reviewed entries")
			}
			switch name {
			case "retry-applied":
				state.applied = append(state.applied, reviewedRuntimeMigration)
			case "unreviewed-ledger":
				target.HistoryReview = nil
			case "extra-entry":
				state.applied = append(state.applied, "999_unreviewed.sql")
			case "missing-current":
				state.applied = state.applied[1:]
			case "missing-username-migration":
				for i, filename := range state.applied {
					if filename == "063_unique_usernames.sql" {
						state.applied = append(state.applied[:i], state.applied[i+1:]...)
						break
					}
				}
			case "missing-historical":
				state.applied = state.applied[:len(state.applied)-1]
			case "ledger-missing":
				state.ledgerMissing = true
			case "capture-active":
				state.activeGate = 1
			case "wrong-live-server":
				state.server = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			case "wrong-review-target":
				target.Database = "different_installation"
			}
			before := append([]string(nil), state.applied...)
			database := sql.OpenDB(migrationPinConnector{state})
			defer database.Close()
			err = ApplyPinnedMigrations(context.Background(), database, target)
			ok := name == "apply-runtime" || name == "retry-applied"
			if (err == nil) != ok {
				t.Fatalf("unexpected apply result: %v", err)
			}
			if !reflect.DeepEqual(before, state.applied) {
				t.Fatal("historical ledger changed")
			}
			if name == "wrong-review-target" {
				if state.connections != 0 {
					t.Fatal("mismatched review opened database")
				}
				return
			}
			if state.connections != 1 || state.identities != 1 || state.releases != 2 {
				t.Fatal("lost same-connection lock/identity")
			}
			if name == "apply-runtime" {
				if len(state.writes) != 5 || state.gates != 5 {
					t.Fatal("expected exactly four runtime DDL statements plus one ledger insert")
				}
				for _, q := range state.writes[:4] {
					if !strings.HasPrefix(q, "CREATE TABLE IF NOT EXISTS system_backup_") {
						t.Fatal("historical SQL replayed")
					}
				}
				if !strings.HasPrefix(state.writes[4], "INSERT INTO schema_migrations") {
					t.Fatal("ledger rewrite")
				}
				if !reflect.DeepEqual(state.recorded, []string{reviewedRuntimeMigration}) {
					t.Fatal("did not record exactly 080")
				}
			} else if len(state.writes) != 0 {
				t.Fatal("rejection or successful retry wrote SQL")
			}
		})
	}
}

func TestPreUsernameHistoryReviewCannotAuthorizeMergedCatalog(t *testing.T) {
	doc, sources := historyFixture(t)
	// The prior 93-file build and its 95-entry installed ledger are historical
	// inputs. Re-hashing the review must not turn them into current authority.
	doc.CatalogSHA256 = "68794bddc66b9809fae57a111778dd8ad53e2a5a5bfb218108295c8d751b1564"
	for i, filename := range doc.ExpectedApplied {
		if filename == "063_unique_usernames.sql" {
			doc.ExpectedApplied = append(doc.ExpectedApplied[:i], doc.ExpectedApplied[i+1:]...)
			break
		}
	}
	raw, digest := encodeHistory(t, doc)
	if _, err := ParseMigrationHistoryReview(raw, digest, sources); err == nil {
		t.Fatal("old catalog review authorized a new username migration")
	}
	// Even updating the catalog pin cannot authorize an extra pending migration.
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	doc.CatalogSHA256 = catalog.Hash
	raw, digest = encodeHistory(t, doc)
	if _, err := ParseMigrationHistoryReview(raw, digest, sources); err == nil {
		t.Fatal("080-only review silently accepted a missing username migration")
	}
}
