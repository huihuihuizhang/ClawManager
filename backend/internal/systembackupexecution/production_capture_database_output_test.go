package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestDatabaseSourceIssueRejectsReservedSequenceOutputsBeforeNativeSigningComponent(t *testing.T) {
	for _, target := range []string{"future-bundle", "future-metadata", "redis-grant", "objects-grant"} {
		t.Run(target, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f := newMaterialProducerComponent(t, ctx)
			s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
			if err != nil {
				t.Fatal(err)
			}
			output := map[string]string{"future-bundle": s.core.CaptureModules.Path, "future-metadata": s.materials.Discovery.GrantFile, "redis-grant": s.materials.Redis.GrantFile, "objects-grant": s.materials.Objects.GrantFile}[target]
			before, beforeErr := os.ReadFile(output)
			if target == "future-bundle" || target == "future-metadata" {
				if !os.IsNotExist(beforeErr) {
					t.Fatal("future reserved output must be genuinely absent before DB issue", beforeErr)
				}
			} else if beforeErr != nil || len(before) == 0 {
				t.Fatal("Begin's exact original Redis/Object grant missing", beforeErr)
			}
			directory := filepath.Dir(f.definitionFile)
			definition := install.DatabaseSourceIssueDefinition{Version: install.DatabaseSourceIssueVersion, OriginalDefinitionSHA256: f.definitionSHA, Account: "component_source@original-host", Service: "original-mysql", ServiceUID: "original-mysql-uid", Port: 3306, Source: worker.FormalSourceMount{GrantFile: filepath.Join(directory, "distinct-database-grant.json"), Issuer: s.materials.Discovery.Issuer, CredentialFile: filepath.Join(directory, "original-db-source-credential.json"), CredentialSHA256: hash([]byte("original-controlled-credential"))}}
			file := filepath.Join(directory, "original-db-source-issue.json")
			write := func() string {
				t.Helper()
				raw, err := json.Marshal(definition)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = jsoncanonicalizer.Transform(raw)
				if err != nil || os.WriteFile(file, raw, 0600) != nil {
					t.Fatal("exact JCS original issue input", err)
				}
				return hash(raw)
			}
			// The same private declaration passes the pure coordinate check with
			// a distinct output. This is not a native source permission claim.
			if s.databaseSourceOutputDisjoint(file, write()) != nil {
				t.Fatal("valid disjoint coordinate rejected before collision mutation")
			}
			definition.Source.GrantFile = output
			pin := write()
			queries, writes := f.model.queries.Load(), f.model.executions.Load()
			if result, err := s.IssueDatabaseSourceGrant(ctx, file, pin); err == nil || result.Source.GrantSHA256 != "" || !s.failed {
				t.Fatal("reserved output issued a DB grant or left sequence reusable", err)
			}
			// Native issuer/signing is after owner Recheck in the actual straight
			// line route. No owner SQL query means that route was not reached.
			if f.model.queries.Load() != queries || f.model.executions.Load() != writes {
				t.Fatal("reserved output reached owner/native issuance work")
			}
			after, afterErr := os.ReadFile(output)
			if target == "future-bundle" || target == "future-metadata" {
				if !os.IsNotExist(afterErr) {
					t.Fatal("reserved future output was written", afterErr)
				}
			} else if afterErr != nil || !bytes.Equal(before, after) {
				t.Fatal("original worker source grant overwritten", afterErr)
			}
			if _, err := s.IssueDatabaseSourceGrant(ctx, file, pin); err == nil || f.model.queries.Load() != queries {
				t.Fatal("same-context retry revived a failed output reservation")
			}
		})
	}
}
