package schemaobjects_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"testing"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/schemaobjects"
)

func TestRetainedLegacyPolicyMatchesReviewedOriginalMigration(t *testing.T) {
	raw, err := os.ReadFile("testdata/original198-retained-renames.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "b97754e940e7ce0267aecc0ae06e6afa75aa243e0698002238dd295f4eff7ab0" {
		t.Fatal("reviewed original migration fixture changed")
	}
	pairs := regexp.MustCompile("`([^`]+)` TO `(dlegacy_[^`]+)`").FindAllSubmatch(raw, -1)
	declared := schemaobjects.RetainedOriginalLegacyControlTables()
	if len(pairs) != 35 || len(declared) != len(pairs) {
		t.Fatal("retained policy differs from the reviewed 35 original renames")
	}
	excluded, actual := map[string]bool{}, map[string]bool{}
	for _, name := range schemaobjects.ExcludedControlTables() {
		excluded[name] = true
	}
	for _, pair := range pairs {
		name := string(pair[2])
		if actual[name] || !excluded[name] {
			t.Fatal("missing or duplicate original migration target", name)
		}
		actual[name] = true
		policy, ok := sb.Policy(name)
		if !ok || policy.Category != "system_backup" || policy.BackupStrategy != "metadata_only" || policy.RestoreStrategy != "reference_only" {
			t.Fatal("original retained control table has inconsistent export policy", name)
		}
	}
	for _, name := range declared {
		if !actual[name] {
			t.Fatal("unreviewed alias entered the control policy", name)
		}
	}
	for _, name := range domain.BusinessCaptureTables() {
		if excluded[name] {
			t.Fatal("business capture table was excluded", name)
		}
	}
	for _, name := range []string{"dlegacy_99_unreviewed", "dlegacy_01_users"} {
		if _, ok := sb.Policy(name); ok || excluded[name] {
			t.Fatal("prefix exclusion accepted an unreviewed table", name)
		}
	}
}
