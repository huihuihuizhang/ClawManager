package systembackupkekadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSQLCensusFramingPreservesNullEmptyAndBoundaries(t *testing.T) {
	digest := func(values ...[]byte) string {
		h := sha256.New()
		for _, v := range values {
			censusFrame(h, v)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	seen := map[string]bool{}
	for _, values := range [][][]byte{{nil}, {[]byte{}}, {[]byte("ab"), []byte("c")}, {[]byte("a"), []byte("bc")}, {[]byte("a"), nil}, {[]byte("a"), []byte{}}} {
		h := digest(values...)
		if seen[h] {
			t.Fatal("ambiguous source-row frame")
		}
		seen[h] = true
	}
}

func TestSQLCensusInstallationOwnerAuthorityDisposition(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/schema-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Objects []struct {
			Name           string `json:"name"`
			Category       string `json:"category"`
			Classification string `json:"data_classification"`
			Backup         string `json:"backup_strategy"`
			Restore        string `json:"restore_strategy"`
		} `json:"objects"`
	}
	if json.Unmarshal(raw, &registry) != nil || len(registry.Objects) == 0 {
		t.Fatal("canonical source policy unavailable")
	}
	sources, excluded := sqlCensusSources()
	wanted := map[string]bool{"system_backup_installation_owner_heads": false, "system_backup_installation_owner_grants": false}
	for _, object := range registry.Objects {
		if object.Backup == "mysql_dump" && excluded[object.Name] {
			t.Fatal("business table excluded from original source census", object.Name)
		}
		if found, relevant := wanted[object.Name]; relevant {
			if found || object.Category != "system_backup" || object.Classification != "secret" || object.Backup != "metadata_only" || object.Restore != "reference_only" || !excluded[object.Name] {
				t.Fatal("installation authority disposition differs from canonical policy", object.Name)
			}
			wanted[object.Name] = true
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatal("installation authority missing from canonical policy", name)
		}
		if _, source := sources[name]; source {
			t.Fatal("installation authority rows selected as lifecycle source", name)
		}
		if excluded[name+"_history"] {
			t.Fatal("unreviewed same-prefix table excluded", name)
		}
	}
	for name := range sources {
		if excluded[name] {
			t.Fatal("original lifecycle source became excluded", name)
		}
	}
}
