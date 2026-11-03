package systembackupkekadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func TestSQLCensusMinIOAndSignerAuthorityDisposition(t *testing.T) {
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
	wanted := map[string]bool{
		"system_backup_minio_owner_heads":       false,
		"system_backup_minio_owner_grants":      false,
		"system_backup_minio_owner_refs":        false,
		"system_backup_signing_resource_heads":  false,
		"system_backup_signing_resource_grants": false,
	}
	for _, object := range registry.Objects {
		if object.Backup == "mysql_dump" && excluded[object.Name] {
			t.Fatal("business source excluded", object.Name)
		}
		if found, relevant := wanted[object.Name]; relevant {
			if found || object.Category != "system_backup" || object.Classification != "secret" || object.Backup != "metadata_only" || object.Restore != "reference_only" || !excluded[object.Name] {
				t.Fatal("authority disposition differs from reviewed canonical policy", object.Name)
			}
			wanted[object.Name] = true
		}
	}
	for name, found := range wanted {
		if !found {
			t.Fatal("authority absent from reviewed canonical policy", name)
		}
		if _, selected := sources[name]; selected {
			t.Fatal("authorization state entered lifecycle source partition", name)
		}
		for _, unknown := range []string{name + "_history", name + "_future", "unreviewed_" + name} {
			if excluded[unknown] {
				t.Fatal("unknown authority table inherited an exclusion", unknown)
			}
			if _, selected := sources[unknown]; selected {
				t.Fatal("unknown authority table acquired a lifecycle partition", unknown)
			}
		}
	}
	// This pins the entire PRE-supersede set of actual sources and their four
	// partitions. Adding control exclusions may not move, remove or add a source.
	// Wire: each ASCII table name, NUL, partition, LF, in table-name order.
	if len(sources) != 49 {
		t.Fatal("original lifecycle source membership changed", len(sources))
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		if excluded[name] {
			t.Fatal("original source became excluded", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name + "\x00" + string(sources[name]) + "\n"))
	}
	if hex.EncodeToString(h.Sum(nil)) != "ce45e366f64cc9a41f793213f73dca3f825cbcd56cd1c88ecc2edcc0d73c8fa8" {
		t.Fatal("original complete source-to-partition mapping changed")
	}
}
