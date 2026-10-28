package systembackupsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func capacitySourceFixture(t *testing.T) CapacityCollectorConfig {
	t.Helper()
	return CapacityCollectorConfig{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "test_capacity", User: "capacity_reader", DataDir: t.TempDir(), Tables: []string{"audit_logs", "system_backup_v2_configs", "system_backup_v2_backups"}}
}
func TestCapacityExactDirectGrants(t *testing.T) {
	c := capacitySourceFixture(t)
	grants := []string{"GRANT USAGE ON *.* TO 'capacity_reader'@'localhost'", "GRANT SELECT ON `test_capacity`.`audit_logs` TO 'capacity_reader'@'localhost'", "GRANT SELECT ON `test_capacity`.`system_backup_v2_configs` TO 'capacity_reader'@'localhost'", "GRANT SELECT ON `test_capacity`.`system_backup_v2_backups` TO 'capacity_reader'@'localhost'"}
	if ValidateCapacityGrants(c, grants) != nil {
		t.Fatal("exact reader grants rejected")
	}
	var backtickGrants []string
	for _, grant := range grants {
		backtickGrants = append(backtickGrants, strings.ReplaceAll(grant, "'", "`"))
	}
	if ValidateCapacityGrants(c, backtickGrants) != nil {
		t.Fatal("MySQL backtick grantee rejected")
	}
	for _, extra := range []string{
		"GRANT SELECT ON `test_capacity`.* TO 'capacity_reader'@'localhost'",
		"GRANT SELECT, UPDATE ON `test_capacity`.`audit_logs` TO 'capacity_reader'@'localhost'",
		"GRANT SELECT ON `other_db`.`audit_logs` TO 'capacity_reader'@'localhost'",
		"GRANT SELECT ON `test_capacity`.`users` TO 'capacity_reader'@'localhost'",
		"GRANT 'reader_role'@'%' TO 'capacity_reader'@'localhost'",
		grants[1] + " WITH GRANT OPTION",
	} {
		if ValidateCapacityGrants(c, append(append([]string{}, grants...), extra)) == nil {
			t.Fatal("overbroad/unknown grant accepted")
		}
	}
	if ValidateCapacityGrants(c, grants[:2]) == nil {
		t.Fatal("missing table accepted")
	}
	if ValidateCapacityGrants(c, grants[:3]) == nil {
		t.Fatal("backup task allocation visibility missing")
	}
}
func TestCapacitySourcePinnedConfiguration(t *testing.T) {
	c := capacitySourceFixture(t)
	file := filepath.Join(t.TempDir(), "source.json")
	raw, _ := json.Marshal(c)
	hash := sha256.Sum256(raw)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapacityCollectorConfig(file, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapacityCollectorConfig(file, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	for _, mutate := range []func(*CapacityCollectorConfig){
		func(c *CapacityCollectorConfig) { c.Tables = c.Tables[:2] },
		func(c *CapacityCollectorConfig) { c.ServerUUID = "" },
		func(c *CapacityCollectorConfig) { c.User = "root" },
		func(c *CapacityCollectorConfig) { c.DataDir = "relative/path" },
		func(c *CapacityCollectorConfig) { c.Tables = append(c.Tables, c.Tables[0]) },
		func(c *CapacityCollectorConfig) { c.Tables = append(c.Tables, "users") },
		func(c *CapacityCollectorConfig) { c.Tables = c.Tables[:1] },
	} {
		changed := c
		changed.Tables = append([]string{}, c.Tables...)
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid source accepted")
		}
	}
}
func TestCapacityReportAtomicReplacementAndCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	for _, data := range []string{`{"version":1}`, `{"version":2}`} {
		if err := WriteCapacityReport(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatal("incomplete replacement")
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0640 {
				t.Fatal("report must be group-readable only")
			}
		}
	}
	// Rename over a directory fails, and must remove the private temporary file.
	if WriteCapacityReport(dir, []byte("bad")) == nil {
		t.Fatal("directory destination accepted")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "report.json" {
		t.Fatal("temporary file leaked")
	}
	if WriteCapacityReport("relative-report.json", []byte("bad")) == nil {
		t.Fatal("relative report accepted")
	}
}
