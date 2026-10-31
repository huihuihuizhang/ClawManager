package domain

import (
	"sort"
	"strings"
	"testing"
)

func TestFiniteBusinessSourceGrantMatrix(t *testing.T) {
	tables := BusinessCaptureTables()
	if !sort.StringsAreSorted(tables) || len(tables) < 60 {
		t.Fatal("reviewed business rules missing")
	}
	var grants []string
	for _, name := range tables {
		grants = append(grants, "GRANT SELECT ON `source`.`"+name+"` TO 'reader'@'127.0.0.1'")
	}
	for _, mode := range []string{"valid", "missing", "wildcard", "global", "control", "unknown", "write", "grant-option", "duplicate", "other-database", "role"} {
		t.Run(mode, func(t *testing.T) {
			actual := append([]string{}, grants...)
			switch mode {
			case "missing":
				actual = actual[1:]
			case "wildcard":
				actual = []string{"GRANT SELECT ON `source`.* TO 'reader'@'127.0.0.1'"}
			case "global":
				actual = append(actual, "GRANT SELECT ON *.* TO 'reader'@'127.0.0.1'")
			case "control":
				actual = append(actual, "GRANT SELECT ON `source`.`system_backup_v2_configs` TO 'reader'@'127.0.0.1'")
			case "unknown":
				actual = append(actual, "GRANT SELECT ON `source`.`future_business_table` TO 'reader'@'127.0.0.1'")
			case "write":
				actual[0] = strings.Replace(actual[0], "SELECT ON", "SELECT, UPDATE ON", 1)
			case "grant-option":
				actual[0] += " WITH GRANT OPTION"
			case "duplicate":
				actual = append(actual, actual[0])
			case "other-database":
				actual[0] = strings.Replace(actual[0], "`source`.", "`other`.", 1)
			case "role":
				actual = append(actual, "GRANT `source_reader_role`@`%` TO `reader`@`127.0.0.1`")
			}
			if err := ValidateBusinessSourceGrants("source", actual); (err == nil) != (mode == "valid") {
				t.Fatal("finite source role mismatch", err)
			}
		})
	}
}
