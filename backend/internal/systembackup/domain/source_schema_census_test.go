package domain

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestCensusGeneratorBindsLiteralSchemaGrantSemantics(t *testing.T) {
	for _, partial := range []bool{false, true} {
		body, err := SchemaCensusProjection("source_with_underscore", "owner@127.0.0.1", partial)
		if err != nil {
			t.Fatal(err)
		}
		pattern := "source_with_underscore"
		if !partial {
			pattern = strings.ReplaceAll(pattern, "_", `\_`)
		}
		if !strings.Contains(body, "BINARY TABLE_SCHEMA=0x"+hex.EncodeToString([]byte(pattern))) || !strings.Contains(body, "TABLE_SCHEMA='source_with_underscore'") || !strings.Contains(body, "CENSUS_INCOMPLETE") || !strings.Contains(body, "mysql.global_grants") || !strings.Contains(body, "mysql.role_edges") {
			t.Fatal("source/grant/canary semantics lost")
		}
	}
	for _, database := range []string{"", "source`.*", "source;DROP TABLE users", "foreign/db"} {
		if _, err := SchemaCensusProjection(database, "owner@127.0.0.1", true); err == nil {
			t.Fatal("unsafe census source identifier")
		}
	}
}
