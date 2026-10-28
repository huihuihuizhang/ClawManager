package domain

import (
	"context"
	"database/sql"
	"testing"
)

func TestVerifierRejectsWildcardSchemaGrants(t *testing.T) {
	for _, wildcards := range []bool{true, false} {
		for _, escaped := range []bool{true, false} {
			name := "cm_drill_fixture"
			if escaped {
				name = `cm\_drill\_fixture`
			}
			state := &memoryDB{wildcardGrants: wildcards, grants: "GRANT SELECT ON `" + name + "`.* TO 'verifier'@'%'"}
			db := sql.OpenDB(connector{state})
			conn, e := db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			e = checkSelectOnly(context.Background(), conn, "cm_drill_fixture")
			conn.Close()
			db.Close()
			if (wildcards == escaped) != (e == nil) {
				t.Fatalf("wildcards=%v escaped=%v: %v", wildcards, escaped, e)
			}
		}
	}
}
