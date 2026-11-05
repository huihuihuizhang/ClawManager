package systembackupcontroller

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestOriginalMinIOMetadataReadProfileKeepsActorColumnsFinite(t *testing.T) {
	grants, err := MinIOMetadataReadGrantSQL("capture", "reader", "127.0.0.1", false, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range grants {
		grants[i] = strings.TrimSuffix(grants[i], ";")
	}
	validate := func(g []string) error { return ValidateMinIOMetadataReadGrants("capture", g, true, true, true) }
	if err = validate(grants); err != nil {
		t.Fatal(err)
	}
	pool := sql.OpenDB(grantProbeConnector{user: "reader@127.0.0.1", role: "NONE", grants: grants})
	defer pool.Close()
	if err = (SQLMinIOMetadataReadGrantProbe{DB: pool, Schema: "capture", User: "reader", Runtime: true, ProviderPermits: true, Publication: true}).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if validateControllerGrants("capture", grants, controlEvidenceTableGrants(true, true, true)) == nil {
		t.Fatal("original strict profile accepted extension")
	}
	var grouped []string
	for _, g := range grants {
		if !strings.Contains(g, " ON `capture`.`users` TO ") {
			grouped = append(grouped, g)
		}
	}
	grouped = append(grouped, "GRANT SELECT (`auth_provider`, `id`, `is_active`, `role`, `username`) ON `capture`.`users` TO 'reader'@'127.0.0.1'")
	if err = validate(grouped); err != nil {
		t.Fatal("MySQL grouped column grants rejected", err)
	}
	for _, column := range minioActorColumns {
		var missing []string
		for _, g := range grants {
			if !strings.Contains(g, "SELECT (`"+column+"`) ON") {
				missing = append(missing, g)
			}
		}
		if validate(missing) == nil {
			t.Fatal("missing actor column accepted", column)
		}
	}
	for _, table := range minioMetadataTables {
		var missing []string
		for _, g := range grants {
			if !strings.Contains(g, ".`"+table+"` TO") {
				missing = append(missing, g)
			}
		}
		if validate(missing) == nil {
			t.Fatal("missing metadata SELECT accepted", table)
		}
	}
	for _, extra := range []string{
		"GRANT SELECT ON `capture`.`users` TO 'reader'@'127.0.0.1'",
		"GRANT SELECT (`password_hash`) ON `capture`.`users` TO 'reader'@'127.0.0.1'",
		"GRANT SELECT (`password`) ON `capture`.`users` TO 'reader'@'127.0.0.1'",
		"GRANT UPDATE ON `capture`.`system_backup_minio_owner_heads` TO 'reader'@'127.0.0.1'",
		"GRANT INSERT ON `capture`.`system_backup_minio_owner_grants` TO 'reader'@'127.0.0.1'",
		"GRANT DELETE ON `capture`.`system_backup_minio_owner_refs` TO 'reader'@'127.0.0.1'",
		"GRANT SELECT (`id`) ON `other`.`users` TO 'reader'@'127.0.0.1'",
		"GRANT SELECT (`id`) ON `capture`.`users` TO 'reader'@'127.0.0.1' WITH GRANT OPTION",
	} {
		if validate(append(append([]string(nil), grants...), extra)) == nil {
			t.Fatal("excess privilege accepted", extra)
		}
	}
}
