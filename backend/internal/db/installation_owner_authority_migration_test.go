package db

import (
	"strings"
	"testing"
)

func TestInstallationOwnerAuthorityMigrationIsEmbeddedWithoutSeedApproval(t *testing.T) {
	const name = "134_backup_v2_installation_owner_authority.sql"
	raw, e := embeddedMigrations.ReadFile("migrations/" + name)
	if e != nil {
		t.Fatal(e)
	}
	if len(splitSQLStatements(string(raw))) != 2 {
		t.Fatal("want head and grant tables")
	}
	for _, s := range []string{"CREATE TABLE system_backup_installation_owner_heads", "CREATE TABLE system_backup_installation_owner_grants", "ON DELETE RESTRICT", "OCTET_LENGTH(signature)=64", "head_sha256=LOWER(SHA2(signed_head,256))", "record_sha256=LOWER(SHA2(signed_record,256))"} {
		if !strings.Contains(string(raw), s) {
			t.Fatal("missing source integrity constraint", s)
		}
	}
	for _, statement := range splitSQLStatements(string(raw)) {
		if !strings.HasPrefix(strings.TrimSpace(statement), "CREATE TABLE") {
			t.Fatal("migration mutates approvals")
		}
	}
	catalog, e := EmbeddedMigrationCatalog()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range catalog.Filenames {
		found = found || n == name
	}
	if !found {
		t.Fatal("not embedded")
	}
}
