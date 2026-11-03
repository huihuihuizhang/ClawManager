package db

import (
	"strings"
	"testing"
)

func TestSigningResourceAuthorityMigrationIsIndependentAndHasNoSeed(t *testing.T) {
	const name = "136_backup_v2_signing_resource_authority.sql"
	raw, err := embeddedMigrations.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	statements := splitSQLStatements(string(raw))
	if len(statements) != 2 {
		t.Fatal("expected only two new signer resource tables")
	}
	for _, statement := range statements {
		if !strings.HasPrefix(strings.TrimSpace(statement), "CREATE TABLE") || strings.Contains(statement, "system_backup_installation_owner") || strings.Contains(statement, "system_backup_v2_backups") {
			t.Fatal("signer resource migration seeded or borrowed capture/task authority")
		}
	}
	for _, required := range []string{"ENUM('acceptance_record','catalog_record')", "PRIMARY KEY(installation_id,enrollment_id,authority_id,purpose)", "PRIMARY KEY(installation_id,enrollment_id,authority_id,purpose,grant_id,record_revision)", "ON DELETE RESTRICT", "OCTET_LENGTH(signed_head)<=65536", "OCTET_LENGTH(signed_record)<=262144", "OCTET_LENGTH(signature)=64", "head_sha256=LOWER(SHA2(signed_head,256))", "record_sha256=LOWER(SHA2(signed_record,256))"} {
		if !strings.Contains(string(raw), required) {
			t.Fatal("missing normative signer resource constraint", required)
		}
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range catalog.Filenames {
		found = found || file == name
	}
	if !found {
		t.Fatal("signer resource migration absent from reviewed catalog")
	}
}
