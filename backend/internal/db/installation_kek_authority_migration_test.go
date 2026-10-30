package db

import (
	"strings"
	"testing"
)

func TestInstallationKEKAuthorityMigrationIsVersioned(t *testing.T) {
	const name = "128_backup_installation_kek_authority.sql"
	raw, err := embeddedMigrations.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	statements := splitSQLStatements(string(raw))
	if len(statements) != 2 {
		t.Fatalf("want current and history tables, got %d statements", len(statements))
	}
	for _, s := range []string{"system_backup_installation_kek_authority (", "system_backup_installation_kek_authority_history (", "UNIQUE KEY sb_install_kek_revision", "REFERENCES system_backup_v2_kek_fences", "COLLATE ascii_bin", "OCTET_LENGTH(signature)=64"} {
		if !strings.Contains(string(raw), s) {
			t.Fatalf("migration missing %s", s)
		}
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range catalog.Filenames {
		if n == name {
			found = true
		}
	}
	if !found {
		t.Fatal("authority migration absent from deployment catalog")
	}
}
