package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDatabaseTLSDefaultYAMLAndEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"DB_TLS_CA_FILE", "DB_TLS_CA_SHA256", "DB_TLS_SERVER_NAME"} {
		t.Setenv(name, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.TLSCAFile != "" || cfg.Database.TLSCASHA256 != "" || cfg.Database.TLSServerName != "" {
		t.Fatal("legacy default unexpectedly requires TLS")
	}
	if err = os.Mkdir("configs", 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("database:\n  tlsCAFile: /owner/original-ca.pem\n  tlsCASHA256: original-pin\n  tlsServerName: mysql.original.invalid\n")
	if err = os.WriteFile(filepath.Join("configs", "dev.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load()
	if err != nil || cfg.Database.TLSCAFile != "/owner/original-ca.pem" || cfg.Database.TLSCASHA256 != "original-pin" || cfg.Database.TLSServerName != "mysql.original.invalid" {
		t.Fatal("YAML TLS selection lost", err)
	}
	t.Setenv("DB_TLS_CA_FILE", "/owner/selected-ca.pem")
	t.Setenv("DB_TLS_CA_SHA256", "selected-pin")
	t.Setenv("DB_TLS_SERVER_NAME", "selected.original.invalid")
	cfg, err = Load()
	if err != nil || cfg.Database.TLSCAFile != "/owner/selected-ca.pem" || cfg.Database.TLSCASHA256 != "selected-pin" || cfg.Database.TLSServerName != "selected.original.invalid" {
		t.Fatal("environment did not override YAML TLS", err)
	}
}
func TestLoadDatabaseTLSRejectsPartialSelection(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"DB_TLS_CA_FILE", "DB_TLS_CA_SHA256", "DB_TLS_SERVER_NAME"} {
		t.Setenv(name, "")
	}
	t.Setenv("DB_TLS_CA_FILE", "/owner/original-ca.pem")
	if cfg, err := Load(); err == nil || cfg != nil {
		t.Fatal("partial explicit TLS selection accepted")
	}
}
