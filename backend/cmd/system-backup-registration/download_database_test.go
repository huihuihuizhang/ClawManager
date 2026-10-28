package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestDownloadDatabaseIsSeparateLazyPool(t *testing.T) {
	dir := t.TempDir()
	basePath, downloadPath := filepath.Join(dir, "registration-dsn"), filepath.Join(dir, "download-dsn")
	base, err := mysql.ParseDSN("registration_writer:PRIVATE@tcp(127.0.0.1:1)/download_test")
	if err != nil {
		t.Fatal(err)
	}
	writeDownloadFixtureFile(t, basePath, []byte(base.FormatDSN()))
	writeDownloadFixtureFile(t, downloadPath, []byte("download_reader:PRIVATE@tcp(127.0.0.1:1)/download_test"))
	db, account, err := openDownloadDatabase(downloadPath, basePath, base)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if account != "download_reader" || db.Stats().OpenConnections != 0 || db.Stats().MaxOpenConnections != 8 {
		t.Fatal("pool opened a connection or lost the separate account boundary")
	}
}

func TestDownloadDatabaseRejectsAliasingAndUnsafeAccounts(t *testing.T) {
	for _, mode := range []string{"same_path", "hardlink", "same_account", "root", "base_root", "base_empty_user", "base_multi", "multi", "wrong_database", "empty_database", "invalid_dsn", "missing", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			basePath, downloadPath := filepath.Join(dir, "registration-dsn"), filepath.Join(dir, "download-dsn")
			base, err := mysql.ParseDSN("registration_writer:PRIVATE@tcp(127.0.0.1:1)/download_test")
			if err != nil {
				t.Fatal(err)
			}
			writeDownloadFixtureFile(t, basePath, []byte(base.FormatDSN()))
			dsn := "download_reader:PRIVATE@tcp(127.0.0.1:1)/download_test"
			switch mode {
			case "same_path":
				downloadPath = basePath
			case "hardlink":
				if err := os.Link(basePath, downloadPath); err != nil {
					t.Fatal(err)
				}
			case "same_account":
				dsn = base.FormatDSN()
			case "root":
				dsn = "root:PRIVATE@tcp(127.0.0.1:1)/download_test"
			case "base_root":
				base.User = "root"
			case "base_empty_user":
				base.User = ""
			case "base_multi":
				base.MultiStatements = true
			case "multi":
				dsn += "?multiStatements=true"
			case "wrong_database":
				dsn = "download_reader:PRIVATE@tcp(127.0.0.1:1)/other"
			case "empty_database":
				dsn = "download_reader:PRIVATE@tcp(127.0.0.1:1)/"
			case "invalid_dsn":
				dsn = "PRIVATE-invalid-dsn"
			case "oversize":
				dsn = strings.Repeat("PRIVATE", 2000)
			}
			if mode != "same_path" && mode != "hardlink" && mode != "missing" {
				writeDownloadFixtureFile(t, downloadPath, []byte(dsn))
			}
			db, _, err := openDownloadDatabase(downloadPath, basePath, base)
			if db != nil {
				db.Close()
			}
			if err != errDownloadDeployment || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe DSN accepted or private material exposed", mode)
			}
		})
	}
}

func TestDownloadDeploymentRejectsBorrowingRegistrationPool(t *testing.T) {
	c, base, model, path := downloadDeploymentFixture(t)
	raw, _ := json.Marshal(c)
	pin := writeDownloadFixtureFile(t, path, raw)
	for _, shared := range []bool{false, true} {
		db := base.DB
		if !shared {
			db = nil
		}
		if d, err := loadDownloadDeployment(context.Background(), base, db, path, pin, c.RegistrationRuntimeSHA256, c.DatabaseUser); err == nil {
			d.Close()
			t.Fatal("missing or shared pool accepted")
		}
	}
	if model.queries != 0 || model.base.queries != 0 || model.connections != 0 || model.base.connections != 0 {
		t.Fatal("rejected pool reached SQL")
	}
}
