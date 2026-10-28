package control

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"clawreef/internal/systembackup/worker"
)

type DatabaseConfig struct {
	Database       worker.DatabaseSpec `json:"database"`
	CredentialFile string              `json:"credential_file"`
}

func readJSONFile(path string, v any) error {
	if !filepath.IsAbs(path) {
		return ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return ErrNotReady
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return ErrInvalid
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}

// OpenControlDatabase does not migrate and never opens the application source
// configuration. The required cm_backup_control_ prefix prevents accidental
// reuse as the business restore target. Credentials are mounted files, not CLI.
func OpenControlDatabase(ctx context.Context, path string) (*sql.DB, error) {
	var cfg DatabaseConfig
	if readJSONFile(path, &cfg) != nil {
		return nil, ErrNotReady
	}
	if !strings.HasPrefix(cfg.Database.Name, "cm_backup_control_") {
		return nil, ErrInvalid
	}
	var credential worker.DatabaseCredential
	if readJSONFile(cfg.CredentialFile, &credential) != nil {
		return nil, ErrNotReady
	}
	defer clear(credential.Password)
	database, e := worker.OpenDatabase(&cfg.Database, &credential)
	if e != nil {
		return nil, ErrNotReady
	}
	var name, uuid string
	if database.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&name, &uuid) != nil || name != cfg.Database.Name || uuid != cfg.Database.ServerUUID {
		database.Close()
		return nil, ErrNotReady
	}
	database.SetMaxOpenConns(12)
	database.SetMaxIdleConns(4)
	return database, nil
}
