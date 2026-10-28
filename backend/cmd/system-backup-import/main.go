// system-backup-import converts only a disposable, explicitly named copy.
// It neither starts the application nor operates on Runtime or source storage.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"clawreef/internal/db"
	"github.com/go-sql-driver/mysql"
)

func run(ctx context.Context, path string, output io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("import credential unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return errors.New("import credential invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("import credential invalid")
	}
	defer clear(raw)
	config, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || config.DBName == "" || config.MultiStatements || config.AllowAllFiles {
		return errors.New("import database configuration invalid")
	}
	config.ParseTime = true
	config.Loc = time.UTC
	config.Timeout = 5 * time.Second
	config.ReadTimeout = 2 * time.Minute
	config.WriteTimeout = 2 * time.Minute
	config.Logger = &mysql.NopLogger{}
	if config.Params == nil {
		config.Params = map[string]string{}
	}
	config.Params["time_zone"] = "'+00:00'"
	pool, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		return errors.New("import database unavailable")
	}
	defer pool.Close()
	pool.SetMaxOpenConns(2)
	pool.SetMaxIdleConns(1)
	report, err := db.ImportBackupCopy(ctx, pool)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}

func main() {
	path := flag.String("dsn-file", "", "mounted DSN for a cm_import_<32hex> isolated copy")
	budget := flag.Duration("timeout", 10*time.Minute, "total import deadline (maximum 30m)")
	flag.Parse()
	if *path == "" || *budget <= 0 || *budget > 30*time.Minute {
		fmt.Fprintln(os.Stderr, "dsn-file and bounded timeout are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *budget)
	defer cancel()
	if err := run(ctx, *path, os.Stdout); err != nil {
		// SQL/DSN errors can contain credentials or source data. Keep the public
		// CLI failure closed; the retained journal shows the last durable stage.
		fmt.Fprintln(os.Stderr, "isolated backup import failed; retained copy and import journal require inspection")
		os.Exit(1)
	}
}
