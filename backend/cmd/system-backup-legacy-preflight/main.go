// system-backup-legacy-preflight verifies a disposable copy of the observed
// 97-migration installation. It performs no conversion or application writes.
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

func privateFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("legacy preflight input unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > limit {
		return nil, errors.New("legacy preflight input invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("legacy preflight input invalid")
	}
	return raw, nil
}

func run(ctx context.Context, dsnFile, inventoryFile string, output io.Writer) error {
	return runPhase(ctx, dsnFile, inventoryFile, "", output)
}

func runPhase(ctx context.Context, dsnFile, inventoryFile, phase string, output io.Writer) error {
	rawDSN, err := privateFile(dsnFile, 16384)
	if err != nil {
		return err
	}
	defer clear(rawDSN)
	config, err := mysql.ParseDSN(strings.TrimSpace(string(rawDSN)))
	if err != nil || config.DBName == "" || config.MultiStatements || config.AllowAllFiles {
		return errors.New("legacy preflight database configuration invalid")
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
	inventory, err := privateFile(inventoryFile, 2_000_000)
	if err != nil {
		return err
	}
	pool, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		return errors.New("legacy preflight database unavailable")
	}
	defer pool.Close()
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	if phase != "" {
		proof, err := db.ProveLegacySiteCopyRows(ctx, pool, inventory, phase)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(proof)
	}
	report, err := db.PreflightLegacySiteCopy(ctx, pool, inventory)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}

func main() {
	dsn := flag.String("dsn-file", "", "private DSN for a cm_import_<32hex> isolated copy")
	inventory := flag.String("source-inventory-file", "", "byte-pinned direct site inventory JSON")
	budget := flag.Duration("timeout", 5*time.Minute, "read-only preflight deadline (maximum 10m)")
	phase := flag.String("row-proof-phase", "", "optional isolated-copy row proof: before or after")
	flag.Parse()
	if *dsn == "" || *inventory == "" || *budget <= 0 || *budget > 10*time.Minute || (*phase != "" && *phase != "before" && *phase != "after") {
		fmt.Fprintln(os.Stderr, "dsn-file, source-inventory-file and bounded timeout are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *budget)
	defer cancel()
	if err := runPhase(ctx, *dsn, *inventory, *phase, os.Stdout); err != nil {
		// SQL and DSN errors may contain credentials or row data.
		fmt.Fprintln(os.Stderr, "legacy isolated-copy preflight rejected; no migration authorized")
		os.Exit(1)
	}
}
