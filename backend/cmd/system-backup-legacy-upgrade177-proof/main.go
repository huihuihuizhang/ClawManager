// system-backup-legacy-upgrade177-proof reads the original schema or proves
// every original column in an isolated full177 migration experiment. No DDL.
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
	"regexp"
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
	// Full99 row proofs are independently bounded by the CLI's <=10m context.
	// Keep original source/preflight reads unchanged; a large snapshot MAX/COUNT
	// query must not inherit the shorter unrelated socket timeout.
	if phase == "before" || phase == "after" || phase == "original-before" || phase == "original-after" {
		config.ReadTimeout = 10 * time.Minute
	}
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
	if phase == "source" || phase == "copy-inventory" {
		database := "clawmanager"
		if phase == "copy-inventory" {
			if !regexp.MustCompile(`^cm_import_[0-9a-f]{32}$`).MatchString(config.DBName) {
				return errors.New("legacy preflight requires an isolated cm_import_<32hex> database")
			}
			database = config.DBName
		}
		observed, err := db.CaptureBackupLegacyInventory(ctx, pool, "f1f5f76a-95f5-11f1-b08e-366835b4a029", database, "5d303453289c28d0b8abf7abab8b3abe15ad605079feb01e599d919b53068903")
		if err != nil {
			return err
		}
		raw, err := db.EncodeBackupLegacyInventory(observed)
		if err != nil {
			return err
		}
		_, err = output.Write(raw)
		return err
	}
	if phase != "" {
		var proof db.LegacySite177RowProof
		var err error
		if phase == "original-before" || phase == "original-after" {
			if config.DBName != "clawmanager" {
				return errors.New("legacy original readproof requires original database")
			}
			proof, err = db.ProveLegacySiteOriginalRows198(ctx, pool, inventory, strings.TrimPrefix(phase, "original-"))
		} else {
			proof, err = db.ProveLegacySiteCopyRows177(ctx, pool, inventory, phase)
		}
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
	dsn := flag.String("dsn-file", "", "private DSN; copy phases require cm_import_<32hex>, explicit readonly original phases require clawmanager")
	inventory := flag.String("source-inventory-file", "", "byte-pinned direct site inventory JSON")
	budget := flag.Duration("timeout", 5*time.Minute, "read-only preflight deadline (maximum 10m)")
	phase := flag.String("phase", "", "read-only phase: source, copy-inventory, before, after, original-before or original-after; never executes DDL")
	flag.Parse()
	if *dsn == "" || *inventory == "" || *budget <= 0 || *budget > 10*time.Minute || (*phase != "source" && *phase != "copy-inventory" && *phase != "before" && *phase != "after" && *phase != "original-before" && *phase != "original-after") {
		fmt.Fprintln(os.Stderr, "dsn-file, source-inventory-file and bounded timeout are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *budget)
	defer cancel()
	if err := runPhase(ctx, *dsn, *inventory, *phase, os.Stdout); err != nil {
		// SQL and DSN errors may contain credentials or row data.
		_ = json.NewEncoder(os.Stderr).Encode(safeFailure(*phase, err))
		os.Exit(1)
	}
}
