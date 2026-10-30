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
	"runtime"
	"strings"
	"time"

	"clawreef/internal/systembackup/staging"
	execution "clawreef/internal/systembackupexecution"
	"github.com/go-sql-driver/mysql"
)

func main() {
	mode := flag.String("mode", "inventory", "inventory, preflight, prune, probe-init, probe-hold, probe-worker, probe-clean")
	config := flag.String("config", "", "pinned deployment file")
	digest := flag.String("config-sha256", "", "independent deployment SHA256")
	dsn := flag.String("dsn-file", "", "private SELECT-only control database DSN file")
	apply := flag.Bool("apply", false, "delete only proven orphans; prune defaults to dry-run")
	age := flag.Duration("minimum-age", 24*time.Hour, "minimum orphan age, at least one hour")
	path := flag.String("root", "", "probe-only mounted staging root")
	id := flag.String("run-id", "", "unique probe ID")
	flag.Parse()
	limit := 2 * time.Minute
	if strings.HasPrefix(*mode, "probe-") {
		limit = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	if err := run(ctx, *mode, *config, *digest, *dsn, *apply, *age, *path, *id); err != nil {
		if strings.HasPrefix(*mode, "probe-") {
			// Probe operations only touch synthetic run-owned files, never DSNs or backup data.
			fmt.Fprintf(os.Stderr, "probe diagnostic: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "seal custody operation rejected; retain probe output and inspect deployment pins/ownership")
		os.Exit(1)
	}
}

func run(ctx context.Context, mode, config, digest, dsn string, apply bool, age time.Duration, path, id string) error {
	if mode == "probe-worker" {
		if apply {
			return staging.ErrFile
		}
		if err := staging.ProbeSealWorker(ctx, path, id); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"run_id": id, "worker_isolation": true, "cross_process_lock": true})
	}
	if mode == "probe-init" || mode == "probe-hold" || mode == "probe-clean" || mode == "probe-verify" {
		if apply {
			return staging.ErrFile
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			return err
		}
		defer root.Close()
		switch mode {
		case "probe-init":
			err = staging.ProbeSealInit(root, id)
		case "probe-hold":
			err = staging.ProbeSealHold(ctx, root, id)
		case "probe-clean":
			err = staging.ProbeSealClean(root, id)
		case "probe-verify":
			err = staging.ProbeSealVerify(root, id)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"run_id": id, "mode": mode, "ok": true})
	}
	if (mode != "inventory" && mode != "preflight" && mode != "prune") || (apply && mode != "prune") || age < time.Hour {
		return staging.ErrFile
	}
	cfg, err := execution.LoadDeploymentConfig(config, digest)
	if err != nil {
		return err
	}
	if mode == "preflight" || mode == "prune" {
		pool, err := openControlDB(dsn, cfg.SourceDatabase)
		if err != nil {
			return err
		}
		defer pool.Close()
		maintenance := execution.SealMaintenance{DB: pool, Installation: cfg.InstallationID, ServerUUID: cfg.SourceServerUUID, Database: cfg.SourceDatabase}
		if err := maintenance.Preflight(ctx); err != nil {
			return err
		}
		if mode == "preflight" {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "mode": "preflight"})
		}
		return runPrune(ctx, cfg, pool, age, apply)
	}
	parent, err := os.OpenRoot(cfg.StagingDirectory)
	if err != nil {
		return err
	}
	defer parent.Close()
	root, err := staging.OpenSealCustody(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	policy := staging.CustodyPolicy{Installation: cfg.InstallationID, MaxBytes: cfg.SealCustodyMaxBytes}
	if mode == "inventory" {
		inventory, e := staging.InventoryCustody(ctx, root, policy)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(inventory)
	}
	return staging.ErrFile
}

func runPrune(ctx context.Context, cfg execution.DeploymentConfig, pool *sql.DB, age time.Duration, apply bool) error {
	parent, err := os.OpenRoot(cfg.StagingDirectory)
	if err != nil {
		return err
	}
	defer parent.Close()
	root, err := staging.OpenSealCustody(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	policy := staging.CustodyPolicy{Installation: cfg.InstallationID, MaxBytes: cfg.SealCustodyMaxBytes}
	result, err := staging.PruneCustody(ctx, root, policy, time.Now().Add(-age), apply, execution.SealMaintenance{DB: pool, Installation: cfg.InstallationID, ServerUUID: cfg.SourceServerUUID, Database: cfg.SourceDatabase})
	// Even a failed pass may have removed earlier independently proven orphans.
	if e := json.NewEncoder(os.Stdout).Encode(map[string]any{"apply": apply, "complete": err == nil, "items": result}); e != nil {
		return e
	}
	return err
}

func openControlDB(path, database string) (*sql.DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8192 || (runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("private database input invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	cfg, err := mysql.ParseDSN(string(raw))
	if err != nil || cfg.DBName != database {
		return nil, errors.New("database scope invalid")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = false
	cfg.AllowAllFiles = false
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.Logger = &mysql.NopLogger{}
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	return db, nil
}
