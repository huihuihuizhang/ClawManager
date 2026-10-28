// Dedicated HTTPS listener for the D registration boundary. Credentials are
// read from mounted files; no secrets or raw driver/provider errors are logged.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "registration startup/check/listener/shutdown failed")
		os.Exit(1)
	}
}
func run() error {
	runtimePath := flag.String("runtime", "", "SHA-pinned runtime JSON path")
	downloadPath := flag.String("download-runtime", "", "optional SHA-pinned evidence download deployment JSON")
	liveReadyURL := flag.String("check-live-url", "", "check-activation only: HTTPS loopback download readiness URL")
	probeServerName := flag.String("probe-server-name", "", "check-live-url only: mounted server certificate hostname")
	bootstrapConfig := flag.String("check-bootstrap-config", "", "offline ConfigValues structure check only; no provider admission or activation")
	check := flag.Bool("check-activation", false, "read-only registration runtime check against active config; not full configuration admission")
	capacityReport := flag.String("collect-capacity", "", "write capacity reports from the MySQL data-volume sidecar")
	capacityConfig := flag.String("capacity-config", "", "SHA-pinned capacity source configuration")
	checkCapacity := flag.Bool("check-capacity-source", false, "read-only check of capacity source identity, grants and data mount")
	inspectSQL := flag.Bool("inspect-sql-evidence", false, "read-only SQL identity/grants/metadata from a public stdin request and an existing mounted DSN")
	address := flag.String("listen", "127.0.0.1:9443", "HTTPS listen address")
	flag.Parse()
	if *inspectSQL {
		var supplied []string
		flag.Visit(func(f *flag.Flag) { supplied = append(supplied, f.Name) })
		if !fieldInspectionFlags(supplied, flag.NArg()) {
			return errFieldSQLInspection
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return runFieldSQLInspection(ctx, os.Stdin, os.Stdout, os.Getenv)
	}
	capacityMode := *capacityReport != "" || *checkCapacity
	if err := validateDownloadMode(downloadMode{runtime: *runtimePath, deployment: *downloadPath, liveURL: *liveReadyURL, serverName: *probeServerName, digest: os.Getenv("SYSTEM_BACKUP_DOWNLOAD_RUNTIME_SHA256"), dsn: os.Getenv("SYSTEM_BACKUP_DOWNLOAD_DSN_FILE"), capacity: capacityMode, bootstrap: *bootstrapConfig != "", check: *check}); err != nil {
		return err
	}
	if flag.NArg() != 0 || (*checkCapacity && *capacityReport != "") || (capacityMode && (*capacityConfig == "" || *runtimePath != "" || *check || *bootstrapConfig != "")) || (!capacityMode && *capacityConfig != "") {
		return fmt.Errorf("conflicting modes or missing capacity pins")
	}
	var collector security.CapacityCollectorConfig
	if capacityMode {
		var e error
		collector, e = security.LoadCapacityCollectorConfig(*capacityConfig, os.Getenv("SYSTEM_BACKUP_CAPACITY_CONFIG_SHA256"))
		if e != nil {
			return e
		}
	}
	if *bootstrapConfig != "" {
		if *check || *capacityReport != "" || *runtimePath != "" || flag.NArg() != 0 {
			return fmt.Errorf("conflicting check modes")
		}
		file, err := os.Open(*bootstrapConfig)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 262144 {
			return fmt.Errorf("invalid config file")
		}
		raw, err := io.ReadAll(io.LimitReader(file, 262145))
		if err != nil || len(raw) > 262144 {
			return fmt.Errorf("invalid config file")
		}
		config, err := security.DecodeBootstrapConfig(raw)
		if err != nil {
			return err
		}
		fmt.Printf("PASS configuration-structure=true config_sha256=%s provider-admission=not-run configuration-mutated=false human-mfa-acceptance=not-run\n", config.SHA256())
		return nil
	}
	dsn, err := os.ReadFile(os.Getenv("SYSTEM_BACKUP_REGISTRATION_DSN_FILE"))
	if err != nil {
		return err
	}
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(dsn)))
	for i := range dsn {
		dsn[i] = 0
	}
	if err != nil {
		return err
	}
	if (*downloadPath != "" || *liveReadyURL != "") && (cfg.User == "" || cfg.MultiStatements || strings.EqualFold(cfg.User, "root")) {
		return errDownloadDeployment
	}
	if capacityMode && (cfg.DBName != collector.Database || cfg.User != collector.User || cfg.MultiStatements) {
		return fmt.Errorf("capacity database mismatch")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = false
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	database, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}
	defer database.Close()
	database.SetMaxOpenConns(8)
	database.SetMaxIdleConns(4)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if capacityMode {
		if !*checkCapacity && !filepath.IsAbs(*capacityReport) {
			return fmt.Errorf("absolute report path required")
		}
		for {
			probe, done := context.WithTimeout(ctx, 5*time.Second)
			report, e := security.CollectPinnedRegistrationCapacity(probe, database, collector)
			done()
			if e != nil {
				return e
			}
			if *checkCapacity {
				return json.NewEncoder(os.Stdout).Encode(report)
			}
			data, e := json.Marshal(report)
			if e != nil {
				return e
			}
			if e = security.WriteCapacityReport(*capacityReport, data); e != nil {
				return e
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
	}
	app, err := security.LoadRegistrationApplication(database, *runtimePath, os.Getenv("SYSTEM_BACKUP_REGISTRATION_RUNTIME_SHA256"))
	if err != nil {
		return err
	}
	var download *loadedDownload
	closeDownload := true
	defer func() {
		if closeDownload {
			download.Close()
		}
	}()
	if *downloadPath != "" {
		downloadDB, downloadAccount, openErr := openDownloadDatabase(os.Getenv("SYSTEM_BACKUP_DOWNLOAD_DSN_FILE"), os.Getenv("SYSTEM_BACKUP_REGISTRATION_DSN_FILE"), cfg)
		if openErr != nil {
			return openErr
		}
		defer downloadDB.Close()
		download, err = loadDownloadDeployment(ctx, app, downloadDB, *downloadPath, os.Getenv("SYSTEM_BACKUP_DOWNLOAD_RUNTIME_SHA256"), os.Getenv("SYSTEM_BACKUP_REGISTRATION_RUNTIME_SHA256"), downloadAccount)
		if err != nil {
			return err
		}
	}
	if *check {
		probe, done := context.WithTimeout(ctx, 15*time.Second)
		defer done()
		if err = app.CheckActivation(probe); err != nil {
			return err
		}
		if *liveReadyURL != "" {
			if err = checkLiveDownloadReadiness(probe, *liveReadyURL, *probeServerName, os.Getenv("SYSTEM_BACKUP_REGISTRATION_TLS_CERT_FILE"), os.Getenv("SYSTEM_BACKUP_DOWNLOAD_RUNTIME_SHA256")); err != nil {
				return err
			}
			fmt.Println("PASS live-download-readiness=true configuration-and-journal-only=true download-journal-opened-by-probe=false provider-admission=not-run production-approval=no")
		}
		fmt.Println("PASS registration-runtime-check=true full-config-admission=not-run configuration-mutated=false human-mfa-acceptance=not-run")
		if download != nil {
			fmt.Println("PASS download-runtime-composition=true startup-grants-pins-match=yes provider-admission=not-run human-mfa-acceptance=not-run production-approval=no")
		}
		return nil
	}
	handler, err := mountDownloadHTTP(app.API, download)
	if err != nil {
		return err
	}
	server := security.RegistrationHTTPServer(*address, app.API)
	server.Handler = handler
	// A forced close may leave handlers alive. Only a confirmed drain permits
	// erasing their keys; otherwise return failure and let process exit own them.
	closeDownload = false
	drained, err := serveRegistrationHTTP(ctx, server, func() error {
		return server.ListenAndServeTLS(os.Getenv("SYSTEM_BACKUP_REGISTRATION_TLS_CERT_FILE"), os.Getenv("SYSTEM_BACKUP_REGISTRATION_TLS_KEY_FILE"))
	}, 10*time.Second)
	closeDownload = drained
	return err
}
