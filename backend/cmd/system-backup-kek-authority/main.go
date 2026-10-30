// Offline original-installation authority importer. It never signs candidate
// configuration or reads committed config; signing belongs to the installation
// owner, whose public key is pinned by the deployment independently.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	"github.com/go-sql-driver/mysql"
)

var errInput = errors.New("original KEK authority import rejected")

func bounded(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, errInput
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errInput
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || int64(len(b)) > limit {
		return nil, errInput
	}
	return b, nil
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("system-backup-kek-authority", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	installation := flags.String("installation-id", "", "deployment-pinned original installation")
	server := flags.String("server-uuid", "", "deployment-pinned MySQL server UUID")
	database := flags.String("database", "", "deployment-pinned MySQL database")
	dsn := flags.String("dsn-file", "", "owner-writer MySQL credential file")
	key := flags.String("issuer-public-key-file", "", "deployment-pinned raw 32-byte Ed25519 public key")
	record := flags.String("record-file", "", "original owner signed record bytes")
	signature := flags.String("signature-file", "", "raw 64-byte original owner signature")
	expected := flags.Uint64("expected-row-version", 0, "CAS row version; 0 creates a new mapping")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *installation == "" || *server == "" || *database == "" {
		return errInput
	}
	pub, err := bounded(*key, 32)
	if err != nil || len(pub) != 32 {
		return errInput
	}
	raw, err := bounded(*record, 65536)
	if err != nil {
		return errInput
	}
	sig, err := bounded(*signature, 64)
	if err != nil || len(sig) != 64 {
		return errInput
	}
	secret, err := bounded(*dsn, 8192)
	if err != nil {
		return errInput
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(secret)))
	if err != nil || cfg.DBName != *database || cfg.MultiStatements || cfg.AllowAllFiles {
		return errInput
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return errInput
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	writer, err := adapter.NewInstallationAuthorityWriter(db, *installation, reg.DatabaseIdentity{ServerUUID: *server, Database: *database}, pub)
	if err != nil {
		return errInput
	}
	version, err := writer.Put(ctx, raw, sig, *expected)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "authority_record_committed", "row_version": version})
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		os.Stderr.WriteString("authority import rejected or commit unconfirmed; inspect original authority history before retry\n")
		os.Exit(1)
	}
}
