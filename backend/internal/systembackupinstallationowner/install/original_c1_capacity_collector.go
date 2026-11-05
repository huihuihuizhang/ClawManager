package install

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"io"
	"reflect"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// This is the original capacity measurement, transported from MySQL's exact
// readonly data-volume inode. No owner/admin password, task key or issuer is
// loaded. Every sample rechecks the pinned source files and SELECT-only grants.
type OriginalCapacityCollectorInputs struct {
	Version                                  string
	CapacityConfig, CapacityDSN, CapacityTLS BootstrapSourceFilePin
}

func RunOriginalCapacityCollector(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-c1-native-inputs capacity-collect", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("inputs-file", "", "")
	digest := f.String("inputs-sha256", "", "")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	input := BootstrapSourceFilePin{File: *file, SHA256: *digest}
	raw, e := readBootstrapSourcePin(input, 65536)
	var in OriginalCapacityCollectorInputs
	if e != nil || decodeExact(raw, &in) != nil || in.Version != "original-select-only-capacity-collector-inputs.v1" {
		return 1
	}
	configRaw, e := readBootstrapSourcePin(in.CapacityConfig, 65536)
	var config sec.CapacityCollectorConfig
	if e != nil || decodeExact(configRaw, &config) != nil || config.Validate() != nil {
		return 1
	}
	tlsRaw, e := readBootstrapSourcePin(in.CapacityTLS, 65536)
	var material mysqltls.Material
	if e != nil || decodeExact(tlsRaw, &material) != nil || !material.Selected() {
		return 1
	}
	dsn, e := readBootstrapSourcePin(in.CapacityDSN, 16384)
	if e != nil {
		return 1
	}
	defer clear(dsn)
	cfg, e := mysql.ParseDSN(strings.TrimSpace(string(dsn)))
	if e != nil || cfg.User != config.User || cfg.DBName != config.Database || cfg.Net != "tcp" || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || cfg.TLS != nil || cfg.TLSConfig != "" || material.Apply(cfg) != nil {
		return 1
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
	cfg.Logger = silentDatabaseSourceLogger{}
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return 1
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	recheck := func() error {
		for _, pin := range []BootstrapSourceFilePin{input, in.CapacityConfig, in.CapacityDSN, in.CapacityTLS} {
			b, err := readBootstrapSourcePin(pin, 65536)
			clear(b)
			if err != nil {
				return ErrInstall
			}
		}
		current, err := material.TLSConfig()
		if err != nil || current == nil || !reflect.DeepEqual(current.RootCAs.Subjects(), cfg.TLS.RootCAs.Subjects()) {
			return ErrInstall
		}
		return nil
	}
	encoder := json.NewEncoder(out)
	for {
		probe, done := context.WithTimeout(ctx, 4*time.Second)
		if recheck() != nil {
			done()
			return 1
		}
		report, err := sec.CollectPinnedRegistrationCapacity(probe, db, config)
		if err == nil {
			err = recheck()
		}
		done()
		if err != nil || encoder.Encode(report) != nil {
			return 1
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(time.Second):
		}
	}
}
