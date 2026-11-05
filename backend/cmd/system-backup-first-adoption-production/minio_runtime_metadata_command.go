package main

import (
	"bytes"
	"clawreef/internal/mysqltls"
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/go-sql-driver/mysql"
	"io"
	"strings"
	"time"
)

func runMinIORuntimeMetadata(ctx context.Context, owner *install.Installer, password []byte, enrollment install.EnrollmentPin, raw []byte, get func(string) string, out io.Writer, query bool) int {
	var in struct {
		Version    string
		Owner      install.OriginalMinIORuntimeMetadataInputs
		RuntimeDSN install.BootstrapSourceFilePin
		RuntimeTLS mysqltls.Material
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != "original-minio-runtime-metadata-owner-inputs.v1" {
		return 1
	}
	secret, e := readPin(in.RuntimeDSN.File, in.RuntimeDSN.SHA256, 16384)
	if e != nil {
		return 1
	}
	defer clear(secret)
	cfg, e := mysql.ParseDSN(strings.TrimSpace(string(secret)))
	if e != nil || cfg.Net != "tcp" || cfg.User == "root" || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || cfg.TLSConfig != "" || cfg.TLS != nil || in.RuntimeTLS.Apply(cfg) != nil {
		return 1
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return 1
	}
	pool := sql.OpenDB(connector)
	defer pool.Close()
	pool.SetMaxOpenConns(2)
	pool.SetMaxIdleConns(1)
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var receipt install.OriginalMinIORuntimeMetadataReceipt
	if query {
		receipt, e = owner.QueryOriginalMinIORuntimeMetadataRead(active, pool, password, enrollment, in.Owner)
	} else {
		private, pe := readPin(get("issuer-private-file"), get("issuer-private-sha256"), 64)
		if pe != nil {
			return 1
		}
		defer clear(private)
		receipt, e = owner.IssueOriginalMinIORuntimeMetadataRead(active, pool, password, enrollment, in.Owner, private)
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	if e != nil {
		return 3
	}
	return 0
}
