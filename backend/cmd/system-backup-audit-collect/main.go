// Read-only observer of one download operation. No runtime authority is granted.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
)

//go:embed audit.sql
var auditSQL string

const identitySQL = "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),CONNECTION_ID(),DATE_FORMAT(UTC_TIMESTAMP(6),'%Y-%m-%dT%H:%i:%s.%fZ')"

var rejected = errors.New("download audit collection rejected")
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

type transport struct {
	Mode       string `json:"mode"`
	ServerName string `json:"server_name"`
	CASHA256   string `json:"ca_sha256"`
}
type request struct {
	SchemaVersion string    `json:"schema_version"`
	ServerUUID    string    `json:"server_uuid"`
	Database      string    `json:"database"`
	CurrentUser   string    `json:"current_user"`
	CurrentRole   string    `json:"current_role"`
	OperationID   string    `json:"operation_public_id"`
	ReceiptSHA256 string    `json:"http_receipt_sha256"`
	Transport     transport `json:"transport"`
}
type identity struct {
	ServerUUID   string `json:"server_uuid"`
	Database     string `json:"database"`
	CurrentUser  string `json:"current_user"`
	CurrentRole  string `json:"current_role"`
	ConnectionID int64  `json:"connection_id"`
	SQLTime      string `json:"sql_time"`
}
type collection struct {
	SchemaVersion string   `json:"schema_version"`
	RequestSHA256 string   `json:"request_sha256"`
	ReceiptSHA256 string   `json:"http_receipt_sha256"`
	QuerySHA256   string   `json:"query_sha256"`
	OperationID   string   `json:"operation_public_id"`
	Before        identity `json:"identity_before"`
	After         identity `json:"identity_after"`
	ReadOnly      bool     `json:"readonly"`
	RolledBack    bool     `json:"rolled_back"`
	ExportSHA256  string   `json:"audit_export_sha256"`
	ExportBase64  string   `json:"audit_export_base64"`
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Reject duplicate/unknown/missing members, invalid UTF-8 and multiple values.
func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, rejected
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, rejected
	}
	result := map[string]json.RawMessage{}
	for dec.More() {
		t, e := dec.Token()
		k, ok := t.(string)
		if e != nil || !ok {
			return nil, rejected
		}
		if _, exists := result[k]; exists {
			return nil, rejected
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil || (k != "resource_id" && bytes.Equal(bytes.TrimSpace(v), []byte("null"))) {
			return nil, rejected
		}
		result[k] = v
	}
	if _, err = dec.Token(); err != nil {
		return nil, rejected
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, rejected
	}
	if len(result) != len(keys) {
		return nil, rejected
	}
	for _, k := range keys {
		if _, ok := result[k]; !ok {
			return nil, rejected
		}
	}
	return result, nil
}
func decodeRequest(raw []byte) (request, error) {
	var r request
	members, err := object(raw, "schema_version", "server_uuid", "database", "current_user", "current_role", "operation_public_id", "http_receipt_sha256", "transport")
	if err != nil {
		return r, rejected
	}
	if _, err = object(members["transport"], "mode", "server_name", "ca_sha256"); err != nil || json.Unmarshal(raw, &r) != nil {
		return request{}, rejected
	}
	if r.SchemaVersion != "a_live_download_audit_request.v1" || !uuidPattern.MatchString(r.ServerUUID) || !namePattern.MatchString(r.Database) ||
		!strings.HasPrefix(r.OperationID, "sop_") || !uuidPattern.MatchString(strings.TrimPrefix(r.OperationID, "sop_")) || !hashPattern.MatchString(r.ReceiptSHA256) ||
		len(r.CurrentUser) < 3 || len(r.CurrentUser) > 256 || strings.Count(r.CurrentUser, "@") != 1 || strings.HasPrefix(r.CurrentUser, "@") || strings.HasSuffix(r.CurrentUser, "@") || strings.ContainsAny(r.CurrentUser, "\x00\r\n") ||
		r.CurrentRole == "" || len(r.CurrentRole) > 1024 || strings.ContainsAny(r.CurrentRole, "\x00\r\n") {
		return request{}, rejected
	}
	switch r.Transport.Mode {
	case "unix":
		if r.Transport.ServerName != "" || r.Transport.CASHA256 != "" {
			return request{}, rejected
		}
	case "tls":
		if !hashPattern.MatchString(r.Transport.CASHA256) || !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`).MatchString(r.Transport.ServerName) {
			return request{}, rejected
		}
	default:
		return request{}, rejected
	}
	return r, nil
}
func readFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, rejected
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, rejected
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, rejected
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, rejected
	}
	return raw, nil
}
func observerConfig(raw, ca []byte, r request) (*mysql.Config, error) {
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || cfg.DBName != r.Database || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || cfg.User == "" {
		return nil, rejected
	}
	// Mounted credentials remain private. Do not execute arbitrary DSN SET options.
	for k, v := range cfg.Params {
		if k != "time_zone" || v != "'+00:00'" {
			return nil, rejected
		}
	}
	if r.Transport.Mode == "unix" {
		if cfg.Net != "unix" || !filepath.IsAbs(cfg.Addr) || cfg.TLSConfig != "" || len(ca) != 0 {
			return nil, rejected
		}
	} else {
		if cfg.Net != "tcp" || (cfg.TLSConfig != "" && cfg.TLSConfig != "true") || digest(ca) != r.Transport.CASHA256 {
			return nil, rejected
		}
		if _, _, err = net.SplitHostPort(cfg.Addr); err != nil {
			return nil, rejected
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, rejected
		}
		cfg.TLS = &tls.Config{RootCAs: roots, ServerName: r.Transport.ServerName, MinVersion: tls.VersionTLS12}
		cfg.TLSConfig = ""
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.InterpolateParams = false
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	return cfg, nil
}
func readIdentity(ctx context.Context, tx *sql.Tx, r request) (identity, error) {
	var v identity
	err := tx.QueryRowContext(ctx, identitySQL).Scan(&v.ServerUUID, &v.Database, &v.CurrentUser, &v.CurrentRole, &v.ConnectionID, &v.SQLTime)
	t, e := time.Parse(time.RFC3339Nano, v.SQLTime)
	if err != nil || e != nil || t.IsZero() || v.ServerUUID != r.ServerUUID || v.Database != r.Database || v.CurrentUser != r.CurrentUser || v.CurrentRole != r.CurrentRole || v.ConnectionID <= 0 || v.ConnectionID > 9007199254740991 {
		return identity{}, rejected
	}
	return v, nil
}
func inspect(ctx context.Context, db *sql.DB, r request) (collection, error) {
	empty := collection{}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, rejected
	}
	defer tx.Rollback()
	before, err := readIdentity(ctx, tx, r)
	if err != nil {
		return empty, rejected
	}
	rows, err := tx.QueryContext(ctx, auditSQL, r.OperationID)
	if err != nil {
		return empty, rejected
	}
	var raw []byte
	count := 0
	for rows.Next() {
		count++
		if count != 1 || rows.Scan(&raw) != nil || len(raw) == 0 || len(raw) > 65536 {
			rows.Close()
			return empty, rejected
		}
		raw = bytes.Clone(raw)
	}
	streamErr, closeErr := rows.Err(), rows.Close()
	if streamErr != nil || closeErr != nil || count != 1 {
		return empty, rejected
	}
	if err = checkExport(raw, r); err != nil {
		return empty, rejected
	}
	after, err := readIdentity(ctx, tx, r)
	if err != nil {
		return empty, rejected
	}
	b, e1 := time.Parse(time.RFC3339Nano, before.SQLTime)
	a, e2 := time.Parse(time.RFC3339Nano, after.SQLTime)
	if e1 != nil || e2 != nil || a.Before(b) || before.ConnectionID != after.ConnectionID || ctx.Err() != nil {
		return empty, rejected
	}
	if tx.Rollback() != nil || ctx.Err() != nil {
		return empty, rejected
	}
	return collection{SchemaVersion: "a_live_download_audit_collection.v1", ReceiptSHA256: r.ReceiptSHA256, QuerySHA256: digest([]byte(auditSQL)), OperationID: r.OperationID, Before: before, After: after, ReadOnly: true, RolledBack: true, ExportSHA256: digest(raw), ExportBase64: base64.StdEncoding.EncodeToString(raw)}, nil
}
func run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("system-backup-audit-collect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsnPath := flags.String("dsn-file", "", "original observer DSN file")
	caPath := flags.String("ca-file", "", "pinned observer TLS CA file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *dsnPath == "" {
		return rejected
	}
	seen := map[string]bool{}
	duplicate := false
	// The flag parser permits duplicates, so reject them explicitly.
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			key := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[key] {
				duplicate = true
			}
			seen[key] = true
		}
	}
	if duplicate {
		return rejected
	}
	raw, err := io.ReadAll(io.LimitReader(in, 65537))
	if err != nil || len(raw) > 65536 {
		return rejected
	}
	r, err := decodeRequest(raw)
	if err != nil {
		return rejected
	}
	dsn, err := readFile(*dsnPath, 8192)
	if err != nil {
		return rejected
	}
	defer clear(dsn)
	var ca []byte
	if r.Transport.Mode == "tls" {
		ca, err = readFile(*caPath, 1048576)
		if err != nil {
			return rejected
		}
	} else if *caPath != "" {
		return rejected
	}
	cfg, err := observerConfig(dsn, ca, r)
	if err != nil {
		return rejected
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return rejected
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer db.Close()
	probe, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	result, err := inspect(probe, db, r)
	if err != nil {
		return rejected
	}
	if db.Close() != nil || probe.Err() != nil {
		return rejected
	}
	result.RequestSHA256 = digest(raw)
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 100000 {
		return rejected
	}
	_, err = out.Write(append(encoded, '\n'))
	return err
}
func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if run(ctx, os.Args[1:], os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "download audit collection rejected; no successful result emitted")
		os.Exit(1)
	}
}
