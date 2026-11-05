package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"clawreef/internal/mysqltls"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	mysql "github.com/go-sql-driver/mysql"
)

// This translates original private DSN DATA with the driver's real parser.
// It issues no authority and performs no SQL. Secrets never reach stdout/argv.
func runOriginalRuntimeDatabaseEnvironment(args []string, out io.Writer) int {
	if out == nil {
		return 2
	}
	f := flag.NewFlagSet("runtime-database-environment", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	workerCredential := f.Bool("worker-source-credential", false, "emit canonical source credential DATA from exact actual role DSN, no grant")
	values := map[string]*string{}
	for _, name := range []string{"plan-file", "plan-sha256", "runtime-dsn-file", "runtime-dsn-sha256", "tls-file", "tls-sha256", "output-file"} {
		values[name] = f.String(name, "", "")
	}
	if f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range values {
		if *v == "" {
			return 2
		}
	}
	get := func(n string) string { return *values[n] }
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	read := func(file, sha string, max int64) ([]byte, error) {
		raw, e := install.ReadPrivateFile(get(file), max)
		if e != nil {
			return nil, e
		}
		if digest(raw) != get(sha) {
			clear(raw)
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	planRaw, e := read("plan-file", "plan-sha256", 262144)
	if e != nil {
		return 1
	}
	plan, e := install.DecodePlan(planRaw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	raw, e := read("runtime-dsn-file", "runtime-dsn-sha256", 65536)
	if e != nil {
		return 1
	}
	defer clear(raw)
	cfg, e := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if e != nil {
		return 1
	}
	defer func() { cfg.Passwd = "" }()
	if cfg.Net != "tcp" || cfg.User == "" || strings.EqualFold(cfg.User, "root") || cfg.User == plan.Target.DatabaseAccount || cfg.Passwd == "" || cfg.DBName != plan.Target.Database || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext {
		return 1
	}
	host, port, e := net.SplitHostPort(cfg.Addr)
	if e != nil || host == "" {
		return 1
	}
	number, e := strconv.Atoi(port)
	if e != nil || number < 1 || number > 65535 {
		return 1
	}
	tlsRaw, e := read("tls-file", "tls-sha256", 65536)
	if e != nil {
		return 1
	}
	var selected mysqltls.Material
	decoder := json.NewDecoder(strings.NewReader(string(tlsRaw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selected) != nil || decoder.Decode(&struct{}{}) != io.EOF || !selected.Selected() || selected.Validate() != nil || selected.CASHA256 != plan.DatabaseCASHA256 || selected.ServerName != plan.DatabaseTLSServerName || selected.Apply(cfg) != nil {
		return 1
	}
	environment := map[string]string{"DB_USER": cfg.User, "DB_PASSWORD": cfg.Passwd, "DB_HOST": host, "DB_PORT": port, "DB_NAME": cfg.DBName, "DB_TLS_CA_FILE": selected.CAFile, "DB_TLS_CA_SHA256": selected.CASHA256, "DB_TLS_SERVER_NAME": selected.ServerName}
	for _, value := range environment {
		if strings.ContainsAny(value, "\r\n\x00") {
			return 1
		}
	}
	file := get("output-file")
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return 1
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(file))
	if e != nil || parent != filepath.Dir(file) {
		return 1
	}
	body, e := json.Marshal(struct {
		Version     string
		Environment map[string]string
	}{"original-runtime-database-environment.v1", environment})
	if *workerCredential {
		credential := worker.DatabaseCredential{Username: cfg.User, Password: []byte(cfg.Passwd)}
		body, e = json.Marshal(credential)
		clear(credential.Password)
	}
	if e != nil {
		return 1
	}
	defer clear(body)
	target, e := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return 1
	}
	_, e = target.Write(body)
	if e == nil {
		e = target.Sync()
	}
	closeErr := target.Close()
	if e != nil || closeErr != nil {
		return 1
	}
	directory, e := os.Open(parent)
	if e != nil {
		return 1
	}
	e = directory.Sync()
	closeErr = directory.Close()
	if e != nil || closeErr != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(install.BootstrapSourceFilePin{File: file, SHA256: digest(body)}) != nil {
		return 3
	}
	return 0
}
