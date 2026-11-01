package domain_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	mysql "github.com/go-sql-driver/mysql"
)

type northboundNativeChildConfig struct {
	MetaPath, OwnerSchema, OwnerNonce, ReaderUser, ReaderPassword, StagingPath string
	Request                                                                    worker.Request
	Key                                                                        []byte
}

func runNorthboundNativeVerifyChild(t *testing.T, f *gatewayNative, r worker.Request, key []byte, stage, user string) {
	t.Helper()
	cfg := northboundNativeChildConfig{MetaPath: os.Getenv("CLAWMANAGER_GATEWAY_RESTORE_MYSQL_META"), OwnerSchema: f.owners, OwnerNonce: f.nonce, ReaderUser: user, ReaderPassword: f.nonce, StagingPath: stage, Request: r, Key: key}
	file := filepath.Join(t.TempDir(), "owned-northbound-verify-child.json")
	raw, e := json.Marshal(cfg)
	if e != nil || os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("private Northbound child control file")
	}
	clear(raw)
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNorthboundNativeVerifyChild$", "-test.v")
	cmd.Env = append(os.Environ(), "CLAWMANAGER_NORTHBOUND_NATIVE_VERIFY_CHILD="+file)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("new process Northbound verification failed: %v\n%s", e, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}
func TestNorthboundNativeVerifyChild(t *testing.T) {
	control := os.Getenv("CLAWMANAGER_NORTHBOUND_NATIVE_VERIFY_CHILD")
	if control == "" {
		t.Skip("owned native parent helper only")
	}
	raw, e := os.ReadFile(control)
	if e != nil || len(raw) > 1<<20 {
		t.Fatal("private Northbound child control unavailable")
	}
	defer clear(raw)
	var cfg northboundNativeChildConfig
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid child control")
	}
	var meta struct {
		Root   string
		Port   int
		Nonce  string `json:"owner_nonce"`
		UUID   string `json:"server_uuid"`
		CAHash string `json:"ca_sha256"`
	}
	metaBytes, e := os.ReadFile(cfg.MetaPath)
	if e != nil || json.Unmarshal(metaBytes, &meta) != nil || !filepath.IsAbs(meta.Root) || !strings.HasPrefix(filepath.Base(meta.Root), "cm-gateway-restore-") || meta.Nonce != cfg.OwnerNonce || meta.Port <= 0 || meta.Port == 63507 || meta.Port == 65298 || meta.Port == 59355 || meta.Port == 65299 {
		t.Fatal("owned child SQL metadata rejected")
	}
	marker, e := os.ReadFile(filepath.Join(meta.Root, "owner-nonce.txt"))
	if e != nil || strings.TrimSpace(string(marker)) != meta.Nonce {
		t.Fatal("owned child marker rejected")
	}
	ca, e := os.ReadFile(filepath.Join(meta.Root, "ca.pem"))
	sum := sha256.Sum256(ca)
	if e != nil || hex.EncodeToString(sum[:]) != meta.CAHash || cfg.Request.Database == nil || !bytes.Equal(ca, cfg.Request.Database.RootCA) || cfg.Request.Database.Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(meta.Port)) || cfg.Request.Database.ServerUUID != meta.UUID || cfg.Request.Operation != "verify-database" {
		t.Fatal("owned child TLS/SQL identity rejected")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("owned child CA invalid")
	}
	adminCfg := mysql.NewConfig()
	adminCfg.User = "root"
	adminCfg.Net = "tcp"
	adminCfg.Addr = cfg.Request.Database.Address
	adminCfg.TLS = &tls.Config{RootCAs: pool, ServerName: cfg.Request.Database.TLSServerName, MinVersion: tls.VersionTLS12}
	adminCfg.Logger = &mysql.NopLogger{}
	adminCfg.Timeout = 5 * time.Second
	connector, e := mysql.NewConnector(adminCfg)
	if e != nil {
		t.Fatal("independent child observation connector")
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	admin.SetMaxIdleConns(0)
	reader, e := worker.OpenDatabase(cfg.Request.Database, &worker.DatabaseCredential{Username: cfg.ReaderUser, Password: []byte(cfg.ReaderPassword)})
	if e != nil {
		t.Fatal("fresh child SELECT-only connector")
	}
	defer reader.Close()
	stage, e := os.OpenRoot(cfg.StagingPath)
	if e != nil {
		t.Fatal(e)
	}
	defer stage.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	check := func(ctx context.Context, purpose string, r worker.Request) error {
		if purpose == "" || r.Operation != "verify-database" || r.Database.Name != cfg.Request.Database.Name || r.Binding != cfg.Request.Binding {
			return errors.New("child expected binding differs")
		}
		var uuid, nonce, locked string
		if admin.QueryRowContext(ctx, "SELECT @@server_uuid,(SELECT nonce FROM `"+cfg.OwnerSchema+"`.owned WHERE database_name=?),(SELECT account_locked FROM mysql.user WHERE User=? AND Host='127.0.0.1')", r.Database.Name, cfg.ReaderUser).Scan(&uuid, &nonce, &locked) != nil || uuid != meta.UUID || nonce != meta.Nonce || locked != "N" {
			return errors.New("child actual identity/account observation differs")
		}
		return ctx.Err()
	}
	// No observation/candidate/source/writer is supplied to this new process.
	// RunDatabase authenticates the actual sealed SQL plan then uses the common
	// restrictive SHOW GRANTS check and complete SELECT-only raw-cell reader.
	result, e := worker.RunDatabase(ctx, cfg.Request, worker.DatabaseEnvironment{Database: reader, Staging: stage, Key: cfg.Key, Check: check})
	if e != nil || !result.Verified {
		t.Fatal("new-process public Northbound verify", e)
	}
	if _, e = reader.ExecContext(ctx, "UPDATE northbound_owner_records SET version=version WHERE 1=0"); nativeImageMySQLNumber(e) != 1142 {
		t.Fatal("actual child SELECT-only DML was not denied1142")
	}
	t.Log("fresh child public verify: actual expected SQL AEAD/EOF, 35/6/56 full raw cells and restrictive SELECT-only grants; no old observation/CAS/source/writer; actual UPDATE denied1142 PASS")
}
