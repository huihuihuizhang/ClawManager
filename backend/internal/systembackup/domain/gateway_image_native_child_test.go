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

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	mysql "github.com/go-sql-driver/mysql"
)

type nativeImageChildConfig struct {
	MetaPath, OwnerSchema, OwnerNonce, ReaderUser, ReaderPassword, StagingPath string
	Request                                                                    worker.Request
	Key                                                                        []byte
	ImageEvidence                                                              staging.Receipt
	Objects                                                                    domain.GatewayImageReaderTestSettings
}

func nativeImageMySQLNumber(e error) uint16 {
	var m *mysql.MySQLError
	if errors.As(e, &m) {
		return m.Number
	}
	return 0
}
func runNativeImageVerifyChild(t *testing.T, f *gatewayNative, r worker.Request, key []byte, stage, user string, imageEvidence staging.Receipt, objects domain.GatewayImageReaderTestSettings) {
	t.Helper()
	cfg := nativeImageChildConfig{MetaPath: os.Getenv("CLAWMANAGER_GATEWAY_RESTORE_MYSQL_META"), OwnerSchema: f.owners, OwnerNonce: f.nonce, ReaderUser: user, ReaderPassword: f.nonce, StagingPath: stage, Request: r, Key: key, ImageEvidence: imageEvidence, Objects: objects}
	file := filepath.Join(t.TempDir(), "owned-image-verify-child.json")
	raw, e := json.Marshal(cfg)
	if e != nil || os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("private child control file")
	}
	clear(raw)
	executable, e := os.Executable()
	if e != nil {
		t.Fatal("test process identity")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestGatewayImageNativeVerifyChild$", "-test.v")
	cmd.Env = append(os.Environ(), "CLAWMANAGER_IMAGE_NATIVE_VERIFY_CHILD="+file)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("independent native image child verification failed: %v\n%s", e, output)
	}
	t.Logf("new process, no old receipt pointer, actual SQL SELECT-only + fresh pinned SDK reader, public expected SQL/image AEAD Open and actual1142: %s", strings.TrimSpace(string(output)))
}

func TestGatewayImageNativeVerifyChild(t *testing.T) {
	control := os.Getenv("CLAWMANAGER_IMAGE_NATIVE_VERIFY_CHILD")
	if control == "" {
		t.Skip("owned native parent helper only")
	}
	raw, e := os.ReadFile(control)
	if e != nil || len(raw) > 1<<20 {
		t.Fatal("private child control unavailable")
	}
	defer clear(raw)
	var cfg nativeImageChildConfig
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("child control invalid")
	}
	var meta struct {
		Root   string
		Port   int
		Nonce  string `json:"owner_nonce"`
		UUID   string `json:"server_uuid"`
		CAHash string `json:"ca_sha256"`
	}
	metaBytes, e := os.ReadFile(cfg.MetaPath)
	if e != nil || json.Unmarshal(metaBytes, &meta) != nil || !filepath.IsAbs(meta.Root) || !strings.HasPrefix(filepath.Base(meta.Root), "cm-gateway-restore-") || meta.Nonce != cfg.OwnerNonce || meta.Port <= 0 || meta.Port == 63507 || meta.Port == 65298 || meta.Port == 59355 {
		t.Fatal("owned native child metadata rejected")
	}
	marker, e := os.ReadFile(filepath.Join(meta.Root, "owner-nonce.txt"))
	if e != nil || strings.TrimSpace(string(marker)) != meta.Nonce {
		t.Fatal("owned native child marker rejected")
	}
	ca, e := os.ReadFile(filepath.Join(meta.Root, "ca.pem"))
	sum := sha256.Sum256(ca)
	if e != nil || hex.EncodeToString(sum[:]) != meta.CAHash || !bytes.Equal(ca, cfg.Request.Database.RootCA) || cfg.Request.Database.Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(meta.Port)) || cfg.Request.Database.ServerUUID != meta.UUID || cfg.Request.Operation != "verify-database" {
		t.Fatal("native child pinned identity rejected")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("native child CA invalid")
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
		t.Fatal("native child independent observation connector")
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	admin.SetMaxOpenConns(1)
	admin.SetMaxIdleConns(0)
	reader, e := worker.OpenDatabase(cfg.Request.Database, &worker.DatabaseCredential{Username: cfg.ReaderUser, Password: []byte(cfg.ReaderPassword)})
	if e != nil {
		t.Fatal("native child SQL reader")
	}
	defer reader.Close()
	objects, e := domain.NewGatewayImageObjectClient(cfg.Objects.Endpoint, cfg.Objects.TLSServerName, cfg.Objects.Region, cfg.Objects.CA, cfg.Objects.Access, cfg.Objects.Secret, "")
	if e != nil {
		t.Fatal("native child new object reader")
	}
	defer objects.Close()
	stage, e := os.OpenRoot(cfg.StagingPath)
	if e != nil {
		t.Fatal("native child encrypted staging")
	}
	defer stage.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	check := func(ctx context.Context, purpose string, r worker.Request) error {
		if purpose == "" || r.Operation != "verify-database" || r.Database.Name != cfg.Request.Database.Name || r.Binding != cfg.Request.Binding {
			return errors.New("native child verify binding rejected")
		}
		var uuid, nonce, locked string
		if admin.QueryRowContext(ctx, "SELECT @@server_uuid,(SELECT nonce FROM `"+cfg.OwnerSchema+"`.owned WHERE database_name=?),(SELECT account_locked FROM mysql.user WHERE User=? AND Host='127.0.0.1')", r.Database.Name, cfg.ReaderUser).Scan(&uuid, &nonce, &locked) != nil || uuid != meta.UUID || nonce != meta.Nonce || locked != "N" {
			return errors.New("native child actual identity/account observation rejected")
		}
		return ctx.Err()
	}
	result, e := worker.RunDatabase(ctx, cfg.Request, worker.DatabaseEnvironment{Database: reader, Staging: stage, Key: cfg.Key, Check: check, GatewayImageReader: objects, GatewayImageEvidence: cfg.ImageEvidence})
	if e != nil || !result.Verified {
		t.Fatal("native child public image verify", e)
	}
	if _, e := reader.ExecContext(ctx, "UPDATE gateway_image_jobs SET settled=settled WHERE 1=0"); nativeImageMySQLNumber(e) != 1142 {
		t.Fatal("native child SELECT-only account did not deny DML1142")
	}
	t.Log("fresh-process public verify authenticated actual SQL expected file + image receipt/binding/full digest; independently connected SELECT-only SQL and pinned SDK fixed-version reads; no former receipt/source/writer capability; actual1142 PASS")
}
