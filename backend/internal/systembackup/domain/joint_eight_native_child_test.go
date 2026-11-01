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
	"io"
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

type jointEightChildConfig struct {
	Base                nativeImageChildConfig
	ExpectDigestRefusal bool
}

func runJointEightNativeChild(t *testing.T, f *gatewayNative, r worker.Request, key []byte, stage, user string, imageEvidence staging.Receipt, objects domain.GatewayImageReaderTestSettings, reject bool) {
	t.Helper()
	cfg := jointEightChildConfig{Base: nativeImageChildConfig{MetaPath: os.Getenv("CLAWMANAGER_GATEWAY_RESTORE_MYSQL_META"), OwnerSchema: f.owners, OwnerNonce: f.nonce, ReaderUser: user, ReaderPassword: f.nonce, StagingPath: stage, Request: r, Key: key, ImageEvidence: imageEvidence, Objects: objects}, ExpectDigestRefusal: reject}
	file := filepath.Join(t.TempDir(), "joint-eight-reader-child.json")
	raw, e := json.Marshal(cfg)
	if e != nil || os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("joint private child control")
	}
	clear(raw)
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestJointEightNativeVerifyChild$", "-test.v")
	cmd.Env = append(os.Environ(), "CLAWMANAGER_JOINT_EIGHT_NATIVE_VERIFY_CHILD="+file)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("joint fresh child failed: %v\n%s", e, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func jointEightSelectCount(t *testing.T, ctx context.Context, db *sql.DB) uint64 {
	t.Helper()
	var name, value string
	if db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_select'").Scan(&name, &value) != nil || name != "Com_select" {
		t.Fatal("joint reader actual SELECT counter")
	}
	n, e := strconv.ParseUint(value, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

// Observe through the separate fixture administrator, without issuing a
// SELECT CONNECTION_ID on the reader whose Com_select counter is measured.
func jointEightReaderSession(t *testing.T, ctx context.Context, admin *sql.DB, user, database string) uint64 {
	t.Helper()
	rows, e := admin.QueryContext(ctx, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER=? AND DB=? ORDER BY ID LIMIT 2", user, database)
	if e != nil {
		t.Fatal("joint physical reader session observation", e)
	}
	defer rows.Close()
	var id uint64
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id) != nil || id == 0 {
			t.Fatal("joint physical reader session identity")
		}
	}
	if rows.Err() != nil || count != 1 {
		t.Fatal("joint reader principal must have exactly one physical session")
	}
	return id
}

func TestJointEightNativeVerifyChild(t *testing.T) {
	control := os.Getenv("CLAWMANAGER_JOINT_EIGHT_NATIVE_VERIFY_CHILD")
	if control == "" {
		t.Skip("joint owned native parent helper only")
	}
	raw, e := os.ReadFile(control)
	if e != nil || len(raw) > 1<<20 {
		t.Fatal("joint child control unavailable")
	}
	defer clear(raw)
	var settings jointEightChildConfig
	if json.Unmarshal(raw, &settings) != nil {
		t.Fatal("joint child control invalid")
	}
	cfg := settings.Base
	var meta struct {
		Root   string
		Port   int
		Nonce  string `json:"owner_nonce"`
		UUID   string `json:"server_uuid"`
		CAHash string `json:"ca_sha256"`
	}
	metaBytes, e := os.ReadFile(cfg.MetaPath)
	if e != nil || json.Unmarshal(metaBytes, &meta) != nil || !filepath.IsAbs(meta.Root) || !strings.HasPrefix(filepath.Base(meta.Root), "cm-gateway-restore-") || len(meta.Nonce) != 32 || meta.Nonce != cfg.OwnerNonce || meta.Port <= 0 || meta.Port == 63507 || meta.Port == 65298 || meta.Port == 59355 || meta.Port == 65299 || meta.Port == 61189 {
		t.Fatal("joint actual owned SQL metadata rejected")
	}
	marker, e := os.ReadFile(filepath.Join(meta.Root, "owner-nonce.txt"))
	if e != nil || strings.TrimSpace(string(marker)) != meta.Nonce {
		t.Fatal("joint actual owner marker rejected")
	}
	ca, e := os.ReadFile(filepath.Join(meta.Root, "ca.pem"))
	sum := sha256.Sum256(ca)
	if e != nil || hex.EncodeToString(sum[:]) != meta.CAHash || cfg.Request.Database == nil || !bytes.Equal(ca, cfg.Request.Database.RootCA) || cfg.Request.Database.Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(meta.Port)) || cfg.Request.Database.ServerUUID != meta.UUID || cfg.Request.Operation != "verify-database" {
		t.Fatal("joint child pinned SQL identity rejected")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("joint child CA invalid")
	}
	adminCfg := mysql.NewConfig()
	adminCfg.User = "root"
	adminCfg.Net = "tcp"
	adminCfg.Addr = cfg.Request.Database.Address
	adminCfg.TLS = &tls.Config{RootCAs: pool, ServerName: cfg.Request.Database.TLSServerName, MinVersion: tls.VersionTLS12}
	adminCfg.Timeout = 5 * time.Second
	adminCfg.Logger = &mysql.NopLogger{}
	connector, e := mysql.NewConnector(adminCfg)
	if e != nil {
		t.Fatal(e)
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	admin.SetMaxIdleConns(0)
	// Root is only this private fixture's independent identity/account observer.
	// It is never supplied as RunDatabase's data reader or a restore credential;
	// this fixture therefore does NOT qualify all-consumer physical isolation.
	reader, e := worker.OpenDatabase(cfg.Request.Database, &worker.DatabaseCredential{Username: cfg.ReaderUser, Password: []byte(cfg.ReaderPassword)})
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	objects, e := domain.NewGatewayImageObjectClient(cfg.Objects.Endpoint, cfg.Objects.TLSServerName, cfg.Objects.Region, cfg.Objects.CA, cfg.Objects.Access, cfg.Objects.Secret, "")
	if e != nil {
		t.Fatal(e)
	}
	defer objects.Close()
	stage, e := os.OpenRoot(cfg.StagingPath)
	if e != nil {
		t.Fatal(e)
	}
	defer stage.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	expected := jointEightOpenSQL(t, ctx, stage, cfg.Request.Receipt, cfg.Key, cfg.Request.Binding)
	defer jointEightClear(expected)
	// Even the deliberately mismatched case supplies TWO real valid AEAD
	// files, a complete8-table SQL entity and the matching SQL file descriptor.
	imageBinding := cfg.Request.Binding
	imageBinding.Path += "/gateway-images"
	imageFile, e := staging.OpenFile(ctx, stage, cfg.ImageEvidence)
	if e != nil {
		t.Fatal("joint child actual image evidence file", e)
	}
	e = staging.Open(ctx, imageFile, io.Discard, cfg.Key, imageBinding, 48<<20)
	imageFile.Close()
	if e != nil {
		t.Fatal("joint child actual image metadata AEAD/EOF", e)
	}
	beforeVerify := false
	check := func(ctx context.Context, phase string, r worker.Request) error {
		if phase == "" || r.Operation != "verify-database" || r.Binding != cfg.Request.Binding || r.Database.Name != cfg.Request.Database.Name {
			return errors.New("joint child invocation differs")
		}
		var uuid, nonce, locked string
		if admin.QueryRowContext(ctx, "SELECT @@server_uuid,(SELECT nonce FROM `"+cfg.OwnerSchema+"`.owned WHERE database_name=?),(SELECT account_locked FROM mysql.user WHERE User=? AND Host='127.0.0.1')", r.Database.Name, cfg.ReaderUser).Scan(&uuid, &nonce, &locked) != nil || uuid != meta.UUID || nonce != meta.Nonce || locked != "N" {
			return errors.New("joint child actual identity/account differs")
		}
		if phase == "before-verify" {
			beforeVerify = true
		}
		return ctx.Err()
	}
	if e = reader.PingContext(ctx); e != nil {
		t.Fatal("joint warm reader session", e)
	}
	physicalBefore := jointEightReaderSession(t, ctx, admin, cfg.ReaderUser, cfg.Request.Database.Name)
	selectsBefore := jointEightSelectCount(t, ctx, reader)
	if jointEightReaderSession(t, ctx, admin, cfg.ReaderUser, cfg.Request.Database.Name) != physicalBefore {
		t.Fatal("joint reader reconnected during initial counter observation")
	}
	result, e := worker.RunDatabase(ctx, cfg.Request, worker.DatabaseEnvironment{Database: reader, Staging: stage, Key: cfg.Key, Check: check, GatewayImageReader: objects, GatewayImageEvidence: cfg.ImageEvidence})
	selectsAfter := jointEightSelectCount(t, ctx, reader)
	if jointEightReaderSession(t, ctx, admin, cfg.ReaderUser, cfg.Request.Database.Name) != physicalBefore {
		t.Fatal("joint reader reconnected: SELECT counters are not comparable")
	}
	if !beforeVerify {
		t.Fatal("joint counterexample failed before actual public SQL decoding/verify boundary")
	}
	if settings.ExpectDigestRefusal {
		if e == nil || result.Verified || selectsAfter != selectsBefore {
			t.Fatal("joint cross-domain full expected digest mismatch reached SQL target reads or was accepted", e)
		}
	} else {
		if e != nil || !result.Verified || selectsAfter <= selectsBefore {
			t.Fatal("joint fresh-process public8-owner verification", e)
		}
		// Public verify already compares every cell; this independent census
		// makes the all8-nonempty qualification explicit in this new process.
		actual := jointEightReadTarget(t, ctx, reader)
		jointEightRequireNonempty(t, actual)
		jointEightClear(actual)
	}
	for _, query := range []string{"UPDATE gateway_image_jobs SET settled=settled WHERE 1=0", "UPDATE northbound_owner_records SET version=version WHERE 1=0"} {
		if _, e = reader.ExecContext(ctx, query); nativeImageMySQLNumber(e) != 1142 {
			t.Fatal("joint actual independent SELECT-only UPDATE did not fail1142")
		}
	}
	if settings.ExpectDigestRefusal {
		t.Log("fresh child: complete8-table changed Northbound expected SQL + matching descriptor + valid image metadata AEAD rejected before any SQL target SELECT by full digest; no old pointer; actual1142")
	} else {
		t.Log("fresh child: ONE complete8-nonempty expected SQL/image cohort, actual fixed-version SDK readback + every raw SQL cell + restrictive SELECT-only grants; no old source/writer/receipt/observation/CAS pointer; actual1142")
	}
}
