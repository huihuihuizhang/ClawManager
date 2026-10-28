package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRequest() request {
	return request{SchemaVersion: "a_live_download_audit_request.v1", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "isolated_test", CurrentUser: "observer@localhost", CurrentRole: "NONE", OperationID: "sop_11111111-2222-3333-4444-555555555555", ReceiptSHA256: strings.Repeat("a", 64), Transport: transport{Mode: "unix"}}
}
func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/audit.json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type fakeState struct {
	raw        []byte
	fail       string
	count      int
	identities int
	queries    int
	rolledBack bool
	committed  bool
	readonly   bool
}
type fakeConnector struct{ s *fakeState }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{c.s}, nil }
func (c fakeConnector) Driver() driver.Driver                        { return fakeDriver{c.s} }

type fakeDriver struct{ s *fakeState }

func (d fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{d.s}, nil }

type fakeConn struct{ s *fakeState }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsafe begin") }
func (c *fakeConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.s.readonly = opts.ReadOnly && opts.Isolation == driver.IsolationLevel(sql.LevelRepeatableRead)
	if !c.s.readonly || c.s.fail == "begin" {
		return nil, errors.New("begin")
	}
	return &fakeTx{c.s}, nil
}

type fakeTx struct{ s *fakeState }

func (t *fakeTx) Commit() error { t.s.committed = true; return errors.New("must never commit") }
func (t *fakeTx) Rollback() error {
	t.s.rolledBack = true
	if t.s.fail == "rollback" {
		return errors.New("rollback")
	}
	return nil
}

type fakeRows struct {
	values [][]driver.Value
	index  int
	fail   string
}

func (r *fakeRows) Columns() []string {
	if len(r.values) > 0 && len(r.values[0]) == 6 {
		return []string{"server", "db", "user", "role", "connection", "time"}
	}
	return []string{"audit"}
}
func (r *fakeRows) Close() error {
	if r.fail == "close" {
		return errors.New("close")
	}
	return nil
}
func (r *fakeRows) Next(out []driver.Value) error {
	if r.index == len(r.values) {
		if r.fail == "stream" {
			return errors.New("stream")
		}
		return io.EOF
	}
	copy(out, r.values[r.index])
	r.index++
	return nil
}
func (c *fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries++
	if q == identitySQL && len(args) == 0 {
		c.s.identities++
		v := []driver.Value{testRequest().ServerUUID, "isolated_test", "observer@localhost", "NONE", int64(17), "2026-10-21T08:00:03Z"}
		if c.s.fail == "identity" {
			v[0] = "wrong"
		}
		if c.s.identities == 2 {
			switch c.s.fail {
			case "user-drift":
				v[2] = "other@localhost"
			case "role-drift":
				v[3] = "new-role"
			case "connection-drift":
				v[4] = int64(18)
			case "time-drift":
				v[5] = "2026-10-20T08:00:03Z"
			case "after-query":
				return nil, errors.New("after query")
			}
		}
		return &fakeRows{values: [][]driver.Value{v}}, nil
	}
	if q != auditSQL || len(args) != 1 || args[0].Value != testRequest().OperationID {
		return nil, errors.New("query changed")
	}
	if c.s.fail == "query" {
		return nil, errors.New("PRIVATE-DSN-ERROR")
	}
	values := [][]driver.Value{}
	for i := 0; i < c.s.count; i++ {
		values = append(values, []driver.Value{c.s.raw})
	}
	failure := ""
	if c.s.fail == "stream" || c.s.fail == "close" {
		failure = c.s.fail
	}
	return &fakeRows{values: values, fail: failure}, nil
}
func fakeDB(s *fakeState) *sql.DB { return sql.OpenDB(fakeConnector{s}) }

func TestReadOnlyCollection(t *testing.T) {
	s := &fakeState{raw: fixture(t), count: 1}
	db := fakeDB(s)
	defer db.Close()
	result, e := inspect(context.Background(), db, testRequest())
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := base64.StdEncoding.DecodeString(result.ExportBase64)
	if e != nil || !bytes.Equal(decoded, s.raw) || result.ExportSHA256 != digest(s.raw) || result.QuerySHA256 != digest([]byte(auditSQL)) || !result.ReadOnly || !result.RolledBack || !s.readonly || !s.rolledBack || s.committed || s.queries != 3 {
		t.Fatalf("invalid result or transaction: %+v", s)
	}
}
func TestRejectsSQLFailuresAndIdentityDrift(t *testing.T) {
	for _, failure := range []string{"begin", "identity", "query", "stream", "close", "user-drift", "role-drift", "connection-drift", "time-drift", "after-query", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			s := &fakeState{raw: fixture(t), count: 1, fail: failure}
			db := fakeDB(s)
			defer db.Close()
			got, e := inspect(context.Background(), db, testRequest())
			if e == nil || got.SchemaVersion != "" || s.committed || (failure != "begin" && !s.rolledBack) {
				t.Fatalf("failure accepted: %+v, %v", s, e)
			}
		})
	}
	for _, count := range []int{0, 2} {
		s := &fakeState{raw: fixture(t), count: count}
		db := fakeDB(s)
		_, e := inspect(context.Background(), db, testRequest())
		db.Close()
		if e == nil || !s.rolledBack {
			t.Fatal("invalid row count accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := fakeDB(&fakeState{})
	defer db.Close()
	if _, e := inspect(ctx, db, testRequest()); e == nil {
		t.Fatal("cancelled inspection accepted")
	}
}
func TestRequestAndPrivateDSNRejection(t *testing.T) {
	raw, _ := json.Marshal(testRequest())
	if _, e := decodeRequest(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"database":"isolated_test"}`)...), append(raw, raw...), bytes.Replace(raw, []byte(`"NONE"`), []byte(`null`), 1), bytes.Replace(raw, []byte(`"unix"`), []byte(`"plaintext"`), 1), bytes.Replace(raw, []byte(`"isolated_test"`), []byte(`"other;SELECT 1"`), 1)} {
		if _, e := decodeRequest(bad); e == nil {
			t.Fatalf("request accepted: %s", bad)
		}
	}
	good := []byte("observer:private@unix(" + filepath.Join(os.TempDir(), "audit-observer.sock") + ")/isolated_test")
	if _, e := observerConfig(good, nil, testRequest()); e != nil {
		t.Fatal(e)
	}
	for _, dsn := range []string{"observer:private@tcp(db:3306)/isolated_test", "observer:private@unix(/s)/wrong", "observer:private@unix(/s)/isolated_test?multiStatements=true", "observer:private@unix(/s)/isolated_test?allowAllFiles=true", "observer:private@unix(/s)/isolated_test?allowCleartextPasswords=true", "observer:private@unix(/s)/isolated_test?sql_mode=bad"} {
		if _, e := observerConfig([]byte(dsn), nil, testRequest()); e == nil {
			t.Fatal("unsafe DSN accepted")
		}
	}
	var out bytes.Buffer
	if run(context.Background(), []string{"--dsn-file", "relative"}, bytes.NewReader(raw), &out) == nil || out.Len() != 0 {
		t.Fatal("invalid private input emitted success")
	}
	if run(context.Background(), []string{"--dsn-file", "/one", "--dsn-file", "/two"}, bytes.NewReader(raw), &out) == nil || out.Len() != 0 {
		t.Fatal("duplicate flags accepted")
	}
}

func TestPinnedTLSAndNoDowngrade(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	r := testRequest()
	r.Transport = transport{Mode: "tls", ServerName: "mysql.test", CASHA256: digest(ca)}
	cfg, err := observerConfig([]byte("observer:private@tcp(mysql.test:3306)/isolated_test?tls=true"), ca, r)
	if err != nil || cfg.TLS == nil || cfg.TLS.InsecureSkipVerify || cfg.TLS.ServerName != "mysql.test" || cfg.TLS.MinVersion != tls.VersionTLS12 || cfg.TLS.RootCAs == nil {
		t.Fatal("pinned TLS not installed", err)
	}
	for _, mode := range []string{"skip-verify", "preferred"} {
		if _, err := observerConfig([]byte("observer:private@tcp(mysql.test:3306)/isolated_test?tls="+mode), ca, r); err == nil {
			t.Fatal("TLS downgrade accepted")
		}
	}
	if _, err := observerConfig([]byte("observer:private@tcp(mysql.test:3306)/isolated_test"), append(bytes.Clone(ca), ' '), r); err == nil {
		t.Fatal("CA byte drift accepted")
	}
}
func TestClosedExportAndBoundedRows(t *testing.T) {
	raw := fixture(t)
	if checkExport(raw, testRequest()) != nil {
		t.Fatal("fixture rejected")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"nonce_count": 1`), []byte(`"nonce_count": 1,"password":"PRIVATE"`), 1),
		bytes.Replace(raw, []byte(`"nonce_count": 1`), []byte(`"nonce_count": {"password":"PRIVATE"}`), 1),
		bytes.Replace(raw, []byte(`"local_write_complete"`), []byte(`{"password":"PRIVATE"}`), 1),
		bytes.Replace(raw, []byte(`"resource_id": null`), []byte(`"resource_id": null,"resource_id":null`), 1),
		bytes.Replace(raw, []byte(`"schema_version":`), []byte(`"unknown_secret":`), 1),
	} {
		if checkExport(bad, testRequest()) == nil {
			t.Fatal("unsafe export accepted")
		}
	}
	s := &fakeState{raw: bytes.Repeat([]byte("a"), 65537), count: 1}
	db := fakeDB(s)
	defer db.Close()
	if _, e := inspect(context.Background(), db, testRequest()); e == nil {
		t.Fatal("oversized row accepted")
	}
}
