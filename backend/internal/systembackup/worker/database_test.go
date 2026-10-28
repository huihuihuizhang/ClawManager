package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func databaseRequestFixture(t *testing.T) Invocation {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return Invocation{StagingPath: "/staging", Request: Request{Version: Version, Operation: "capture-database", ArtifactName: "source.enc", Deadline: time.Now().Add(time.Minute), MaxArchiveBytes: 1 << 20, MaxCompressedBytes: 1 << 20, Database: &DatabaseSpec{Address: "fixture.invalid:3306", Name: "source", ServerUUID: "fixture-uuid", TLSServerName: "fixture.invalid", RootCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), MaxRows: 100, MaxMemoryBytes: 1 << 20}}}
}
func TestDatabaseConnectionHasExplicitTLSAndNoDSNEscapes(t *testing.T) {
	i := databaseRequestFixture(t)
	credential := &DatabaseCredential{Username: "fixture_reader", Password: []byte("synthetic-/?&password")}
	cfg, err := databaseConfig(i.Request.Database, credential)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Passwd != string(credential.Password) || cfg.Net != "tcp" || cfg.TLS == nil || cfg.TLS.MinVersion < tls.VersionTLS12 || cfg.TLS.InsecureSkipVerify || cfg.TLS.ServerName != "fixture.invalid" || cfg.TLS.RootCAs == nil || cfg.ParseTime || cfg.AllowAllFiles || cfg.MultiStatements || cfg.AllowCleartextPasswords || cfg.AllowFallbackToPlaintext || cfg.AllowOldPasswords {
		t.Fatal("unsafe connection options")
	}
	db, err := OpenDatabase(i.Request.Database, credential)
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // lazy: no network/DNS connection
	for _, mode := range []string{"ca", "address", "database", "credential"} {
		t.Run(mode, func(t *testing.T) {
			d := *i.Request.Database
			c := *credential
			switch mode {
			case "ca":
				d.RootCA = []byte("invalid")
			case "address":
				d.Address = "fixture:3306/?tls=false"
			case "database":
				d.Name = "source?multiStatements=true"
			case "credential":
				c.Password = nil
			}
			if _, err := OpenDatabase(&d, &c); err == nil {
				t.Fatal("unsafe connection accepted")
			}
		})
	}
}
func TestDatabaseCredentialIsOnlyDeliveredInBoundAcquireGrant(t *testing.T) {
	i := databaseRequestFixture(t)
	hash, _ := i.Hash()
	h := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, _ string, r ControlRequest) (Lease, error) {
		if r.InvocationSHA256 != hash {
			return Lease{}, ErrExecution
		}
		l := Lease{InvocationSHA256: hash, ExpiresAt: time.Now().Add(20 * time.Second)}
		if r.Action == "acquire" {
			l.DEK = bytes.Repeat([]byte{1}, 32)
			l.Database = &DatabaseCredential{Username: "reader", Password: []byte("fixture-secret")}
		}
		return l, nil
	})}
	c, _ := mutualTLSFixture(t, h)
	if err := c.Ready(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	l, err := c.Acquire(context.Background(), i)
	if err != nil || l.Database == nil || string(l.Database.Password) != "fixture-secret" {
		t.Fatal("missing database grant", err)
	}
	defer l.Clear()
	if err = c.Check(context.Background(), i, "before-capture"); err != nil {
		t.Fatal(err)
	}
	changed := i
	d := *i.Request.Database
	d.Address = "another.invalid:3306"
	changed.Request.Database = &d
	if _, err = c.Acquire(context.Background(), changed); err == nil {
		t.Fatal("endpoint change reused authorization")
	}
	b, _ := json.Marshal(i)
	if strings.Contains(string(b), "fixture-secret") || strings.Contains(string(b), "reader") {
		t.Fatal("credentials persisted in invocation")
	}
	request := ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "check", Point: "before-capture"}
	if validLeasePayload(l, request) {
		t.Fatal("heartbeat allowed credentials")
	}
	request.Action = "acquire"
	password := l.Database.Password
	l.Clear()
	l.Database = nil
	if validLeasePayload(l, request) {
		t.Fatal("database grant without password accepted")
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("grant password was not cleared")
	}
}
