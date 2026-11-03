package systembackupexecution

import (
	"clawreef/internal/mysqltls"
	"clawreef/internal/systembackup"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mysqlBusinessTLSFixture(t *testing.T) (mysqltls.Material, tls.Certificate) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned protocol fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"mysql.original.invalid"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, serverPub, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	file := filepath.Join(t.TempDir(), "original-ca.pem")
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("CA fixture write")
	}
	sum := sha256.Sum256(raw)
	return mysqltls.Material{CAFile: file, CASHA256: hex.EncodeToString(sum[:]), ServerName: "mysql.original.invalid"}, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: serverKey}
}
func mysqlFixturePacket(w io.Writer, seq byte, body []byte) error {
	header := []byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), seq}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}
func mysqlFixtureRead(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size > 65536 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, size)
	_, err := io.ReadFull(r, body)
	return body, err
}

// These use the production pool constructors and actual MySQL driver over a
// local protocol fixture. No real SQL UUID/grant checks or field cert is implied.
func TestIndependentMySQLTLSPools(t *testing.T) {
	for _, kind := range []string{"control", "source"} {
		for _, mode := range []string{"tls13", "wrong-name", "wrong-ca", "tls12-only", "no-server-tls"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				material, cert := mysqlBusinessTLSFixture(t)
				if mode == "wrong-name" {
					material.ServerName = "wrong.original.invalid"
				}
				if mode == "wrong-ca" {
					other, _ := mysqlBusinessTLSFixture(t)
					material.CAFile = other.CAFile
					material.CASHA256 = other.CASHA256
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				var plaintext atomic.Bool
				var version atomic.Uint32
				done := make(chan struct{})
				go func() {
					defer close(done)
					conn, e := listener.Accept()
					if e != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(4 * time.Second))
					flags := uint32(1 | 4 | 8 | 512 | 8192 | 32768 | 0x80000)
					if mode != "no-server-tls" {
						flags |= 2048
					}
					greeting := append([]byte{10}, []byte("8.0.0-fixture\x00")...)
					greeting = append(greeting, 1, 0, 0, 0)
					greeting = append(greeting, []byte("12345678")...)
					greeting = append(greeting, 0, byte(flags), byte(flags>>8), 45, 2, 0, byte(flags>>16), byte(flags>>24), 21)
					greeting = append(greeting, make([]byte, 10)...)
					greeting = append(greeting, []byte("abcdefghijkl\x00mysql_native_password\x00")...)
					if mysqlFixturePacket(conn, 0, greeting) != nil {
						return
					}
					request, e := mysqlFixtureRead(conn)
					if e != nil {
						return
					}
					if mode == "no-server-tls" {
						plaintext.Store(len(request) > 0)
						return
					}
					if len(request) != 32 || binary.LittleEndian.Uint32(request[:4])&2048 == 0 {
						plaintext.Store(true)
						return
					}
					cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
					if mode == "tls12-only" {
						cfg.MinVersion = tls.VersionTLS12
						cfg.MaxVersion = tls.VersionTLS12
					}
					secure := tls.Server(conn, cfg)
					if secure.Handshake() != nil {
						return
					}
					version.Store(uint32(secure.ConnectionState().Version))
					if _, e = mysqlFixtureRead(secure); e != nil {
						return
					}
					if mysqlFixturePacket(secure, 3, []byte{0, 0, 0, 2, 0, 0, 0}) != nil {
						return
					}
					for {
						body, e := mysqlFixtureRead(secure)
						if e != nil || len(body) == 0 || body[0] == 1 {
							return
						}
						if body[0] != 3 && body[0] != 14 {
							return
						}
						if mysqlFixturePacket(secure, 1, []byte{0, 0, 0, 2, 0, 0, 0}) != nil {
							return
						}
					}
				}()
				path := filepath.Join(t.TempDir(), "dsn")
				if err = os.WriteFile(path, []byte("fixture:PRIVATE_CANARY@tcp("+listener.Addr().String()+")/test"), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				var pool *sql.DB
				if kind == "control" {
					pool, err = systembackup.OpenControlDatabaseWithTLS(ctx, path, material)
				} else {
					pool, err = openDeploymentSource(DeploymentConfig{SourceDSNFile: path, SourceUser: "fixture", SourceDatabase: "test", SourceTLS: &material})
					if err == nil {
						err = pool.PingContext(ctx)
					}
				}
				if pool != nil {
					defer pool.Close()
				}
				if mode == "tls13" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("unsafe TLS accepted")
				}
				if err != nil && strings.Contains(err.Error(), "PRIVATE_CANARY") {
					t.Fatal("secret leaked")
				}
				if pool != nil {
					pool.Close()
				}
				listener.Close()
				<-done
				if plaintext.Load() {
					t.Fatal("plaintext authentication sent")
				}
				if mode == "tls13" && version.Load() != tls.VersionTLS13 {
					t.Fatal("TLS 1.3 not negotiated")
				}
			})
		}
	}
}
func TestDeploymentSourceTLSIdentityAndPartialSelection(t *testing.T) {
	material, _ := mysqlBusinessTLSFixture(t)
	for _, mode := range []string{"wrong-user", "wrong-db", "multi-statements", "allow-files", "preferred", "partial", "empty"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dsn")
			dsn := "fixture:PRIVATE_CANARY@tcp(127.0.0.1:1)/test"
			cfg := DeploymentConfig{SourceDSNFile: path, SourceUser: "fixture", SourceDatabase: "test", SourceTLS: &material}
			copy := material
			cfg.SourceTLS = &copy
			switch mode {
			case "wrong-user":
				cfg.SourceUser = "other"
			case "wrong-db":
				cfg.SourceDatabase = "other"
			case "multi-statements":
				dsn += "?multiStatements=true"
			case "allow-files":
				dsn += "?allowAllFiles=true"
			case "preferred":
				dsn += "?tls=preferred"
			case "partial":
				copy.ServerName = ""
			case "empty":
				copy = mysqltls.Material{}
			}
			if os.WriteFile(path, []byte(dsn), 0600) != nil {
				t.Fatal("write")
			}
			pool, err := openDeploymentSource(cfg)
			if pool != nil {
				pool.Close()
			}
			if err == nil || strings.Contains(err.Error(), "PRIVATE_CANARY") {
				t.Fatal("invalid identity/transport accepted", err)
			}
		})
	}
}
func TestDeploymentSourceTLSConfigBinding(t *testing.T) {
	cfg := testDeploymentConfiguration(t)
	material, _ := mysqlBusinessTLSFixture(t)
	cfg.SourceTLS = &material
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(cfg.ProfileFile, raw, 0600) != nil {
		t.Fatal("write")
	}
	got, err := LoadDeploymentConfig(cfg.ProfileFile, hash(raw))
	if err != nil || got.SourceTLS == nil || *got.SourceTLS != material {
		t.Fatal("TLS config not pinned", err)
	}
	for _, bad := range []mysqltls.Material{{}, {CAFile: material.CAFile}, {CASHA256: material.CASHA256}, {ServerName: material.ServerName}} {
		cfg.SourceTLS = &bad
		if cfg.Validate() == nil {
			t.Fatal("empty/partial explicit TLS accepted")
		}
	}
}
