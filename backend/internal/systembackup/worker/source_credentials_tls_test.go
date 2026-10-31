package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	k "clawreef/internal/systembackupkms"
)

// Actual database/sql + go-sql-driver/mysql protocol/STARTTLS/authentication
// through the production source opener. This bounded local protocol fixture
// supplies identity responses, not business rows. Real SQL/RR/SELECT-only and
// mid-capture revocation are exercised separately on the disposable MySQL.
func TestFormalSQLSourceProductionOpenerRequiresTLSIdentityAndAccount(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-ca", "wrong-uuid", "wrong-account", "active-role", "wrong-password"} {
		t.Run(mode, func(t *testing.T) {
			address, ca, queries := sourceMySQLTLSFixture(t, mode)
			i, _, _ := formalInvocationFixture(t)
			i.WorkspacePath = ""
			i.Request.Operation = "capture-database"
			i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
			i.Request.Files = nil
			i.Request.RuntimePolicy = nil
			base := databaseRequestFixture(t)
			unrelatedCA := bytes.Clone(base.Request.Database.RootCA)
			i.Request.Database = base.Request.Database
			i.Request.Database.Address = address
			i.Request.Database.TLSServerName = "source.fixture"
			i.Request.Database.ServerUUID = "source-tls-fixture-uuid"
			i.Request.Database.RootCA = ca
			if mode == "wrong-ca" {
				i.Request.Database.RootCA = unrelatedCA
			}
			i.FormalCapture.SourceConfigSHA256 = strings.Repeat("c", 64)
			i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("d", 64)}
			job := sourceControlJobFixture(t, i)
			dir := t.TempDir()
			pub, private, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(private)
			password := []byte("local-independent-source-password")
			if mode == "wrong-password" {
				password = []byte("wrong-independent-source-password")
			}
			credential, _ := json.Marshal(formalSourceCredential{Username: "source_reader", Password: password})
			mount := FormalSourceMount{GrantFile: filepath.Join(dir, "source.json"), CredentialFile: filepath.Join(dir, "credential.json"), CredentialSHA256: sourceDigest(credential), Issuer: pub}
			if os.WriteFile(mount.CredentialFile, credential, 0600) != nil {
				t.Fatal("local source credential unavailable")
			}
			clear(credential)
			scope, err := FormalSourceScopeSHA256(i, mount)
			if err != nil {
				t.Fatal(err)
			}
			grant := FormalSourceGrant{Version: FormalSourceGrantVersion, InstallationID: i.ProviderKey.Request.Context.InstallationID, ConfigSHA256: i.FormalCapture.SourceConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: i.Request.Operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
			body, _ := json.Marshal(grant)
			signed, _ := json.Marshal(SignedFormalSourceGrant{Record: body, Signature: ed25519.Sign(private, append([]byte(FormalSourceGrantDomain), body...))})
			mount.GrantSHA256 = sourceDigest(signed)
			if os.WriteFile(mount.GrantFile, signed, 0600) != nil {
				t.Fatal("local source grant unavailable")
			}
			sources, err := OpenFormalCaptureSources(context.Background(), i, job, &mount)
			if sources != nil {
				defer sources.Close()
			}
			if (mode == "valid") != (err == nil) {
				t.Fatal("production SQL source opener accepted wrong TLS/identity/account", mode, err)
			}
			if mode == "valid" && (sources.Database == nil || queries.Load() != 1) {
				t.Fatal("positive must complete actual TLS SQL identity query")
			}
			if (mode == "wrong-ca" || mode == "wrong-password") && queries.Load() != 0 {
				t.Fatal("untrusted source received SQL")
			}
		})
	}
}

func sourceMySQLTLSFixture(t *testing.T, mode string) (string, []byte, *atomic.Int32) {
	t.Helper()
	now := time.Now()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() { clear(key) })
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local SQL source CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"source.fixture"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	serverCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	queries := new(atomic.Int32)
	t.Cleanup(func() {
		listener.Close()
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("SQL source TLS fixture did not stop")
		}
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		scramble := []byte("original-source-seed") // twenty bytes, independent test auth challenge
		const capabilities uint32 = 1 | 4 | 8 | 512 | 2048 | 8192 | 32768 | 131072 | 524288
		hello := []byte{10}
		hello = append(hello, []byte("8.4.13-local-source\x00")...)
		hello = binary.LittleEndian.AppendUint32(hello, 1)
		hello = append(hello, scramble[:8]...)
		hello = append(hello, 0)
		hello = binary.LittleEndian.AppendUint16(hello, uint16(capabilities&0xffff))
		hello = append(hello, 45)
		hello = binary.LittleEndian.AppendUint16(hello, 2)
		hello = binary.LittleEndian.AppendUint16(hello, uint16(capabilities>>16))
		hello = append(hello, 21)
		hello = append(hello, make([]byte, 10)...)
		hello = append(hello, scramble[8:]...)
		hello = append(hello, 0)
		hello = append(hello, []byte("mysql_native_password\x00")...)
		if sourceSQLPacketWrite(conn, 0, hello) != nil {
			return
		}
		request, seq, err := sourceSQLPacketRead(conn)
		if err != nil || seq != 1 || len(request) != 32 || binary.LittleEndian.Uint32(request[:4])&2048 == 0 {
			return
		}
		secured := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}})
		if secured.Handshake() != nil {
			return
		}
		response, seq, err := sourceSQLPacketRead(secured)
		if err != nil || seq != 2 || len(response) < 34 {
			return
		}
		user, rest, ok := sourceSQLNul(response[32:])
		if !ok || len(rest) < 1 {
			return
		}
		n := int(rest[0])
		if len(rest) < 1+n {
			return
		}
		auth := rest[1 : 1+n]
		database, _, ok := sourceSQLNul(rest[1+n:])
		if !ok || user != "source_reader" || database != "source" || subtle.ConstantTimeCompare(auth, sourceNativePassword([]byte("local-independent-source-password"), scramble)) != 1 {
			sourceSQLPacketWrite(secured, 3, append([]byte{0xff, 0x15, 0x04, '#'}, []byte("28000source authentication denied")...))
			return
		}
		if sourceSQLPacketWrite(secured, 3, []byte{0, 0, 0, 2, 0, 0, 0}) != nil {
			return
		}
		for {
			command, _, err := sourceSQLPacketRead(secured)
			if err != nil || len(command) == 0 || command[0] == 1 {
				return
			}
			if command[0] != 3 || string(command[1:]) != "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid" {
				t.Error("unexpected SQL source opener statement")
				return
			}
			queries.Add(1)
			account, role, uuid := "source_reader@localhost", "NONE", "source-tls-fixture-uuid"
			switch mode {
			case "wrong-account":
				account = "application_writer@localhost"
			case "active-role":
				role = "application_role"
			case "wrong-uuid":
				uuid = "other-server"
			}
			values := []string{account, role, "source", uuid}
			if sourceSQLPacketWrite(secured, 1, []byte{4}) != nil {
				return
			}
			for n, name := range []string{"account", "role", "database", "uuid"} {
				column := []byte{}
				for _, field := range []string{"def", "", "", "", name, ""} {
					column = append(column, byte(len(field)))
					column = append(column, []byte(field)...)
				}
				column = append(column, 12, 45, 0, 0, 1, 0, 0, 0xfd, 0, 0, 0, 0, 0)
				if sourceSQLPacketWrite(secured, byte(n+2), column) != nil {
					return
				}
			}
			if sourceSQLPacketWrite(secured, 6, []byte{0xfe, 0, 0, 2, 0}) != nil {
				return
			}
			row := []byte{}
			for _, value := range values {
				row = append(row, byte(len(value)))
				row = append(row, []byte(value)...)
			}
			if sourceSQLPacketWrite(secured, 7, row) != nil {
				return
			}
			if sourceSQLPacketWrite(secured, 8, []byte{0xfe, 0, 0, 2, 0}) != nil {
				return
			}
		}
	}()
	return listener.Addr().String(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), queries
}
func sourceNativePassword(password, scramble []byte) []byte {
	one := sha1.Sum(password)
	two := sha1.Sum(one[:])
	hash := sha1.New()
	hash.Write(scramble)
	hash.Write(two[:])
	result := hash.Sum(nil)
	for n := range result {
		result[n] ^= one[n]
	}
	return result
}
func sourceSQLNul(raw []byte) (string, []byte, bool) {
	at := bytes.IndexByte(raw, 0)
	if at < 0 {
		return "", nil, false
	}
	return string(raw[:at]), raw[at+1:], true
}
func sourceSQLPacketWrite(writer io.Writer, sequence byte, raw []byte) error {
	if len(raw) > 65536 {
		return errors.New("oversized SQL fixture packet")
	}
	header := []byte{byte(len(raw)), byte(len(raw) >> 8), byte(len(raw) >> 16), sequence}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(raw)
	return err
}
func sourceSQLPacketRead(reader io.Reader) ([]byte, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, 0, err
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size > 65536 {
		return nil, 0, errors.New("oversized SQL fixture packet")
	}
	raw := make([]byte, size)
	_, err := io.ReadFull(reader, raw)
	return raw, header[3], err
}
