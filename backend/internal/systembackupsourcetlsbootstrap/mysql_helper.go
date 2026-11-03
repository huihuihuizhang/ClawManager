// Package systembackupsourcetlsbootstrap bootstraps original source transport
// before migrations/enrollment/Installer exist. It does not issue task grants.
package systembackupsourcetlsbootstrap

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var ErrBootstrap = errors.New("original source TLS bootstrap refused; inspect operation receipt")
var bootstrapOperation = regexp.MustCompile(`^[a-f0-9]{32}$`)
var bootstrapDatabase = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

type MySQLHelperRequest struct {
	Version, Mode, Database, AdminUsername, Socket, Operation, ExpectedServerUUID string
	AdminPassword                                                                 []byte
	DNSNames, IPAddresses                                                         []string
	Deadline                                                                      time.Time
}
type MySQLNativeTLS struct {
	Version, ServerUUID, Database, SQLAccount, Hostname, DataDirectory, Socket, CAFile, CertificateFile, KeyFile string
	AdminID                                                                                                      int64
	AdminUsername                                                                                                string
	Port                                                                                                         int
	CA, Certificate                                                                                              []byte
	CertificateSHA256, KeySHA256                                                                                 string
	IssuerKeyAvailable                                                                                           bool
	Clock                                                                                                        time.Time
}
type MySQLHelperResult struct {
	Version, Mode, Operation, State, OriginalCertificateSHA256, OriginalKeySHA256 string
	Native                                                                        MySQLNativeTLS
	TLSVerified                                                                   bool
	TLSVersion                                                                    uint16
}
type mysqlTLSJournal struct {
	Version, Operation, ServerUUID, Database, AdminUsername, CAFile, CertificateFile, KeyFile string
	OriginalCertificateSHA256, OriginalKeySHA256, NewCertificateSHA256, NewKeySHA256          string
	OriginalCASHA256                                                                          string
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func nativeFile(file string, max int64, private bool) ([]byte, os.FileInfo, error) {
	before, e := os.Lstat(file)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > max || private && before.Mode().Perm()&0077 != 0 {
		return nil, nil, ErrBootstrap
	}
	raw, e := os.ReadFile(file)
	after, e2 := os.Lstat(file)
	if e != nil || e2 != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != before.Size() {
		clear(raw)
		return nil, nil, ErrBootstrap
	}
	return raw, before, nil
}
func contained(data, file string) (string, error) {
	if !filepath.IsAbs(file) {
		file = filepath.Join(data, file)
	}
	file = filepath.Clean(file)
	rel, e := filepath.Rel(data, file)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || !filepath.IsAbs(file) {
		return "", ErrBootstrap
	}
	return file, nil
}
func certificate(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrBootstrap
	}
	return x509.ParseCertificate(block.Bytes)
}
func signer(raw []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrBootstrap
	}
	if value, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		if key, ok := value.(crypto.Signer); ok {
			return key, nil
		}
	}
	if key, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return key, nil
	}
	if key, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
		return key, nil
	}
	return nil, ErrBootstrap
}
func helperSocket(requested string) (string, error) {
	choices := []string{requested}
	if requested == "" {
		choices = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/tmp/mysql.sock"}
	}
	var original os.FileInfo
	selected := ""
	for _, candidate := range choices {
		if candidate == "" || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
			continue
		}
		info, e := os.Stat(candidate)
		if e != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		if original != nil && !os.SameFile(original, info) {
			return "", ErrBootstrap
		}
		original, selected = info, candidate
	}
	if selected == "" {
		return "", ErrBootstrap
	}
	return selected, nil
}
func originalRootPassword() (string, error) {
	password := os.Getenv("MYSQL_ROOT_PASSWORD")
	if password == "" && os.Getenv("MYSQL_ROOT_PASSWORD_FILE") != "" {
		raw, _, e := nativeFile(os.Getenv("MYSQL_ROOT_PASSWORD_FILE"), 65536, false)
		if e != nil {
			return "", ErrBootstrap
		}
		password = strings.TrimSuffix(string(raw), "\n")
		clear(raw)
	}
	return password, nil
}

func localSQL(ctx context.Context, request MySQLHelperRequest) (*sql.DB, error) {
	socket, e := helperSocket(request.Socket)
	if e != nil {
		return nil, e
	}
	password, e := originalRootPassword()
	if e != nil {
		return nil, e
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = password
	cfg.Net = "unix"
	cfg.Addr = socket
	cfg.DBName = request.Database
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	// This is container-local Unix IPC inside the pre-existing TLS Kubernetes
	// exec channel, not a plaintext remote SQL or a relaxed mysqltls.Material.
	db, e := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd = ""
	password = ""
	if e != nil {
		return nil, ErrBootstrap
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if db.PingContext(ctx) != nil {
		db.Close()
		return nil, ErrBootstrap
	}
	return db, nil
}
func readNative(ctx context.Context, db *sql.DB, request MySQLHelperRequest) (MySQLNativeTLS, error) {
	var out MySQLNativeTLS
	var ca, cert, key string
	if db.QueryRowContext(ctx, `SELECT VERSION(),@@server_uuid,DATABASE(),CURRENT_USER(),@@hostname,@@datadir,@@socket,@@ssl_ca,@@ssl_cert,@@ssl_key,@@port,UTC_TIMESTAMP(6)`).Scan(&out.Version, &out.ServerUUID, &out.Database, &out.SQLAccount, &out.Hostname, &out.DataDirectory, &out.Socket, &ca, &cert, &key, &out.Port, &out.Clock) != nil || out.Database != request.Database || out.ServerUUID == "" || out.SQLAccount != "root@localhost" || !filepath.IsAbs(out.DataDirectory) || ca == "" || cert == "" || key == "" {
		return out, ErrBootstrap
	}
	var stored, role, provider string
	var active bool
	if db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`, request.AdminUsername).Scan(&out.AdminID, &out.AdminUsername, &stored, &role, &active, &provider) != nil || out.AdminID < 1 || out.AdminUsername != request.AdminUsername || role != "admin" || !active || provider != "local" || bcrypt.CompareHashAndPassword([]byte(stored), request.AdminPassword) != nil {
		return out, ErrBootstrap
	}
	var e error
	out.DataDirectory = filepath.Clean(out.DataDirectory)
	if out.CAFile, e = contained(out.DataDirectory, ca); e != nil {
		return out, e
	}
	if out.CertificateFile, e = contained(out.DataDirectory, cert); e != nil {
		return out, e
	}
	if out.KeyFile, e = contained(out.DataDirectory, key); e != nil {
		return out, e
	}
	if out.CA, e = readPublic(out.CAFile); e != nil {
		return out, e
	}
	if out.Certificate, e = readPublic(out.CertificateFile); e != nil {
		return out, e
	}
	private, _, e := nativeFile(out.KeyFile, 65536, true)
	if e != nil {
		return out, e
	}
	out.KeySHA256 = digest(private)
	clear(private)
	out.CertificateSHA256 = digest(out.Certificate)
	issuerFile := filepath.Join(filepath.Dir(out.CAFile), strings.TrimSuffix(filepath.Base(out.CAFile), ".pem")+"-key.pem")
	issuerRaw, _, e := nativeFile(issuerFile, 65536, true)
	if e == nil {
		caCert, e1 := certificate(out.CA)
		issuer, e2 := signer(issuerRaw)
		if e1 == nil && e2 == nil {
			one, _ := x509.MarshalPKIXPublicKey(caCert.PublicKey)
			two, _ := x509.MarshalPKIXPublicKey(issuer.Public())
			out.IssuerKeyAvailable = bytes.Equal(one, two) && caCert.IsCA
		}
		clear(issuerRaw)
	}
	return out, nil
}
func readPublic(file string) ([]byte, error) {
	raw, _, e := nativeFile(file, 65536, false)
	return raw, e
}
func nativeSame(first, last MySQLNativeTLS) bool {
	return first.ServerUUID == last.ServerUUID && first.Database == last.Database && first.AdminID == last.AdminID && first.AdminUsername == last.AdminUsername && first.CAFile == last.CAFile && bytes.Equal(first.CA, last.CA) && first.CertificateFile == last.CertificateFile && first.KeyFile == last.KeyFile
}
func fileOwner(info os.FileInfo) (int, int, error) {
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !v.IsValid() {
		return 0, 0, ErrBootstrap
	}
	uid, gid := v.FieldByName("Uid"), v.FieldByName("Gid")
	if !uid.IsValid() || !gid.IsValid() || !uid.CanUint() || !gid.CanUint() {
		return 0, 0, ErrBootstrap
	}
	return int(uid.Uint()), int(gid.Uint()), nil
}
func newPrivate(file string, raw []byte, mode os.FileMode, uid, gid int) error {
	f, e := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return ErrBootstrap
	}
	defer f.Close()
	if os.Geteuid() == 0 {
		if f.Chown(uid, gid) != nil {
			return ErrBootstrap
		}
	} else if uid != os.Geteuid() {
		return ErrBootstrap
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		return ErrBootstrap
	}
	if f.Sync() != nil {
		return ErrBootstrap
	}
	return f.Close()
}
func syncDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return ErrBootstrap
	}
	defer f.Close()
	return f.Sync()
}
func replaceNative(file string, raw []byte, operation string, allowed ...string) error {
	current, info, e := nativeFile(file, 65536, strings.Contains(filepath.Base(file), "key"))
	if e != nil {
		return e
	}
	defer clear(current)
	matched := false
	for _, expected := range allowed {
		matched = matched || digest(current) == expected
	}
	if !matched {
		return ErrBootstrap
	}
	uid, gid, e := fileOwner(info)
	if e != nil {
		return e
	}
	temporary := filepath.Join(filepath.Dir(file), ".clawreef-"+filepath.Base(file)+"-"+operation+".new")
	if newPrivate(temporary, raw, info.Mode().Perm(), uid, gid) != nil {
		return ErrBootstrap
	}
	if os.Rename(temporary, file) != nil {
		return ErrBootstrap
	}
	return syncDirectory(filepath.Dir(file))
}
func signedServer(native MySQLNativeTLS, request MySQLHelperRequest) ([]byte, []byte, error) {
	if !native.IssuerKeyAvailable {
		return nil, nil, ErrBootstrap
	}
	ca, e := certificate(native.CA)
	if e != nil {
		return nil, nil, e
	}
	old, e := certificate(native.Certificate)
	if e != nil {
		return nil, nil, e
	}
	issuerFile := filepath.Join(filepath.Dir(native.CAFile), strings.TrimSuffix(filepath.Base(native.CAFile), ".pem")+"-key.pem")
	issuerRaw, _, e := nativeFile(issuerFile, 65536, true)
	if e != nil {
		return nil, nil, e
	}
	defer clear(issuerRaw)
	issuer, e := signer(issuerRaw)
	if e != nil {
		return nil, nil, e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, e
	}
	now := time.Now().UTC()
	until := now.Add(365 * 24 * time.Hour)
	if ca.NotAfter.Before(until) {
		until = ca.NotAfter
	}
	if !until.After(now.Add(time.Hour)) {
		return nil, nil, ErrBootstrap
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: old.Subject, NotBefore: now.Add(-time.Minute), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: append([]string{}, old.DNSNames...), IPAddresses: append([]net.IP{}, old.IPAddresses...)}
	seen := map[string]bool{}
	for _, name := range leaf.DNSNames {
		seen[name] = true
	}
	for _, name := range request.DNSNames {
		if name == "" || len(name) > 253 || strings.ContainsAny(name, "*\\\x00\r\n /:") {
			return nil, nil, ErrBootstrap
		}
		if !seen[name] {
			leaf.DNSNames = append(leaf.DNSNames, name)
			seen[name] = true
		}
	}
	for _, raw := range request.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, nil, ErrBootstrap
		}
		found := false
		for _, old := range leaf.IPAddresses {
			found = found || old.Equal(ip)
		}
		if !found {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, issuer)
	if e != nil {
		return nil, nil, e
	}
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}
func probeTLS(ctx context.Context, native MySQLNativeTLS, request MySQLHelperRequest) (uint16, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(native.CA) || len(request.DNSNames) == 0 {
		return 0, ErrBootstrap
	}
	var verified atomic.Bool
	var version atomic.Uint32
	transport := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: request.DNSNames[0], VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return ErrBootstrap
		}
		cert, _ := certificate(native.Certificate)
		if cert == nil || !bytes.Equal(cert.Raw, state.PeerCertificates[0].Raw) {
			return ErrBootstrap
		}
		verified.Store(true)
		version.Store(uint32(state.Version))
		return nil
	}}
	name := "clawreef-bootstrap-" + request.Operation
	if mysql.RegisterTLSConfig(name, transport) != nil {
		return 0, ErrBootstrap
	}
	defer mysql.DeregisterTLSConfig(name)
	cfg := mysql.NewConfig()
	cfg.User = "root"
	password, e := originalRootPassword()
	if e != nil {
		return 0, e
	}
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(native.Port))
	cfg.DBName = request.Database
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.TLSConfig = name
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	db, e := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd = ""
	password = ""
	if e != nil {
		return 0, ErrBootstrap
	}
	defer db.Close()
	var uuid string
	if db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != native.ServerUUID || !verified.Load() {
		return 0, ErrBootstrap
	}
	return uint16(version.Load()), nil
}

// RunMySQLHelper is invoked ONLY inside the selected original MySQL container
// through the operator's existing verified Kubernetes TLS exec connection.
// SQL uses the actual local Unix socket and the original active/local/admin
// bcrypt row, before Installer/migrations/enrollment are needed.
func RunMySQLHelper(ctx context.Context, request MySQLHelperRequest) (MySQLHelperResult, error) {
	var zero MySQLHelperResult
	if runtime.GOOS != "linux" || ctx == nil || ctx.Err() != nil || request.Version != "original-source-mysql-tls-request.v1" || !bootstrapOperation.MatchString(request.Operation) || !bootstrapDatabase.MatchString(request.Database) || request.AdminUsername == "" || len(request.AdminPassword) == 0 || len(request.AdminPassword) > 1024 || len(request.DNSNames) > 32 || len(request.IPAddresses) > 32 || request.Deadline.IsZero() || !time.Now().Before(request.Deadline) {
		return zero, ErrBootstrap
	}
	until := time.Now().Add(90 * time.Second)
	if request.Deadline.Before(until) {
		until = request.Deadline
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	db, e := localSQL(bounded, request)
	if e != nil {
		return zero, e
	}
	defer db.Close()
	native, e := readNative(bounded, db, request)
	if e != nil {
		return zero, e
	}
	result := MySQLHelperResult{Version: "original-source-mysql-tls-result.v1", Mode: request.Mode, Operation: request.Operation, Native: native}
	if request.Mode == "inspect" {
		result.State = "authenticated_local_original_sql_only"
		return result, nil
	}
	if request.ExpectedServerUUID == "" || request.ExpectedServerUUID != native.ServerUUID || len(request.DNSNames) == 0 {
		return zero, ErrBootstrap
	}
	directory := filepath.Join(native.DataDirectory, ".clawreef-source-tls-"+request.Operation)
	if request.Mode == "rollback" {
		raw, _, e := nativeFile(filepath.Join(directory, "journal.json"), 65536, true)
		var journal mysqlTLSJournal
		if e != nil || json.Unmarshal(raw, &journal) != nil || journal.Version != "original-source-mysql-tls-journal.v1" || journal.Operation != request.Operation || journal.ServerUUID != native.ServerUUID || journal.Database != native.Database || journal.AdminUsername != native.AdminUsername || journal.CAFile != native.CAFile || journal.OriginalCASHA256 != digest(native.CA) || journal.CertificateFile != native.CertificateFile || journal.KeyFile != native.KeyFile {
			return zero, ErrBootstrap
		}
		cert, _, e := nativeFile(filepath.Join(directory, "original-cert.pem"), 65536, true)
		if e != nil || digest(cert) != journal.OriginalCertificateSHA256 {
			return zero, ErrBootstrap
		}
		key, _, e := nativeFile(filepath.Join(directory, "original-key.pem"), 65536, true)
		if e != nil || digest(key) != journal.OriginalKeySHA256 {
			return zero, ErrBootstrap
		}
		defer clear(key)
		if replaceNative(native.CertificateFile, cert, request.Operation+"-rollback", journal.OriginalCertificateSHA256, journal.NewCertificateSHA256) != nil || replaceNative(native.KeyFile, key, request.Operation+"-rollback", journal.OriginalKeySHA256, journal.NewKeySHA256) != nil {
			return zero, ErrBootstrap
		}
		if _, e := db.ExecContext(bounded, "ALTER INSTANCE RELOAD TLS"); e != nil {
			return zero, ErrBootstrap
		}
		actual, e := readNative(bounded, db, request)
		if e != nil || !nativeSame(native, actual) || digest(actual.CA) != journal.OriginalCASHA256 || actual.CertificateSHA256 != journal.OriginalCertificateSHA256 || actual.KeySHA256 != journal.OriginalKeySHA256 {
			return zero, ErrBootstrap
		}
		result.Native = actual
		result.State = "original_tls_files_restored_not_backup_authority"
		return result, nil
	}
	if request.Mode != "apply" || !native.IssuerKeyAvailable || !supportedMySQLReload(native.Version) {
		return zero, ErrBootstrap
	}
	newCert, newKey, e := signedServer(native, request)
	if e != nil {
		return zero, e
	}
	defer clear(newKey)
	oldKey, _, e := nativeFile(native.KeyFile, 65536, true)
	if e != nil {
		return zero, e
	}
	defer clear(oldKey)
	if os.Mkdir(directory, 0700) != nil {
		return zero, ErrBootstrap
	}
	journal := mysqlTLSJournal{"original-source-mysql-tls-journal.v1", request.Operation, native.ServerUUID, native.Database, native.AdminUsername, native.CAFile, native.CertificateFile, native.KeyFile, native.CertificateSHA256, native.KeySHA256, digest(newCert), digest(newKey), digest(native.CA)}
	journalRaw, _ := json.Marshal(journal)
	for name, content := range map[string][]byte{"original-cert.pem": native.Certificate, "original-key.pem": oldKey, "journal.json": journalRaw} {
		if newPrivate(filepath.Join(directory, name), content, 0600, os.Geteuid(), os.Getegid()) != nil {
			return zero, ErrBootstrap
		}
	}
	if syncDirectory(directory) != nil {
		return zero, ErrBootstrap
	}
	current, e := readNative(bounded, db, request)
	if e != nil || !nativeSame(native, current) || current.CertificateSHA256 != native.CertificateSHA256 || current.KeySHA256 != native.KeySHA256 {
		return zero, ErrBootstrap
	}
	if replaceNative(native.CertificateFile, newCert, request.Operation, native.CertificateSHA256) != nil || replaceNative(native.KeyFile, newKey, request.Operation, native.KeySHA256) != nil {
		return zero, ErrBootstrap
	}
	// Default rollback-on-error is intentional: never use NO ROLLBACK ON ERROR.
	if _, e := db.ExecContext(bounded, "ALTER INSTANCE RELOAD TLS"); e != nil {
		return zero, ErrBootstrap
	}
	actual, e := readNative(bounded, db, request)
	if e != nil || !nativeSame(native, actual) || actual.CertificateSHA256 != digest(newCert) || actual.KeySHA256 != digest(newKey) {
		return zero, ErrBootstrap
	}
	version, e := probeTLS(bounded, actual, request)
	if e != nil {
		return zero, e
	}
	last, e := readNative(bounded, db, request)
	if e != nil || !nativeSame(actual, last) || last.CertificateSHA256 != actual.CertificateSHA256 || last.KeySHA256 != actual.KeySHA256 {
		return zero, ErrBootstrap
	}
	result.Native = last
	result.State = "source_mysql_original_ca_san_leaf_reloaded"
	result.OriginalCertificateSHA256 = native.CertificateSHA256
	result.OriginalKeySHA256 = native.KeySHA256
	result.TLSVerified = true
	result.TLSVersion = version
	return result, nil
}

func supportedMySQLReload(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) != 3 || parts[0] != "8" {
		return false
	}
	if parts[1] == "4" {
		return true
	}
	if parts[1] != "0" {
		return false
	}
	patch := strings.FieldsFunc(parts[2], func(r rune) bool { return r < '0' || r > '9' })
	if len(patch) == 0 {
		return false
	}
	n, e := strconv.Atoi(patch[0])
	return e == nil && n >= 16
}
