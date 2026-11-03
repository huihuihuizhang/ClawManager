package db

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"clawreef/internal/config"
	mysql "github.com/go-sql-driver/mysql"
)

var errBusinessMySQLTLS = errors.New("business database TLS configuration rejected")

func businessMySQLTLSSelected(c config.DatabaseConfig) bool {
	return c.TLSCAFile != "" || c.TLSCASHA256 != "" || c.TLSServerName != ""
}

// Each connector gets an immutable private TLS clone. No global TLS profile,
// system roots, insecure mode, optional upgrade or plaintext retry is used.
func businessMySQLTLS(c config.DatabaseConfig) (*tls.Config, error) {
	if !businessMySQLTLSSelected(c) {
		return nil, nil
	}
	if !filepath.IsAbs(c.TLSCAFile) || filepath.Clean(c.TLSCAFile) != c.TLSCAFile || len(c.TLSCASHA256) != 64 || c.TLSCASHA256 != strings.ToLower(c.TLSCASHA256) || !businessMySQLServerName(c.TLSServerName) {
		return nil, errBusinessMySQLTLS
	}
	if _, err := hex.DecodeString(c.TLSCASHA256); err != nil {
		return nil, errBusinessMySQLTLS
	}
	canonical, err := filepath.EvalSymlinks(c.TLSCAFile)
	if err != nil || canonical != c.TLSCAFile {
		return nil, errBusinessMySQLTLS
	}
	before, err := os.Lstat(c.TLSCAFile)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 65536 {
		return nil, errBusinessMySQLTLS
	}
	f, err := os.Open(c.TLSCAFile)
	if err != nil {
		return nil, errBusinessMySQLTLS
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, errBusinessMySQLTLS
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || int64(len(raw)) != actual.Size() {
		return nil, errBusinessMySQLTLS
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != c.TLSCASHA256 {
		return nil, errBusinessMySQLTLS
	}
	roots := x509.NewCertPool()
	remaining := raw
	count := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errBusinessMySQLTLS
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errBusinessMySQLTLS
		}
		roots.AddCert(cert)
		count++
		remaining = rest
	}
	after, err := os.Lstat(c.TLSCAFile)
	if err != nil || !os.SameFile(actual, after) || after.Size() != actual.Size() || !after.ModTime().Equal(actual.ModTime()) || count == 0 {
		return nil, errBusinessMySQLTLS
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.TLSServerName, RootCAs: roots}, nil
}
func businessMySQLServerName(name string) bool {
	if name == "" || len(name) > 253 || strings.TrimSpace(name) != name {
		return false
	}
	if net.ParseIP(name) != nil {
		return true
	}
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
func businessMySQLDriverConfig(c config.DatabaseConfig, dsn string) (*mysql.Config, error) {
	driver, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, errBusinessMySQLTLS
	}
	tlsConfig, err := businessMySQLTLS(c)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		if driver.Net != "tcp" || driver.TLS != nil || driver.TLSConfig != "" || driver.AllowFallbackToPlaintext {
			return nil, errBusinessMySQLTLS
		}
		driver.TLS = tlsConfig
		driver.AllowFallbackToPlaintext = false
	}
	return driver, nil
}
