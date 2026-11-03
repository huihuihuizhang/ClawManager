package mysqltls

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

	mysql "github.com/go-sql-driver/mysql"
)

// Material is selected only by the administrator's pinned configuration.
// CAFile contains public CA bytes, mounted as a read-only regular file.
type Material struct {
	CAFile     string `json:"ca_file"`
	CASHA256   string `json:"ca_sha256"`
	ServerName string `json:"server_name"`
}

// Validate checks completeness and syntax without accessing files or dialing.
func (c Material) Validate() error {
	if !c.Selected() {
		return nil
	}
	if !filepath.IsAbs(c.CAFile) || filepath.Clean(c.CAFile) != c.CAFile || len(c.CASHA256) != 64 || c.CASHA256 != strings.ToLower(c.CASHA256) || !validServerName(c.ServerName) {
		return ErrConfiguration
	}
	if _, err := hex.DecodeString(c.CASHA256); err != nil {
		return ErrConfiguration
	}
	return nil
}

var ErrConfiguration = errors.New("database TLS configuration rejected")

func (c Material) Selected() bool {
	return c.CAFile != "" || c.CASHA256 != "" || c.ServerName != ""
}

// Each connector gets an immutable private TLS clone. No global TLS profile,
// system roots, insecure mode, optional upgrade or plaintext retry is used.
func (c Material) TLSConfig() (*tls.Config, error) {
	if !c.Selected() {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(c.CAFile)
	if err != nil || canonical != c.CAFile {
		return nil, ErrConfiguration
	}
	before, err := os.Lstat(c.CAFile)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 65536 {
		return nil, ErrConfiguration
	}
	f, err := os.Open(c.CAFile)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || int64(len(raw)) != actual.Size() {
		return nil, ErrConfiguration
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != c.CASHA256 {
		return nil, ErrConfiguration
	}
	roots := x509.NewCertPool()
	remaining := raw
	count := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrConfiguration
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrConfiguration
		}
		roots.AddCert(cert)
		count++
		remaining = rest
	}
	after, err := os.Lstat(c.CAFile)
	if err != nil || !os.SameFile(actual, after) || after.Size() != actual.Size() || !after.ModTime().Equal(actual.ModTime()) || count == 0 {
		return nil, ErrConfiguration
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.ServerName, RootCAs: roots}, nil
}
func validServerName(name string) bool {
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

// Apply installs private pinned TLS on an already identity-validated DSN.
// The zero material preserves the caller's legacy path. Partial selection fails.
func (c Material) Apply(driver *mysql.Config) error {
	if driver == nil {
		return ErrConfiguration
	}
	tlsConfig, err := c.TLSConfig()
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		if driver.Net != "tcp" || driver.TLS != nil || driver.TLSConfig != "" || driver.AllowFallbackToPlaintext {
			return ErrConfiguration
		}
		driver.TLS = tlsConfig
		driver.AllowFallbackToPlaintext = false
	}
	return nil
}
