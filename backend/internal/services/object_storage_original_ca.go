package services

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"clawreef/internal/config"
)

// This CA belongs to this concrete object-storage client only. It changes no
// global root pool, TLS skip setting, fallback endpoint or credential purpose.
func objectStorageOriginalCATransport(cfg config.ObjectStorageConfig) (http.RoundTripper, error) {
	if cfg.TLSCAFile == "" && cfg.TLSCASHA256 == "" {
		return nil, nil
	}
	failed := errors.New("object storage original TLS CA unavailable")
	digest, e := hex.DecodeString(cfg.TLSCASHA256)
	if !cfg.UseSSL || cfg.Endpoint == "" || !filepath.IsAbs(cfg.TLSCAFile) || filepath.Clean(cfg.TLSCAFile) != cfg.TLSCAFile || e != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != cfg.TLSCASHA256 {
		return nil, failed
	}
	f, e := os.Open(cfg.TLSCAFile)
	if e != nil {
		return nil, failed
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 65536 {
		return nil, failed
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, failed
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, failed
	}
	current, e := os.Stat(cfg.TLSCAFile)
	if e != nil || !os.SameFile(after, current) {
		return nil, failed
	}
	actual := sha256.Sum256(raw)
	if hex.EncodeToString(actual[:]) != cfg.TLSCASHA256 {
		return nil, failed
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, failed
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, failed
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return transport, nil
}
