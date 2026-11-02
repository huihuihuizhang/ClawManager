package systembackupkms

import (
	"crypto/x509"
	"net/url"
	"strings"
)

// ValidateCaptureConfig checks the same pure Config structure as newTransit,
// without constructing a resolver/client or claiming any provider authority.
// The worker still applies its unchanged checks at actual consumption.
func ValidateCaptureConfig(c Config) error {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.Opaque != "" || strings.ContainsAny(c.Endpoint, "?#\r\n") || !text(c.InstallationID) || !keyName.MatchString(c.KeyName) || !validKey(c.Key) || c.NotBefore.IsZero() || !c.NotAfter.After(c.NotBefore) || len(c.CAPEM) > 65536 || !digest.MatchString(c.CASHA256) || hash(c.CAPEM) != c.CASHA256 {
		return ErrBinding
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) {
		return ErrBinding
	}
	return nil
}
