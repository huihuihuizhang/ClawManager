// Package systembackupcatrust supplies the public CA resource portion of
// bootstrap admission. Deployment composition owns the exact binding; HTTP and
// approval JSON cannot create one. Provider permissions are separate resources.
package systembackupcatrust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	sec "clawreef/internal/systembackupsecurity"
)

// Binding is trusted deployment composition, not a request/config DTO. Identity
// hashes come from the existing reviewed identity rules, NEVER from key bytes.
// Original controlled mapping must bind these pins to installation/provider/
// scope and authorize the exact target IP and hostname. New does not attest that
// the original deployment mapping or its non-implementer review was delivered.
type Binding struct {
	InstallationID, ServerUUID, Database, ConfigSHA256 string
	Purpose, ProviderIdentityHash, ScopeHash           string
	DescriptorFile, DescriptorSHA256, CAFile, CASHA256 string
	Endpoint                                           string
	TargetIP                                           netip.Addr
	NotBefore, ExpiresAt                               time.Time
}

func (Binding) String() string               { return "BootstrapCATrustBinding" }
func (Binding) GoString() string             { return "BootstrapCATrustBinding" }
func (Binding) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }

type Validator struct {
	binding       Binding
	host, address string
	now           func() time.Time
}
type check struct {
	validator             *Validator
	observedAt, expiresAt time.Time
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var installationPattern = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var serverPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var databasePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// New closes all targets before any resource read or connection. TLS dials the
// explicit deployment IP while verifying the original hostname: no request DNS,
// redirect, environment proxy or fallback address is involved.
func New(binding Binding) (*Validator, error) {
	fail := func() (*Validator, error) { return nil, sec.ErrRegistrationUnavailable }
	if !installationPattern.MatchString(binding.InstallationID) || !serverPattern.MatchString(binding.ServerUUID) || !databasePattern.MatchString(binding.Database) || !digestPattern.MatchString(binding.ConfigSHA256) || !digestPattern.MatchString(binding.ProviderIdentityHash) || !digestPattern.MatchString(binding.ScopeHash) || !digestPattern.MatchString(binding.DescriptorSHA256) || !digestPattern.MatchString(binding.CASHA256) || (binding.Purpose != "artifact_ca" && binding.Purpose != "evidence_ca") || binding.NotBefore.IsZero() || !binding.ExpiresAt.After(binding.NotBefore) {
		return fail()
	}
	for _, name := range []string{binding.DescriptorFile, binding.CAFile} {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return fail()
		}
	}
	if !binding.TargetIP.IsValid() || binding.TargetIP.IsUnspecified() || binding.TargetIP.IsMulticast() || binding.TargetIP.Zone() != "" {
		return fail()
	}
	u, err := url.Parse(binding.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return fail()
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fail()
	}
	return &Validator{binding: binding, host: u.Hostname(), address: net.JoinHostPort(binding.TargetIP.Unmap().String(), port), now: time.Now}, nil
}

func (*Validator) String() string               { return "BootstrapCATrustValidator" }
func (*Validator) GoString() string             { return "BootstrapCATrustValidator" }
func (*Validator) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*check) String() string                   { return "BootstrapCATrustCheck" }
func (*check) GoString() string                 { return "BootstrapCATrustCheck" }
func (*check) MarshalJSON() ([]byte, error)     { return nil, sec.ErrRegistrationUnavailable }

func pinnedFile(name, digest string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, sec.ErrRegistrationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	sum := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) > limit || hex.EncodeToString(sum[:]) != digest {
		return nil, sec.ErrRegistrationUnavailable
	}
	return raw, nil
}

func (v *Validator) files() (refs.SecurityReference, []byte, error) {
	failed := func() (refs.SecurityReference, []byte, error) {
		return refs.SecurityReference{}, nil, sec.ErrRegistrationUnavailable
	}
	raw, err := pinnedFile(v.binding.DescriptorFile, v.binding.DescriptorSHA256, 16384)
	if err != nil {
		return failed()
	}
	ref, err := refs.DecodeSecurityReference(raw, v.binding.DescriptorSHA256)
	if err != nil || ref.Kind() != "ca_bundle" || ref.Purpose() != v.binding.Purpose || ref.ProviderIdentity() != v.binding.ProviderIdentityHash || ref.ScopeHash() != v.binding.ScopeHash {
		return failed()
	}
	ca, err := pinnedFile(v.binding.CAFile, v.binding.CASHA256, 262144)
	if err != nil {
		return failed()
	}
	return ref, ca, nil
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (v *Validator) live(now time.Time) bool {
	return !now.IsZero() && !now.Before(v.binding.NotBefore) && now.Before(v.binding.ExpiresAt)
}

func (v *Validator) Prepare(ctx context.Context, g sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	fail := func() (sec.BootstrapResourceCheck, error) { return nil, sec.ErrRegistrationUnavailable }
	if v == nil || ctx == nil || ctx.Err() != nil || v.now == nil || g.InstallationID != v.binding.InstallationID || g.ServerUUID != v.binding.ServerUUID || g.Database != v.binding.Database || g.ConfigSHA256 != v.binding.ConfigSHA256 || config.SHA256() != v.binding.ConfigSHA256 || len(config.CanonicalJSON()) == 0 {
		return fail()
	}
	started := v.now().UTC()
	if !v.live(started) {
		return fail()
	}
	ref, raw, err := v.files()
	if err != nil {
		return fail()
	}
	matched := 0
	for _, pin := range config.References() {
		if pin.Purpose == v.binding.Purpose && ref.MatchesBootstrapPin(pin) {
			matched++
		}
	}
	if matched != 1 {
		return fail()
	}
	pool := x509.NewCertPool()
	expires := v.binding.ExpiresAt
	certificates := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		// pem.Decode otherwise skips arbitrary leading text. Only public CERTIFICATE
		// blocks and whitespace are permitted; private keys/junk cannot be ignored.
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return fail()
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fail()
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || started.Before(cert.NotBefore) || !started.Before(cert.NotAfter) {
			return fail()
		}
		pool.AddCert(cert)
		expires = earliest(expires, cert.NotAfter)
		certificates++
		if certificates > 128 {
			return fail()
		}
		raw = rest
	}
	if certificates == 0 {
		return fail()
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: v.host}}
	networkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(networkCtx, "tcp", v.address)
	if err != nil {
		return fail()
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return fail()
	}
	state := tlsConn.ConnectionState()
	closeErr := conn.Close()
	if closeErr != nil || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || ctx.Err() != nil {
		return fail()
	}
	for _, cert := range state.VerifiedChains[0] {
		expires = earliest(expires, cert.NotAfter)
	}
	observed := v.now().UTC()
	expires = earliest(expires, started.Add(30*time.Second))
	if !v.live(observed) || observed.Before(started) || !observed.Before(expires) {
		return fail()
	}
	// Check the exact local authority inputs again after external work. Recheck
	// later performs the same reads without opening another network connection.
	if _, _, err = v.files(); err != nil {
		return fail()
	}
	finished := v.now().UTC()
	if ctx.Err() != nil || finished.Before(observed) || !finished.Before(expires) || !v.live(finished) {
		return fail()
	}
	copy := *v
	return &check{validator: &copy, observedAt: observed, expiresAt: expires}, nil
}

func (c *check) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if c == nil || c.validator == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return sec.ErrRegistrationUnavailable
	}
	v := c.validator
	wall := v.now().UTC()
	for _, clock := range []time.Time{now, wall} {
		if !v.live(clock) || clock.Before(c.observedAt) || !clock.Before(c.expiresAt) {
			return sec.ErrRegistrationUnavailable
		}
	}
	if _, _, err := v.files(); err != nil {
		return sec.ErrRegistrationUnavailable
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != v.binding.ServerUUID || database != v.binding.Database || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	// A delayed local/SQL read must not carry an expired observation through
	// the caller's final guard.
	wall = v.now().UTC()
	if !v.live(wall) || wall.Before(c.observedAt) || !wall.Before(c.expiresAt) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

// These assertions keep this candidate compatible with the real bootstrap
// boundary; production composition still requires owner review and real pins.
var _ sec.BootstrapResourceValidator = (*Validator)(nil)
var _ sec.BootstrapResourceCheck = (*check)(nil)
