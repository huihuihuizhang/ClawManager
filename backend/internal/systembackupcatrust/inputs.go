package systembackupcatrust

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"

	sec "clawreef/internal/systembackupsecurity"
)

// InspectInputs checks only exact local public descriptor/CA inputs. It never
// dials TLS, opens SQL, establishes permissions, or returns source diagnostics.
// A later real Prepare remains mandatory, even after this inspection succeeds.
func (v *Validator) InspectInputs(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) error {
	if v == nil || ctx == nil || ctx.Err() != nil || v.now == nil || g.InstallationID != v.binding.InstallationID || g.ServerUUID != v.binding.ServerUUID || g.Database != v.binding.Database || g.ConfigSHA256 != v.binding.ConfigSHA256 || c.SHA256() != v.binding.ConfigSHA256 {
		return sec.ErrRegistrationUnavailable
	}
	start := v.now().UTC()
	if !v.live(start) {
		return sec.ErrRegistrationUnavailable
	}
	ref, raw, err := v.files()
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	matched := 0
	for _, pin := range c.References() {
		if pin.Purpose == v.binding.Purpose && ref.MatchesBootstrapPin(pin) {
			matched++
		}
	}
	if matched != 1 {
		return sec.ErrRegistrationUnavailable
	}
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return sec.ErrRegistrationUnavailable
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return sec.ErrRegistrationUnavailable
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || start.Before(cert.NotBefore) || !start.Before(cert.NotAfter) {
			return sec.ErrRegistrationUnavailable
		}
		count++
		if count > 128 {
			return sec.ErrRegistrationUnavailable
		}
		raw = rest
	}
	end := v.now().UTC()
	if count == 0 || ctx.Err() != nil || end.Before(start) || !v.live(end) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
