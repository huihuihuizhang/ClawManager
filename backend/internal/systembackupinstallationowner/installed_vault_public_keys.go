package systembackupinstallationowner

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// Compare the actual RSA trust set, not the provider's PEM whitespace or key
// order. Reject extra material, duplicate keys and non-RSA/weak keys; this does
// not add any key that was not read from the authenticated Kubernetes API.
func installedVaultPublicKeysEqual(actual, expected []string) bool {
	parse := func(values []string) (map[string]bool, bool) {
		if len(values) == 0 || len(values) > 32 {
			return nil, false
		}
		out := map[string]bool{}
		for _, value := range values {
			if len(value) > 16384 {
				return nil, false
			}
			raw := bytes.TrimSpace([]byte(value))
			if !bytes.HasPrefix(raw, []byte("-----BEGIN ")) || bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
				return nil, false
			}
			block, rest := pem.Decode(raw)
			if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || !bytes.HasPrefix(raw, []byte("-----BEGIN "+block.Type+"-----")) {
				return nil, false
			}
			var key *rsa.PublicKey
			switch block.Type {
			case "PUBLIC KEY":
				parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return nil, false
				}
				key, _ = parsed.(*rsa.PublicKey)
			case "RSA PUBLIC KEY":
				var err error
				key, err = x509.ParsePKCS1PublicKey(block.Bytes)
				if err != nil {
					return nil, false
				}
			default:
				return nil, false
			}
			if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
				return nil, false
			}
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil || out[string(der)] {
				return nil, false
			}
			out[string(der)] = true
		}
		return out, true
	}
	a, ok := parse(actual)
	b, valid := parse(expected)
	if !ok || !valid || len(a) != len(b) {
		return false
	}
	for key := range a {
		if !b[key] {
			return false
		}
	}
	return true
}
