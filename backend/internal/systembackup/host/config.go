// Package host wires the controller exclusively from mounted configuration.
// Reading/checking configuration has no network or database side effects.
package host

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/profile"
	"clawreef/internal/systembackup/quiesce"
)

type TLSFiles struct{ CA, Certificate, Key string }
type Profile struct {
	Config                                                         profile.Config
	SourceCredential, SourceAdminCredential, TargetAdminCredential string
	RuntimeCA, RuntimeToken, StorageCA, StorageToken               string
	WriterCA, WriterToken                                          string
	Objects                                                        *ObjectSource
}
type Config struct {
	Owner, Listen, ControlDatabase, Kubeconfig          string
	StagingPath, EvidencePath, ArtifactPath             string
	Relay, NodeProof                                    TLSFiles
	NodeEndpoints                                       map[string]quiesce.ProofEndpoint
	IssuerCertificate, IssuerKey, TrustDomain, KeysFile string
	Profiles                                            []Profile
	Catalogs                                            []CatalogProfile
	ActiveRevisions                                     map[string]string
}
type Keys struct {
	VaultVersion    string
	Vault, Wrapping map[string][]byte
	Signers         map[string]ed25519.PrivateKey
	Verify          map[string]ed25519.PublicKey
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,48}$`)

func ReadJSON(path string, v any) error {
	b, e := ReadFile(path, 4<<20)
	if e != nil {
		return e
	}
	defer clear(b)
	return decodeConfig(b, v)
}
func decodeConfig(b []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil || decoder.Decode(new(any)) != io.EOF {
		return control.ErrInvalid
	}
	return nil
}
func ReadFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, control.ErrInvalid
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, control.ErrInvalid
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, control.ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, control.ErrInvalid
	}
	return b, nil
}
func Load(path string) (Config, error) {
	var c Config
	if e := ReadJSON(path, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if !identifier.MatchString(c.Owner) || len(c.Profiles)+len(c.Catalogs) == 0 || c.validateCatalogs() != nil {
		return control.ErrInvalid
	}
	if len(c.Profiles) == 0 {
		if !absolute(c.ControlDatabase) || !absolute(c.KeysFile) {
			return control.ErrInvalid
		}
		return nil
	}
	if c.Listen == "" || len(c.NodeEndpoints) == 0 || c.TrustDomain == "" {
		return control.ErrInvalid
	}
	paths := []string{c.ControlDatabase, c.StagingPath, c.EvidencePath, c.ArtifactPath, c.Relay.CA, c.Relay.Certificate, c.Relay.Key, c.NodeProof.CA, c.NodeProof.Certificate, c.NodeProof.Key, c.IssuerCertificate, c.IssuerKey, c.KeysFile}
	if c.Kubeconfig != "" {
		paths = append(paths, c.Kubeconfig)
	}
	for _, p := range c.Profiles {
		if p.Config.Validate() != nil {
			return control.ErrInvalid
		}
		if p.Config.Mode != "target" {
			paths = append(paths, p.SourceCredential, p.SourceAdminCredential)
		}
		if p.Config.Mode != "backup" {
			paths = append(paths, p.TargetAdminCredential)
		}
		if p.RuntimeToken != "" {
			paths = append(paths, p.RuntimeCA, p.RuntimeToken)
		}
		if p.Config.ExclusiveNFSProofURL != "" {
			paths = append(paths, p.StorageCA, p.StorageToken)
		}
		if p.Config.WriterProofURL != "" {
			paths = append(paths, p.WriterCA, p.WriterToken)
		}
		if p.Objects != nil {
			paths = append(paths, p.Objects.CA, p.Objects.Credentials)
		}
	}
	for _, p := range paths {
		// The runtime is Linux-only, but --check-config may run on a Windows
		// development host against Linux deployment paths. Actual file reads
		// still require native absolute paths in ReadFile.
		if !filepath.IsAbs(p) && !path.IsAbs(p) {
			return control.ErrInvalid
		}
	}
	if filepath.Clean(c.StagingPath) == filepath.Clean(c.EvidencePath) || filepath.Clean(c.StagingPath) == filepath.Clean(c.ArtifactPath) || filepath.Clean(c.EvidencePath) == filepath.Clean(c.ArtifactPath) {
		return control.ErrInvalid
	}
	seen := map[string]bool{}
	selected := map[string]bool{}
	for _, p := range c.Profiles {
		m := (&profile.Driver{Config: p.Config}).Metadata()
		key := m.ID + "/" + m.Revision
		if seen[key] {
			return control.ErrInvalid
		}
		seen[key] = true
		if active, ok := c.ActiveRevisions[m.ID]; ok && active != m.Revision {
			continue
		}
		if selected[m.ID] {
			return control.ErrInvalid
		}
		selected[m.ID] = true
	}
	for id := range c.ActiveRevisions {
		for _, catalog := range c.Catalogs {
			if catalog.ID == id {
				selected[id] = true
			}
		}
		if !selected[id] {
			return control.ErrInvalid
		}
	}
	return nil
}
func (k *Keys) Clear() {
	for _, m := range []map[string][]byte{k.Vault, k.Wrapping} {
		for _, b := range m {
			clear(b)
		}
	}
	for _, b := range k.Signers {
		clear(b)
	}
}
func (c Config) materials() (Keys, control.IdentityIssuer, error) {
	var keys Keys
	if ReadJSON(c.KeysFile, &keys) != nil || len(keys.Vault[keys.VaultVersion]) != 32 {
		return keys, control.IdentityIssuer{}, control.ErrInvalid
	}
	for _, m := range []map[string][]byte{keys.Vault, keys.Wrapping} {
		for version, b := range m {
			if !identifier.MatchString(version) || len(b) != 32 {
				return keys, control.IdentityIssuer{}, control.ErrInvalid
			}
		}
	}
	for id, private := range keys.Signers {
		if !identifier.MatchString(id) || len(private) != ed25519.PrivateKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), keys.Verify[id]) {
			return keys, control.IdentityIssuer{}, control.ErrInvalid
		}
	}
	for _, p := range c.Profiles {
		if len(keys.Wrapping[p.Config.KeyVersion]) != 32 || len(keys.Signers[p.Config.SignerID]) != ed25519.PrivateKeySize {
			return keys, control.IdentityIssuer{}, control.ErrInvalid
		}
	}
	cert, e := ReadFile(c.IssuerCertificate, 64<<10)
	if e != nil {
		return keys, control.IdentityIssuer{}, e
	}
	key, e := ReadFile(c.IssuerKey, 64<<10)
	if e != nil {
		return keys, control.IdentityIssuer{}, e
	}
	defer clear(key)
	block, _ := pem.Decode(cert)
	if block == nil {
		return keys, control.IdentityIssuer{}, control.ErrInvalid
	}
	certificate, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !certificate.IsCA {
		return keys, control.IdentityIssuer{}, control.ErrInvalid
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return keys, control.IdentityIssuer{}, control.ErrInvalid
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return keys, control.IdentityIssuer{}, control.ErrInvalid
	}
	roots, e := ReadFile(c.Relay.CA, 64<<10)
	return keys, control.IdentityIssuer{Certificate: certificate, Signer: signer, ServerRoots: roots, TrustDomain: c.TrustDomain}, e
}
