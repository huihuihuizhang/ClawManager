package host

import (
	"context"
	"encoding/json"
	"path"
	"path/filepath"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/recovery"
)

type PinnedFile struct {
	Path      string
	Reference recovery.Reference
}
type CatalogArtifact struct {
	Provider     recovery.GatewayConfig
	TLS          TLSFiles
	Bootstrap    recovery.Bootstrap
	Codec        PinnedFile
	WrappingKeys PinnedFile
}
type CatalogProfile struct {
	ID        string
	Provider  recovery.GatewayConfig
	TLS       TLSFiles
	Trust     PinnedFile
	Artifacts []CatalogArtifact
}

// Factories only construct readers from pinned bytes; no discovery or network
// calls are allowed here. Proprietary formats must be explicitly registered.
type CatalogCodecFactory func(CatalogArtifact, []byte, artifact.Keys, recovery.Reader) (recovery.Authenticator, error)
type CatalogCodecs map[string]CatalogCodecFactory

func catalogRevision(c CatalogProfile) string { b, _ := recovery.Marshal(c); return recovery.Hash(b) }
func absolute(p string) bool                  { return filepath.IsAbs(p) || path.IsAbs(p) }
func pinned(p PinnedFile) bool {
	return absolute(p.Path) && p.Reference.Validate() == nil
}
func tlsPaths(t TLSFiles) bool { return absolute(t.CA) && absolute(t.Certificate) && absolute(t.Key) }
func (c Config) validateCatalogs() error {
	seen := map[string]bool{}
	for _, p := range c.Profiles {
		seen[p.Config.ID] = true
	}
	for _, p := range c.Catalogs {
		if !identifier.MatchString(p.ID) || seen[p.ID] || p.Provider.Validate() != nil || p.Provider.AllowAppend || !tlsPaths(p.TLS) || !pinned(p.Trust) {
			return control.ErrInvalid
		}
		seen[p.ID] = true
		if p.Provider.DiscoveryMode == "known_record_only" && len(p.Artifacts) == 0 {
			return control.ErrInvalid
		}
		if selected, ok := c.ActiveRevisions[p.ID]; ok && selected != catalogRevision(p) {
			return control.ErrInvalid
		}
		locations := map[recovery.Locator]bool{}
		for _, a := range p.Artifacts {
			if a.Provider.Validate() != nil || a.Provider.AllowAppend || !tlsPaths(a.TLS) || !pinned(a.Codec) || !pinned(a.WrappingKeys) || a.Bootstrap.ReadCredential.Validate() != nil || a.Bootstrap.CA.Validate() != nil || a.Bootstrap.Identity.Validate() != nil || a.Bootstrap.KEK != a.WrappingKeys.Reference || locations[a.Provider.Location] {
				return control.ErrInvalid
			}
			locations[a.Provider.Location] = true
		}
	}
	for id := range c.ActiveRevisions {
		if !seen[id] {
			return control.ErrInvalid
		}
	}
	return nil
}
func readPinned(p PinnedFile, out any) error {
	raw, e := readPinnedBytes(p)
	if e != nil {
		return e
	}
	defer clear(raw)
	return decodeConfig(raw, out)
}
func readPinnedBytes(p PinnedFile) ([]byte, error) {
	raw, e := ReadFile(p.Path, recovery.MaxDocument)
	if e != nil {
		return nil, e
	}
	if recovery.Hash(raw) != p.Reference.SHA256 {
		clear(raw)
		return nil, control.ErrInvalid
	}
	// Also reject duplicate keys and invalid Unicode before typed decoding.
	if _, e = recovery.Canonical(raw); e != nil {
		clear(raw)
		return nil, control.ErrInvalid
	}
	return raw, nil
}
func gateway(c recovery.GatewayConfig, t TLSFiles) (*recovery.Gateway, error) {
	ca, e := ReadFile(t.CA, 64<<10)
	if e != nil {
		return nil, e
	}
	cert, e := ReadFile(t.Certificate, 64<<10)
	if e != nil {
		return nil, e
	}
	key, e := ReadFile(t.Key, 64<<10)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	return recovery.NewGateway(c, ca, cert, key)
}

// CatalogBindings constructs clients without contacting providers. All readers
// and KEKs come from pinned configuration, never a URL/credential in a record.
func CatalogBindings(configs []CatalogProfile) ([]control.CatalogBinding, func(), error) {
	return CatalogBindingsWithCodecs(configs, nil)
}
func CatalogBindingsWithCodecs(configs []CatalogProfile, codecs CatalogCodecs) ([]control.CatalogBinding, func(), error) {
	bindings := []control.CatalogBinding{}
	closers := []func(){}
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func() ([]control.CatalogBinding, func(), error) {
		closeAll()
		return nil, func() {}, control.ErrNotReady
	}
	for _, c := range configs {
		var trust recovery.Trust
		if readPinned(c.Trust, &trust) != nil || trust.Validate() != nil {
			return fail()
		}
		store, e := gateway(c.Provider, c.TLS)
		if e != nil {
			return fail()
		}
		closers = append(closers, store.Close)
		type source struct {
			config CatalogArtifact
			reader *recovery.Gateway
			auth   recovery.Authenticator
		}
		sources := []source{}
		for _, a := range c.Artifacts {
			var keys artifact.SecretKeys
			if readPinned(a.WrappingKeys, &keys) != nil {
				return fail()
			}
			closers = append(closers, func() {
				for _, key := range keys {
					clear(key)
				}
			})
			reader, e := gateway(a.Provider, a.TLS)
			if e != nil {
				return fail()
			}
			closers = append(closers, reader.Close)
			auth, e := catalogAuthenticator(a, keys, reader, codecs)
			if e != nil {
				return fail()
			}
			sources = append(sources, source{a, reader, auth})
		}
		kinds := []string{}
		if c.Provider.DiscoveryMode != "known_record_only" {
			kinds = append(kinds, "catalog_scan")
		}
		if len(sources) > 0 {
			kinds = append(kinds, "catalog_import")
		}
		if len(kinds) == 0 {
			return fail()
		}
		importer := recovery.Importer{Catalog: recovery.Catalog{Store: store, Trust: trust, Now: func() int64 { return time.Now().UnixMilli() }}, Resolve: func(ctx context.Context, l recovery.Locator, b recovery.Bootstrap) (recovery.Reader, recovery.Authenticator, error) {
			for _, s := range sources {
				if s.config.Provider.Location == l && s.config.Bootstrap == b {
					if s.reader.Probe(ctx, false, false) != nil {
						return nil, nil, recovery.ErrUnavailable
					}
					return s.reader, s.auth, nil
				}
			}
			return nil, nil, recovery.ErrUnavailable
		}}
		bindings = append(bindings, control.CatalogBinding{Profile: control.Profile{ID: c.ID, Revision: catalogRevision(c), Kinds: kinds}, Identity: c.Provider.Identity, Discovery: store, Importer: importer, Probe: func(ctx context.Context, full bool) error {
			if e := store.Probe(ctx, false, full); e != nil {
				return e
			}
			for _, s := range sources {
				if e := s.reader.Probe(ctx, false, false); e != nil {
					return e
				}
			}
			return nil
		}})
	}
	return bindings, closeAll, nil
}
func catalogAuthenticator(a CatalogArtifact, keys artifact.Keys, reader recovery.Reader, codecs CatalogCodecs) (recovery.Authenticator, error) {
	raw, e := readPinnedBytes(a.Codec)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var format struct{ Format string }
	if json.Unmarshal(raw, &format) != nil || format.Format == "" {
		return nil, control.ErrInvalid
	}
	if format.Format == recovery.StagingCodec {
		var descriptor recovery.CodecDescriptor
		if decodeConfig(raw, &descriptor) != nil {
			return nil, control.ErrInvalid
		}
		return recovery.NewStagingAuthenticator(descriptor, keys)
	}
	if factory := codecs[format.Format]; factory != nil {
		auth, e := factory(a, raw, keys, reader)
		if e != nil || auth == nil {
			return nil, control.ErrNotReady
		}
		return auth, nil
	}
	return nil, control.ErrNotReady
}
func runCatalogOnly(ctx context.Context, c Config, report func(string), codecs CatalogCodecs) error {
	var keys Keys
	if ReadJSON(c.KeysFile, &keys) != nil || len(keys.Vault[keys.VaultVersion]) != 32 {
		return control.ErrInvalid
	}
	defer keys.Clear()
	bindings, close, e := CatalogBindingsWithCodecs(c.Catalogs, codecs)
	if e != nil {
		return e
	}
	defer close()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	db, e := control.OpenControlDatabase(bounded, c.ControlDatabase)
	cancel()
	if e != nil {
		return e
	}
	defer db.Close()
	store := control.SQLStore{DB: db}
	vault := control.Vault{Store: store, WriteVersion: keys.VaultVersion, Keys: keys.Vault}
	executor := control.NewCatalogExecutor(store, vault, nil, bindings)
	return (control.Service{Store: store, Publisher: control.Publisher{Store: store}, Controller: control.Controller{Store: store, Executor: executor, Owner: c.Owner, Lease: 30 * time.Second, RecoveryTimeout: time.Minute}, PollInterval: time.Second, ProbeTimeout: 10 * time.Second, OnError: report}).Run(ctx)
}
