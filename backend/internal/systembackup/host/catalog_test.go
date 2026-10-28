package host

import (
	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/recovery"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func catalogConfigFixture() Config {
	ref := recovery.Reference{ID: "catalog", Version: "v1", SHA256: strings.Repeat("a", 64)}
	return Config{Owner: "catalog-controller", ControlDatabase: "/credentials/control.json", KeysFile: "/credentials/vault.json", Catalogs: []CatalogProfile{{ID: "catalog", Provider: recovery.GatewayConfig{Endpoint: "https://provider.invalid", Identity: ref, Location: recovery.Locator{Provider: "s3", Bucket: "catalog", Prefix: "catalog-root", FailureDomain: "external"}, DiscoveryMode: "inventory_manifest"}, TLS: TLSFiles{"/tls/ca", "/tls/cert", "/tls/key"}, Trust: PinnedFile{"/credentials/trust.json", ref}}}}
}

type catalogAuthFixture struct{}

func (catalogAuthFixture) Authenticate(context.Context, recovery.Manifest, recovery.Object, io.Reader) error {
	return recovery.ErrUnavailable
}
func TestCatalogCodecFactoryRequiresExplicitRegistrationAndPinnedBytes(t *testing.T) {
	raw := []byte(`{"Format":"owner-framing.v2","OwnerFields":{"version":2}}`)
	path := filepath.Join(t.TempDir(), "owner.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	a := CatalogArtifact{Codec: PinnedFile{path, recovery.Reference{ID: "owner-codec", Version: "v2", SHA256: recovery.Hash(raw)}}}
	if _, e := catalogAuthenticator(a, nil, nil, nil); e == nil {
		t.Fatal("unknown codec fell back")
	}
	calls := 0
	codecs := CatalogCodecs{"owner-framing.v2": func(c CatalogArtifact, b []byte, _ artifact.Keys, _ recovery.Reader) (recovery.Authenticator, error) {
		calls++
		if c.Codec.Reference != a.Codec.Reference || string(b) != string(raw) {
			t.Fatal("wrong descriptor")
		}
		return catalogAuthFixture{}, nil
	}}
	if _, e := catalogAuthenticator(a, nil, nil, codecs); e != nil || calls != 1 {
		t.Fatal(e, calls)
	}
	a.Codec.Reference.SHA256 = strings.Repeat("a", 64)
	if _, e := catalogAuthenticator(a, nil, nil, codecs); e == nil || calls != 1 {
		t.Fatal("changed file reached owner", e, calls)
	}
}
func TestCatalogOnlyConfigurationNeedsNoSourceKubernetesOrNodeIdentity(t *testing.T) {
	c := catalogConfigFixture()
	if c.Validate() != nil {
		t.Fatal("catalog-only requires source")
	}
	c.Catalogs[0].Provider.AllowAppend = true
	if c.Validate() == nil {
		t.Fatal("catalog reader got append authority")
	}
	c = catalogConfigFixture()
	c.Catalogs[0].Provider.Endpoint = "http://provider.invalid"
	if c.Validate() == nil {
		t.Fatal("insecure bridge")
	}
	c = catalogConfigFixture()
	c.Catalogs = append(c.Catalogs, c.Catalogs[0])
	if c.Validate() == nil {
		t.Fatal("ambiguous catalog identity")
	}
}
func TestPinnedConfigurationRejectsDriftDuplicateKeysAndUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pinned.json")
	for _, raw := range []string{`{"ID":"one","ID":"two"}`, `{"Unexpected":"secret-not-for-errors"}`, `{"ID":"one"}`} {
		if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		pin := PinnedFile{p, recovery.Reference{ID: "pin", Version: "v1", SHA256: recovery.Hash([]byte(raw))}}
		var out struct{ ID string }
		e := readPinned(pin, &out)
		if raw == `{"ID":"one"}` {
			if e != nil {
				t.Fatal(e)
			}
			pin.Reference.SHA256 = strings.Repeat("a", 64)
			if readPinned(pin, &out) == nil {
				t.Fatal("file drift accepted")
			}
		} else if e == nil || strings.Contains(e.Error(), "secret-not-for-errors") {
			t.Fatal("ambiguous config or leaked error", e)
		}
	}
}
