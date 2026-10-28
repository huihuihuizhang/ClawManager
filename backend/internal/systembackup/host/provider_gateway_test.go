package host

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/recovery"
)

func gatewayConfigFixture() ProviderGatewayConfig {
	r := recovery.Reference{ID: "native-owner", Version: "v1", SHA256: strings.Repeat("a", 64)}
	return ProviderGatewayConfig{Listen: "127.0.0.1:8443", TLS: TLSFiles{CA: "/not-mounted/ca.pem", Certificate: "/not-mounted/server.pem", Key: "/not-mounted/key.pem"}, ControlDatabase: "/not-mounted/control.json", Server: recovery.GatewayServerConfig{Identity: r, Location: recovery.Locator{Provider: "s3", Bucket: "isolated", Prefix: "root", FailureDomain: "test"}, DiscoveryMode: "inventory_manifest", AllowAppend: true, Clients: map[string][]string{strings.Repeat("b", 64): {"capabilities", "observe", "open", "conditional_create", "begin_snapshot", "snapshot_page"}}, TimeoutMS: 30000}, BackendModule: r, BackendConfig: PinnedFile{Path: "/not-mounted/backend.json", Reference: r}}
}
func TestProviderGatewayOfflineCheckAndMissingAdapterOpenNothing(t *testing.T) {
	c := gatewayConfigFixture()
	raw, _ := json.Marshal(c)
	file := filepath.Join(t.TempDir(), "gateway.json")
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("fixture write")
	}
	loaded, e := LoadProviderGateway(file)
	if e != nil {
		t.Fatal("offline check read absent secrets", e)
	}
	if e = RunProviderGateway(context.Background(), loaded, nil); e != control.ErrNotReady {
		t.Fatal("missing adapter attempted environment access", e)
	}
	for _, mutate := range []func(*ProviderGatewayConfig){func(c *ProviderGatewayConfig) { c.Server.Clients = nil }, func(c *ProviderGatewayConfig) { c.ControlDatabase = "" }, func(c *ProviderGatewayConfig) { c.Server.TimeoutMS = 0 }, func(c *ProviderGatewayConfig) { c.Listen = "127.0.0.1:abc" }, func(c *ProviderGatewayConfig) {
		c.Server.Clients = map[string][]string{strings.Repeat("b", 64): {"delete"}}
	}} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	if os.WriteFile(file, append([]byte(`{"Listen":"127.0.0.1:1",`), raw[1:]...), 0600) != nil {
		t.Fatal("fixture write")
	}
	if _, e = LoadProviderGateway(file); e == nil {
		t.Fatal("duplicate configuration key accepted")
	}
}
