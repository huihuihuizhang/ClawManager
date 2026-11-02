package systembackupkms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPureCaptureConfigValidationKeepsWorkerConstructorChecks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("pure config validation performed provider I/O") }))
	t.Cleanup(server.Close)
	for _, fault := range []string{"valid", "zero-not-before", "wrong-ca", "mutable-key-version", "empty-key-name", "invalid-endpoint"} {
		cfg := testConfig(server)
		switch fault {
		case "zero-not-before":
			cfg.NotBefore = time.Time{}
		case "wrong-ca":
			cfg.CASHA256 = hash([]byte("another CA"))
		case "mutable-key-version":
			cfg.Key.RegistryVersion = "latest"
		case "empty-key-name":
			cfg.KeyName = ""
		case "invalid-endpoint":
			cfg.Endpoint = "https://:8200"
		}
		pure := ValidateCaptureConfig(cfg)
		generator, worker := NewCaptureGenerator(cfg, resolverFunc(func(context.Context, Access) (Grant, error) {
			t.Error("constructor acquired resolver authority")
			return Grant{}, ErrPermission
		}))
		if generator != nil {
			generator.Close()
		}
		if (pure == nil) != (worker == nil) || fault == "valid" && pure != nil || fault != "valid" && pure == nil {
			t.Fatal("materializer/worker pure structure diverged", fault, pure, worker)
		}
	}
}
