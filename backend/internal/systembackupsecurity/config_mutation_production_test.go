package systembackupsecurity

import (
	"context"
	"strings"
	"testing"
)

func TestConfigMutationProductionRequiresEveryActualOwner(t *testing.T) {
	missing := MissingConfigMutationProductionOwners(ConfigMutationResolverSources{})
	if len(missing) != 31 {
		t.Fatal("did not retain nine registries/twenty refs/cross/deployment", missing)
	}
	for _, name := range missing {
		if name == "registry_bytes" {
			t.Fatal("fixed file reader reported as an external adapter")
		}
	}
	if p, err := NewConfigMutationProduction(ConfigMutationProductionConfig{}); err == nil || p != nil {
		t.Fatal("missing real config authority/resolver supplied a service")
	}
}

func TestConfigMutationProductionReasonNeverEchoesSubmittedSecrets(t *testing.T) {
	secret := "Bearer submitted-secret password=hidden"
	out, err := redactProductionConfigChangeReason(context.Background(), &secret)
	if err != nil || out == nil || *out != "[redacted]" || strings.Contains(*out, "submitted-secret") || secret != "Bearer submitted-secret password=hidden" {
		t.Fatal("free-text audit redaction failed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := redactProductionConfigChangeReason(ctx, &secret); err == nil {
		t.Fatal("cancelled redaction succeeded")
	}
}
