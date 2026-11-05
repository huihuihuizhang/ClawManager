package systembackupkekadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
)

func TestProviderPermitEnabledOnlyNeedsActualOriginalForwardAndSQLView(t *testing.T) {
	i := &ProviderPermitIssuer{cfg: ProviderPermitIssuerConfig{Binding: reg.Binding{InstallationID: "installation_original"}}}
	g := ProviderPermitIssuerGrant{Workload: ControllerVerifierWorkload{ControllerOwner: "original-controller", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64)}}
	a := d.Authority{InstallationID: "installation_original", ClaimOwner: "original-controller", ConfigVersion: 2, ConfigSHA256: strings.Repeat("b", 64)}
	// No descriptor, caller auth SHA, ready bit or nil view can stand in for
	// the original signed predecessor and the actual same-view SQL proof.
	if p, e := i.bindEnabledOnlyScope(context.Background(), nil, g, a); e == nil || p != nil {
		t.Fatal("missing actual original source/view accepted")
	}
	if e := ((*permitEnabledOnlyLineage)(nil)).recheck(context.Background(), nil, i, g, a); e == nil {
		t.Fatal("Task2 scope accepted without same-view private proof")
	}
	if _, e := json.Marshal(&permitEnabledOnlyLineage{}); e == nil {
		t.Fatal("private scoped proof serialized")
	}
}
