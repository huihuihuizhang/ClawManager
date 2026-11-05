package systembackupexecution

import (
	"reflect"
	"testing"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
)

func TestExplicitRuntimeScopeBindingRejectsForeignAndDrift(t *testing.T) {
	raw := []domain.SourceInstance{{ID: 3, UserID: 1, Generation: 1, Type: "openclaw", Mode: "lite", Status: "running"}, {ID: 7, UserID: 1, Generation: 0, Type: "opencode", Mode: "lite", Status: "error"}, {ID: 9, UserID: 1, Generation: 0, Type: "deepseek-harness", Mode: "lite", Status: "error"}}
	scope, e := domain.NewKnownErrorLiteRuntimeTestScope("synthetic-installation", "synthetic-server", "synthetic-db", "synthetic-namespace", raw)
	if e != nil {
		t.Fatal(e)
	}
	cfg := DeploymentConfig{InstallationID: scope.InstallationID, SourceServerUUID: scope.ServerUUID, SourceDatabase: scope.Database, NamespaceUID: scope.NamespaceUID, RuntimeSources: &RuntimeSourceConfig{RuntimeTestScope: scope}}
	inv := b.SourceInventory{Database: scope.Database, ServerUUID: scope.ServerUUID, Instances: append([]b.InstanceIdentity{}, raw...)}
	if bindRuntimeTestScope(cfg, &inv) != nil || !reflect.DeepEqual(inv.Instances, raw) || !reflect.DeepEqual(inv.RuntimeTestScope, scope) {
		t.Fatal("binding changed raw SQL or lost original scope")
	}
	runtime, e := runtimeTestProjection(cfg, inv)
	if e != nil || len(runtime.Instances) != 1 || len(inv.Instances) != 3 {
		t.Fatal("projection changed complete original inventory")
	}
	foreign := inv
	foreign.ServerUUID = "different-server"
	if bindRuntimeTestScope(cfg, &foreign) == nil {
		t.Fatal("foreign source header accepted")
	}
	foreign = inv
	foreign.RuntimeTestScope = scope.Clone()
	foreign.RuntimeTestScope.NamespaceUID = "different-namespace"
	if bindRuntimeTestScope(cfg, &foreign) == nil {
		t.Fatal("foreign scope accepted")
	}
	changed := inv
	changed.Instances = append([]b.InstanceIdentity{}, raw...)
	changed.Instances[1].Generation++
	if bindRuntimeTestScope(cfg, &changed) == nil {
		t.Fatal("generation drift accepted")
	}
	strict := cfg
	strict.RuntimeSources = &RuntimeSourceConfig{}
	if bindRuntimeTestScope(strict, &inv) == nil {
		t.Fatal("scope admitted by default full configuration")
	}
}
