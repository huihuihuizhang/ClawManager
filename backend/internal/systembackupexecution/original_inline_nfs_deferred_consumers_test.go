package systembackupexecution

import (
	"context"
	"reflect"
	"testing"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"k8s.io/client-go/kubernetes"
)

// Reuse the actual inline NFS provider/API fixture. The ordinary stopped Pro
// row still requires its declared path; it does not require an unrelated live
// writer session. Both real consumer methods receive the COMPLETE inventory,
// including both exact deferred rows required by the original scope schema.
// Fake Kubernetes checks are component regression evidence, never native proof.
func TestOriginalInlineNFSDeferredScopeRealConsumers(t *testing.T) {
	consumers := []struct {
		name  string
		check func(context.Context, DeploymentConfig, kubernetes.Interface, []b.InstanceIdentity) error
	}{
		{"bootstrap-registry", func(ctx context.Context, cfg DeploymentConfig, client kubernetes.Interface, rows []b.InstanceIdentity) error {
			x := &bootstrapSourceRegistryReader{config: cfg}
			return x.checkNFSRuntimeWorkspace(ctx, client, rows, nil)
		}},
		{"deployment-runtime", func(ctx context.Context, cfg DeploymentConfig, client kubernetes.Interface, rows []b.InstanceIdentity) error {
			s := &DeploymentService{Config: cfg}
			return s.checkNFSRuntimeWorkspace(ctx, client, rows)
		}},
	}
	for _, consumer := range consumers {
		for _, fault := range []string{"", "unapproved", "deferred-generation", "deferred-user", "deferred-workspace", "deferred-namespace", "deferred-status", "deferred-type", "normal-path-missing", "normal-generation", "provider-service-uid"} {
			t.Run(consumer.name+"/"+fault, func(t *testing.T) {
				workspace, normal, client := inlineNFSFixture(t)
				normal.Type, normal.Mode, normal.OS, normal.Status = "openclaw", "pro", "linux", "stopped"
				raw := []b.InstanceIdentity{
					normal,
					{ID: 31, UserID: 3, Generation: 0, Type: "opencode", Mode: "lite", OS: "linux", Status: "error", Workspace: "/work/users/3/instances/31", Namespace: normal.Namespace},
					{ID: 42, UserID: 3, Generation: 0, Type: "deepseek-harness", Mode: "lite", OS: "linux", Status: "error", Workspace: "/work/users/3/instances/42", Namespace: normal.Namespace},
				}
				approved, err := domain.NewKnownErrorLiteRuntimeTestScope("synthetic-installation", "synthetic-server", "synthetic-db", "synthetic-namespace", raw)
				if err != nil {
					t.Fatal(err)
				}
				cfg := DeploymentConfig{InstallationID: approved.InstallationID, Namespace: normal.Namespace, NamespaceUID: approved.NamespaceUID,
					SourceServerUUID: approved.ServerUUID, SourceDatabase: approved.Database, Workspace: workspace,
					RuntimeSources: &RuntimeSourceConfig{WorkspaceRoot: "/work", RuntimeTestScope: approved}}
				inv := b.SourceInventory{Database: approved.Database, ServerUUID: approved.ServerUUID, Users: []int{3}, Instances: append([]b.InstanceIdentity{}, raw...)}
				if bindRuntimeTestScope(cfg, &inv) != nil || len(inv.Instances) != 3 || !reflect.DeepEqual(inv.Instances, raw) {
					t.Fatal("complete original SQL inventory/scope binding lost")
				}
				if len(cfg.Workspace.NFS.OriginalPaths) != 1 || cfg.Workspace.NFS.OriginalPaths[0].InstanceID != normal.ID ||
					!approved.IsDeferred(inv.Instances[1]) || !approved.IsDeferred(inv.Instances[2]) {
					t.Fatal("fixture must omit only the exact two deferred paths")
				}
				switch fault {
				case "unapproved":
					cfg.RuntimeSources.RuntimeTestScope = nil
				case "deferred-generation":
					inv.Instances[1].Generation++
				case "deferred-user":
					inv.Instances[1].UserID++
				case "deferred-workspace":
					inv.Instances[1].Workspace += "/changed"
				case "deferred-namespace":
					inv.Instances[1].Namespace += "-changed"
				case "deferred-status":
					inv.Instances[1].Status = "running"
				case "deferred-type":
					inv.Instances[1].Type = "openclaw"
				case "normal-path-missing":
					cfg.Workspace.NFS.OriginalPaths[0].InstanceID = normal.ID + 1
					cfg.Workspace.NFS.OriginalPaths[0].SubPath = "users/3/instances/8"
				case "normal-generation":
					inv.Instances[0].Generation++
				case "provider-service-uid":
					cfg.Workspace.NFS.Provider.ServiceUID += "-replaced"
				}
				beforeRows := append([]b.InstanceIdentity{}, inv.Instances...)
				beforeScope := inv.RuntimeTestScope.Clone()
				originalScope := approved.Clone()
				err = consumer.check(context.Background(), cfg, client, inv.Instances)
				if (err == nil) != (fault == "") {
					t.Fatalf("actual consumer admission mismatch: fault=%q err=%v", fault, err)
				}
				if len(inv.Instances) != 3 || !reflect.DeepEqual(inv.Instances, beforeRows) ||
					!reflect.DeepEqual(inv.RuntimeTestScope, beforeScope) || !reflect.DeepEqual(approved, originalScope) {
					t.Fatal("consumer filtered SQL rows or rewrote original approved scope")
				}
				if len(client.Actions()) == 0 {
					t.Fatal("real consumer must independently read provider API identities")
				}
				for _, action := range client.Actions() {
					if action.GetVerb() != "get" {
						t.Fatal("workspace source validation mutated Kubernetes")
					}
				}
			})
		}
	}
}
