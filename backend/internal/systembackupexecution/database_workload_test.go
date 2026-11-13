package systembackupexecution

import (
	"slices"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDatabaseGraphIdentityIsNotAStopWriter(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-host", "replaced-deployment", "replaced-parent", "not-ready", "duplicate-host", "stop-writer", "runtime-writer", "controller"} {
		t.Run(scenario, func(t *testing.T) {
			controller := true
			cfg := DeploymentConfig{Namespace: "ns", DatabaseWorkload: &PlatformDeployment{Namespace: "ns", Name: "sql", UID: "db-uid"}}
			api := &observedWriterAPI{objects: []observedWriterAPIObject{
				{Kind: "Deployment", Namespace: "ns", Name: "sql", UID: "db-uid", Replicas: 1, Ready: 1, Generation: 2, ObservedGeneration: 2},
				{Kind: "ReplicaSet", Namespace: "ns", Name: "sql-rs", UID: "rs-uid", Owners: []metav1.OwnerReference{{Kind: "Deployment", Name: "sql", UID: "db-uid", Controller: &controller}}},
				{Kind: "Pod", Namespace: "ns", Name: "sql-pod", UID: "pod-uid", Running: true, Owners: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "sql-rs", UID: "rs-uid", Controller: &controller}}},
			}}
			sql := []productionSQLSourceMetadata{{DatabaseHostname: "sql-pod"}}
			want := map[string]string{}
			switch scenario {
			case "wrong-host":
				sql[0].DatabaseHostname = "foreign"
			case "replaced-deployment":
				api.objects[0].UID = "new"
			case "replaced-parent":
				api.objects[1].UID = "new"
			case "not-ready":
				api.objects[2].Running = false
			case "duplicate-host":
				p := api.objects[2]
				p.Name = "other"
				p.Hostname = "sql-pod"
				api.objects = append(api.objects, p)
			case "stop-writer":
				cfg.Writers = []PlatformDeployment{*cfg.DatabaseWorkload}
			case "runtime-writer":
				cfg.RuntimeSources = &RuntimeSourceConfig{Deployments: []PlatformDeployment{*cfg.DatabaseWorkload}}
			case "controller":
				want["Deployment/ns/sql"] = "db-uid"
			}
			err := addDatabaseGraphRoot(cfg, api, want, sql)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
			if len(cfg.Writers) != 0 && scenario == "valid" {
				t.Fatal("database promoted to stop writer")
			}
		})
	}
}

func TestDatabaseWorkloadBothGraphsKeepUnknownAndControllerRejection(t *testing.T) {
	for _, scenario := range []string{"valid", "unknown", "replaced", "controller-writer", "no-sql", "missing-database-pin"} {
		t.Run(scenario, func(t *testing.T) {
			s, api := sourceWriterGraphFixture()
			s.Config.DatabaseWorkload = &PlatformDeployment{Namespace: "source", Name: "sql", UID: "db-uid"}
			controller := true
			api.objects = append(api.objects,
				observedWriterAPIObject{Kind: "Deployment", Namespace: "source", Name: "sql", UID: "db-uid", Replicas: 1, Ready: 1},
				observedWriterAPIObject{Kind: "ReplicaSet", Namespace: "source", Name: "sql-rs", UID: "db-rs", Owners: []metav1.OwnerReference{{Kind: "Deployment", Name: "sql", UID: "db-uid", Controller: &controller}}},
				observedWriterAPIObject{Kind: "Pod", Namespace: "source", Name: "sql-pod", UID: "db-pod", Running: true, Owners: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "sql-rs", UID: "db-rs", Controller: &controller}}})
			metadata := []productionSQLSourceMetadata{{DatabaseHostname: "sql-pod"}}
			switch scenario {
			case "unknown":
				api.objects = append(api.objects, observedWriterAPIObject{Kind: "Deployment", Namespace: "source", Name: "unknown", UID: "unknown"})
			case "replaced":
				api.objects[4].UID = "replacement"
			case "controller-writer":
				s.Config.Writers = append(s.Config.Writers, PlatformDeployment{Namespace: "source", Name: "controller", UID: "controller-uid"})
			case "no-sql":
				metadata = nil
			case "missing-database-pin":
				s.Config.DatabaseWorkload = nil
			}
			x := &bootstrapSourceRegistryReader{config: s.Config, materials: *s.captureMaterials}
			for name, err := range map[string]error{"native": x.checkWriterGraph(b.SourceInventory{}, api, metadata...), "production": checkObservedWriterGraph(s, b.SourceInventory{}, api, metadata...)} {
				if (err == nil) != (scenario == "valid") {
					t.Fatalf("%s: %v", name, err)
				}
			}
		})
	}
}

func TestDatabaseCaptureGrantsNeverIncludeDeploymentMutation(t *testing.T) {
	cfg := captureAccessFixture(t)
	cfg.DatabaseWorkload = &PlatformDeployment{Namespace: cfg.Namespace, Name: "sql", UID: "db-uid"}
	access, err := RequiredCaptureAccess(cfg)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range access {
		rule := entry.Rule
		if entry.Namespace != cfg.Namespace || !slices.Contains(rule.Resources, "deployments") || len(rule.ResourceNames) != 0 && !slices.Contains(rule.ResourceNames, "sql") {
			continue
		}
		found = true
		if !slices.Equal(rule.Verbs, []string{"get"}) {
			t.Fatal("database became a mutable deployment", rule)
		}
	}
	if !found {
		t.Fatal("database observation grant missing")
	}
	cfg.Writers = append(cfg.Writers, *cfg.DatabaseWorkload)
	if _, err := RequiredCaptureAccess(cfg); err == nil {
		t.Fatal("database stop authority admitted")
	}
	cfg = captureAccessFixture(t)
	cfg.Writers = append(cfg.Writers, PlatformDeployment{Namespace: cfg.Namespace, Name: "controller", UID: cfg.ControllerOwner})
	if cfg.Validate() == nil {
		t.Fatal("controller stop authority admitted")
	}
}
