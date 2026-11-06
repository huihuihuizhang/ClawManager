package install

import (
	"strings"
	"testing"
)

func TestFreshInstallationIdentityNeverAdoptsOtherOrAdvancedState(t *testing.T) {
	id := "installation_expected"
	defaultEngine := freshSQLIdentityState{EnginePresent: true, EngineScope: "installation", Engine: "legacy", EngineVersion: 1}
	exact := defaultEngine
	exact.Present, exact.ControllerUnseen, exact.InstallationID = true, true, id
	foreign := exact
	foreign.InstallationID = "installation_other"
	advanced := exact
	advanced.ConfigVersion = 1
	controllerSeen := exact
	controllerSeen.ControllerUnseen = false
	partial := exact
	partial.EnginePresent = false
	switched := defaultEngine
	switched.Engine, switched.EngineVersion = "v2", 2
	for _, tc := range []struct {
		name  string
		state freshSQLIdentityState
		want  string
	}{
		{"empty", freshSQLIdentityState{}, freshIdentityAbsent},
		{"preexisting default engine from application gate", defaultEngine, freshIdentityAbsent},
		{"same operation readback", exact, freshIdentityInitialized},
		{"other identity", foreign, ""},
		{"already configured", advanced, ""},
		{"controller already seen", controllerSeen, ""},
		{"partial foreign bootstrap", partial, ""},
		{"engine already switched", switched, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.state.classify(id)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("classify = %q, %v", got, err)
			}
		})
	}
}

func TestFreshInstallationIDBindsOperationOriginalNamespaceDatabaseAndPrincipals(t *testing.T) {
	input := FreshInstallationIdentityInputs{OriginalEnrollmentInputs: OriginalEnrollmentInputs{Namespace: "test", LocalAdminUsername: "admin"},
		Operation: strings.Repeat("a", 32), NamespaceUID: "ns", ExpectedServerUUID: "server", ExpectedDatabase: "db"}
	kube := freshKubeIdentity{ClusterUID: "cluster", Username: "operator", UID: "operator-uid", GroupsSHA256: "group-sha"}
	target := freshAppDatabase{AppUID: "app", DBUID: "mysql", ServiceUID: "mysql-service"}
	id, err := freshInstallationID(input, kube, target, 2)
	if err != nil || !strings.HasPrefix(id, "installation_") || len(id) != len("installation_")+32 {
		t.Fatal("bad fresh identity", err)
	}
	if retry, err := freshInstallationID(input, kube, target, 2); err != nil || retry != id {
		t.Fatal("same operation did not produce exact identity", err)
	}
	foreign := target
	foreign.ServiceUID = "other-service"
	if actual, err := freshInstallationID(input, kube, foreign, 2); err != nil || actual == id {
		t.Fatal("replacement MySQL Service could be treated as the original operation", err)
	}
	for _, changed := range []func(*FreshInstallationIdentityInputs, *freshKubeIdentity, *int64){
		func(in *FreshInstallationIdentityInputs, _ *freshKubeIdentity, _ *int64) {
			in.Operation = strings.Repeat("b", 32)
		},
		func(in *FreshInstallationIdentityInputs, _ *freshKubeIdentity, _ *int64) {
			in.NamespaceUID = "replacement"
		},
		func(in *FreshInstallationIdentityInputs, _ *freshKubeIdentity, _ *int64) {
			in.ExpectedServerUUID = "other-server"
		},
		func(in *FreshInstallationIdentityInputs, _ *freshKubeIdentity, _ *int64) {
			in.ExpectedDatabase = "other-db"
		},
		func(_ *FreshInstallationIdentityInputs, actor *freshKubeIdentity, _ *int64) {
			actor.UID = "other-actor"
		},
		func(_ *FreshInstallationIdentityInputs, _ *freshKubeIdentity, user *int64) { *user = 3 },
	} {
		in, actor, user := input, kube, int64(2)
		changed(&in, &actor, &user)
		if actual, err := freshInstallationID(in, actor, target, user); err != nil || actual == id {
			t.Fatal("changed operation/identity could be treated as a retry", err)
		}
	}
}
