package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestNativeWriterDiagnosticPreservesCauseAndHidesPrivateError(t *testing.T) {
	for _, tc := range []struct {
		observed error
		reason   string
	}{
		{nil, "validation"}, {context.DeadlineExceeded, "deadline"},
		{apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "private-pod", errors.New("private-token")), "forbidden"},
		{errors.New("private-token"), "read_error"},
	} {
		err := writerNativeReadFailure(install.ErrInstall, context.Background(), "native_agent_capabilities", "RuntimeAgent", 7, tc.observed)
		var f *WriterAPIReadFailure
		if !errors.As(err, &f) || !errors.Is(err, install.ErrInstall) || f.Reason != tc.reason || f.InstanceID != 7 {
			t.Fatalf("diagnostic changed rejection: %v", err)
		}
		raw, _ := json.Marshal(f)
		if strings.Contains(string(raw)+err.Error(), "private-") {
			t.Fatal("private error escaped")
		}
		outer := writerNativeReadFailure(err, context.Background(), "outer", "other", 8, nil)
		var nested *WriterAPIReadFailure
		if !errors.As(outer, &nested) || nested.Step != f.Step || f.InstanceID != 7 || nested.InstanceID != 8 {
			t.Fatal("inner label/cause mutated")
		}
	}
	if writerNativeReadFailure(nil, nil, "unused", "", 1, nil) != nil {
		t.Fatal("success changed")
	}
}

func TestNativeWriterGraphRefusalLabelsKeepClosedCoverage(t *testing.T) {
	for _, scenario := range []struct{ name, step string }{
		{"valid", ""}, {"team-unit", "graph_team_platform_units"}, {"controller-role", "graph_writer_roles"},
		{"missing-root", "graph_root_identity"}, {"not-ready", "graph_root_readiness"},
		{"unknown", "graph_deployment_coverage"}, {"owner", "graph_owner_chain"},
		{"pod-ready", "graph_pod_readiness"}, {"claim", "graph_pod_claims"}, {"count", "graph_replica_count"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			s, api := sourceWriterGraphFixture()
			switch scenario.name {
			case "team-unit":
				s.captureMaterials.Discovery.TeamPlatformUnits = map[string][]string{"private-unlisted": {"private-source"}}
			case "controller-role":
				s.Config.Writers = append(s.Config.Writers, PlatformDeployment{Namespace: "source", Name: "controller", UID: "controller-uid"})
			case "missing-root":
				api.objects[1].UID = "replacement"
			case "not-ready":
				api.objects[1].Ready = 0
			case "unknown":
				api.objects = append(api.objects, observedWriterAPIObject{Kind: "Deployment", Namespace: "source", Name: "private-unlisted", UID: "unknown"})
			case "owner":
				api.objects[3].Owners[0].UID = "replacement"
			case "pod-ready":
				api.objects[3].Running = false
			case "claim":
				api.objects[3].Claims = []string{"private-claim"}
			case "count":
				api.objects = api.objects[:3]
			}
			x := &bootstrapSourceRegistryReader{config: s.Config, materials: *s.captureMaterials}
			err := x.checkWriterGraph(b.SourceInventory{}, api)
			if scenario.step == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var f *WriterAPIReadFailure
			if !errors.As(err, &f) || f.Step != scenario.step || !errors.Is(err, ErrSourceWriterObservationIncomplete) || strings.Contains(err.Error(), "private-") {
				t.Fatalf("wrong bounded graph refusal: %v", err)
			}
		})
	}
}

func TestNativeWriterDiagnosticReportsActualControllerAPIRefusal(t *testing.T) {
	s, api := sourceWriterGraphFixture()
	x := &bootstrapSourceRegistryReader{config: s.Config, materials: *s.captureMaterials, physical: context.Background()}
	kube := fake.NewSimpleClientset()
	kube.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "private-pod", errors.New("private-token"))
	})
	_, err := x.readNativeWriters(&bootstrapSourceSQLFacts{inventory: b.SourceInventory{}}, api, &productionMetadataClients{API: kube})
	var f *WriterAPIReadFailure
	if !errors.As(err, &f) || f.Step != "native_controller_pod" || f.Reason != "forbidden" || f.InstanceID != 0 || !errors.Is(err, install.ErrInstall) {
		t.Fatalf("actual API error lost: %v", err)
	}
	if len(kube.Actions()) != 1 || kube.Actions()[0].GetVerb() != "get" {
		t.Fatal("diagnostic added mutation or extra reads")
	}
}
