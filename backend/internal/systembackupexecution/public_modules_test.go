package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Compile the real D method against B's production callback, without another
// control SQL implementation or a shadow task. Positive SQL semantics remain
// covered by D's runtime-control tests, not by a model masquerading as that DB.
var _ b.WriterBuilder = (&c.SQLRuntimeControl{}).BuildWriters

func TestPublicSourceModuleOptInPreservesOriginalWriterAndDefaultParts(t *testing.T) {
	writers, oldParts := 0, 0
	source := b.LinuxProfileConfig{Source: &sql.DB{}, Database: "synthetic", ServerUUID: "synthetic", Supported: map[b.AgentKind]bool{{Type: "openclaw", Mode: "lite", Variant: "linux", OS: "linux"}: true}, HoldLimit: time.Second,
		BuildWriters: func(context.Context, d.Input, b.SourceInventory, []b.FrozenWriter) ([]flow.Writer, error) {
			writers++
			return nil, nil
		},
		BuildParts: func(d.Input, b.SourceInventory, time.Time) ([]b.JobPart, error) { oldParts++; return nil, nil },
	}
	plain, err := configuredPublicSource(PublicCaptureConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	plain.BuildParts(d.Input{}, b.SourceInventory{}, time.Now())
	if oldParts != 1 || writers != 0 {
		t.Fatal("default workspace hook replaced")
	}
	modules, err := b.NewCaptureModules([]b.CaptureModuleRegistration{{Descriptor: b.CaptureModuleDescriptor{ID: "workspace", Owner: "C", Revision: "reviewed-fixture", Parts: []b.CaptureModulePart{{Part: "workspace", Category: "workspace", RequestedPart: "workspace", Operation: "capture-workspace"}}}, Build: func(b.CaptureModuleInput) ([]b.CapturePartRequest, error) {
		return nil, errors.New("not exercised during construction")
	}}}, func(d.Input, b.SourceInventory, time.Time, string) (b.ModuleCaptureContext, error) {
		return b.ModuleCaptureContext{}, errors.New("not exercised during construction")
	})
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := configuredPublicSource(PublicCaptureConfig{Source: source, Modules: modules})
	if err != nil || writers != 0 || oldParts != 1 {
		t.Fatal("constructor performed IO", err)
	}
	admitted.BuildWriters(context.Background(), d.Input{}, b.SourceInventory{}, nil)
	if writers != 1 {
		t.Fatal("module intake dropped D/C writer callback")
	}
	if _, err = configuredPublicSource(PublicCaptureConfig{Source: source, Modules: &b.CaptureModules{}}); err == nil {
		t.Fatal("uninitialized module directory accepted")
	}
}

func TestFormalSourceRequiresIndependentUnwrapperBeforeWritersOrDispatch(t *testing.T) {
	_, _, _, invocation, _, keys := formalObserverFixture(t)
	raw, _ := json.Marshal(invocation)
	builds := 0
	source := b.LinuxProfileConfig{BuildParts: func(d.Input, b.SourceInventory, time.Time) ([]b.JobPart, error) {
		builds++
		return []b.JobPart{{InvocationJSON: raw}}, nil
	}}
	profile, err := configuredPublicSource(PublicCaptureConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = profile.BuildParts(d.Input{}, b.SourceInventory{}, time.Now()); err == nil {
		t.Fatal("formal capture admitted before independent unwrap assembly")
	}
	if builds != 1 || keys.calls != 0 {
		t.Fatal("assembly performed provider operation")
	}
	profile, err = configuredPublicSource(PublicCaptureConfig{Source: source, FormalKeys: func(context.Context, FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
		t.Fatal("assembly opened provider factory")
		return nil, errors.New("not called during assembly")
	}})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := profile.BuildParts(d.Input{}, b.SourceInventory{}, time.Now())
	if err != nil || len(parts) != 1 || string(parts[0].InvocationJSON) != string(raw) || keys.calls != 0 {
		t.Fatal("source composition changed original invocation or performed IO", err)
	}
}

func TestPublicRuntimeOptInCannotDiscardPlatformWriters(t *testing.T) {
	// Even a zero-value owner/control pair cannot turn an absent group into
	// permission to overwrite the original platform hook. The outer production
	// constructor additionally requires the original ready owner/scope/grants.
	if _, err := configuredPublicSource(PublicCaptureConfig{Owner: &PublicJobOwner{}, RuntimeControl: &c.SQLRuntimeControl{}}); err == nil {
		t.Fatal("runtime control discarded platform writers")
	}
}

func TestPlatformGroupRetainsNonemptyGuardWithoutRuntimeIO(t *testing.T) {
	service := &DeploymentService{Config: DeploymentConfig{Writers: []PlatformDeployment{{Namespace: "source", Name: "platform", UID: "original-uid"}}}}
	group, err := service.PlatformWriterGroup(&PublicJobOwner{})
	if err != nil || len(group.IDs) != 1 || group.IDs[0] != "deployment/source/platform" {
		t.Fatal("signed platform group lost", err)
	}
	// The original guard rejects before any client, grant or stop witness IO.
	if _, err := group.Build(context.Background(), d.Input{}, b.SourceInventory{Instances: []b.InstanceIdentity{{ID: 7}}}, nil); err == nil {
		t.Fatal("nonempty gate silently removed")
	}
}
