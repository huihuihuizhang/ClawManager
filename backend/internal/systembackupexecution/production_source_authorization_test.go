package systembackupexecution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
)

// Private comparison-token MODELS, not an actual source freeze, SQL bind,
// successful normal enable, health observation or production permission.
func TestOriginalSourceAuthorizationFactoryPreservesCurrentPayload(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	in.Authority.ConfigVersion = 2
	plan, err := newProductionCapturePlan(operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	binding := capturePlanBindingFixture(t, plan, operations)
	key, err := originalSourceAuthorizationKey(in, source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &originalFrozenSourceAuthorization{binding: binding, ctx: ctx, key: key, authorizationSHA: strings.Repeat("a", 64), until: hold}
	p.origin = p
	binding.authorizations = map[string]*originalFrozenSourceAuthorization{key: p}
	modules, err := binding.moduleFactory()(in, source, hold, writers)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	for _, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil || inv.FormalCapture == nil {
			t.Fatal("original invocation")
		}
		actual := inv.FormalCapture
		applicable := inv.Request.ControlEvidence != nil || inv.Request.SourceRedis != nil || inv.Request.Database != nil || inv.Request.Teams != nil || inv.Request.SkillObjects != nil
		if applicable {
			observed++
			if actual.SourceConfigSHA256 != in.Authority.ConfigSHA256 || actual.SourceAuthorizationConfigSHA256 != p.authorizationSHA {
				t.Fatal("current task or original source scope lost", part.Part)
			}
			if inv.Request.ControlEvidence != nil && inv.Request.ControlEvidence.Expected.ConfigSHA256 != in.Authority.ConfigSHA256 {
				t.Fatal("CE payload rewritten to old configuration")
			}
		} else if actual.SourceAuthorizationConfigSHA256 != "" {
			t.Fatal("source exception reached unrelated operation", part.Part)
		}
		if inv.Request.CaptureDescription != nil && actual.SourceConfigSHA256 != in.Authority.ConfigSHA256 {
			t.Fatal("CD no longer describes current configuration")
		}
	}
	if observed < 4 {
		t.Fatal("original source operations missing", observed)
	}
	cancel()
	if p.matches(in, source) {
		t.Fatal("cancelled source token accepted")
	}
}

func TestOriginalSourceAuthorizationCannotBeMintedFromMetadataOrTemplate(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	for name, op := range operations {
		op.Formal.SourceAuthorizationConfigSHA256 = strings.Repeat("e", 64)
		operations[name] = op
	}
	plan, err := newProductionCapturePlan(operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	binding := capturePlanBindingFixture(t, plan, operations)
	modules, err := binding.moduleFactory()(in, source, hold, writers)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil || inv.FormalCapture == nil || inv.FormalCapture.SourceAuthorizationConfigSHA256 != "" {
			t.Fatal("template or metadata minted source authorization", part.Part)
		}
	}
}

func TestOriginalSourceAuthorizationRejectsCopiedExpiredAndForeignSource(t *testing.T) {
	in, source, hold, _, operations := productionModuleFixture(t)
	plan, err := newProductionCapturePlan(operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	binding := capturePlanBindingFixture(t, plan, operations)
	key, err := originalSourceAuthorizationKey(in, source)
	if err != nil {
		t.Fatal(err)
	}
	p := &originalFrozenSourceAuthorization{binding: binding, ctx: context.Background(), key: key, authorizationSHA: strings.Repeat("a", 64), until: hold}
	p.origin = p
	if !p.matches(in, source) {
		t.Fatal("comparison fixture invalid")
	}
	copied := *p
	if copied.matches(in, source) {
		t.Fatal("copied opaque pin accepted")
	}
	changed := source
	changed.CaptureMetadata = append(append([]byte{}, source.CaptureMetadata...), ' ')
	if p.matches(in, changed) {
		t.Fatal("different frozen metadata accepted")
	}
	foreign := in
	foreign.Authority.TaskPublicID = "sbk_foreign"
	if p.matches(foreign, source) {
		t.Fatal("foreign task accepted")
	}
	p.until = time.Now().Add(-time.Second)
	if p.matches(in, source) {
		t.Fatal("expired source pin accepted")
	}
	// Real producer refuses absent task/SQL dependencies; comparison fixtures
	// above never acquire their own source or SQL mutation authority.
	if _, err := binding.service.readOriginalSourceAuthorization(context.Background(), nil, in, strings.Repeat("a", 64)); err == nil {
		t.Fatal("missing original task authority accepted")
	}
	if err := binding.rememberOriginalSourceAuthorization(context.Background(), in, source.CaptureMetadata, nil); err == nil {
		t.Fatal("serialized source observation minted private pin")
	}
}
