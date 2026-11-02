package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

func TestOriginalHeldControlReadScopeIsRPCBoundAndContainsNoAuthority(t *testing.T) {
	store, model := newExecutionModel(t)
	store.ApplicationScope = "original-scope"
	ctx, closeScope, err := OpenOriginalHeldControlReadScope(context.Background(), store, model.a)
	if err != nil {
		t.Fatal(err)
	}
	defer closeScope()
	if !useOriginalHeldControlRead(ctx, store, model.a) || useOriginalHeldControlRead(context.Background(), store, model.a) {
		t.Fatal("scope not bound to exact original context")
	}
	changed := model.a
	changed.AttemptNo++
	if useOriginalHeldControlRead(ctx, store, changed) {
		t.Fatal("foreign authority accepted")
	}
	changedStore := store
	changedStore.ApplicationScope = "foreign"
	if useOriginalHeldControlRead(ctx, changedStore, model.a) {
		t.Fatal("foreign source accepted")
	}
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	if useOriginalHeldControlRead(derived, store, model.a) {
		t.Fatal("copied/derived context selected another RPC")
	}
	closeScope()
	if useOriginalHeldControlRead(ctx, store, model.a) {
		t.Fatal("closed context copy revived scope")
	}
	if len(model.queries) != 0 {
		t.Fatal("implementation selection supplied authority or issued SQL")
	}
}

func prefixDataFixture() (originalHeldControlPrefix, d.Authority) {
	now := time.Now().UTC()
	config := []byte(`{"source":"original held DATA"}`)
	sum := sha256.Sum256(config)
	a := d.Authority{InstallationID: "installation_test", TaskPublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef", TaskType: "backup", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: hex.EncodeToString(sum[:]), AttemptNo: 7, Phase: "capture", ClaimOwner: "controller-1", ClaimRowVersion: 2, MaintenanceOwner: "capture-1", MaintenanceFencingToken: 7, DeadlineAt: now.Add(time.Minute)}
	p := originalHeldControlPrefix{engine: "v2", phase: "held", applicationOwner: a.TaskPublicID, applicationToken: 21, generation: 7, epoch: 7, acquireToken: 20, heldToken: sql.NullInt64{Int64: 21, Valid: true}, maintenanceFence: 7, gateLease: sql.NullTime{Time: now.Add(time.Minute), Valid: true}, hold: sql.NullTime{Time: now.Add(time.Minute), Valid: true}, stateSchema: "system-backup-installation-state.v1", configSchema: "system-backup-config.v1", enabled: true, activeVersion: 1, taskSchema: "system-backup-task.v1", origin: a.InstallationID, kind: a.TaskType, request: a.RequestID, owner: a.ClaimOwner, configHash: a.ConfigSHA256, taskVersion: a.ClaimRowVersion, configSize: uint64(len(config)), configVersion: a.ConfigVersion, deadline: a.DeadlineAt, snapshot: executionSnapshot{status: "capturing", gateState: "held", gateOwner: a.MaintenanceOwner, gateVersion: 3, installationVersion: 4, claimUntil: now.Add(time.Minute), config: config}}
	return p, a
}

func TestOriginalHeldControlPrefixRejectsEveryOriginalIdentityDrift(t *testing.T) {
	base, a := prefixDataFixture()
	if _, err := base.validated(a); err != nil {
		t.Fatal("DATA fixture prefix", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*originalHeldControlPrefix)
	}{
		{"engine", func(p *originalHeldControlPrefix) { p.engine = "legacy" }},
		{"phase", func(p *originalHeldControlPrefix) { p.phase = "acquiring" }},
		{"application-owner", func(p *originalHeldControlPrefix) { p.applicationOwner = "foreign" }},
		{"application-token", func(p *originalHeldControlPrefix) { p.applicationToken++ }},
		{"generation", func(p *originalHeldControlPrefix) { p.generation++ }},
		{"epoch", func(p *originalHeldControlPrefix) { p.epoch++ }},
		{"missing-held", func(p *originalHeldControlPrefix) { p.heldToken.Valid = false }},
		{"gate-phase", func(p *originalHeldControlPrefix) { p.snapshot.gateState = "idle" }},
		{"gate-version", func(p *originalHeldControlPrefix) { p.snapshot.gateVersion = 0 }},
		{"installation-schema", func(p *originalHeldControlPrefix) { p.stateSchema = "foreign" }},
		{"installation-version", func(p *originalHeldControlPrefix) { p.snapshot.installationVersion = 0 }},
		{"active-version", func(p *originalHeldControlPrefix) { p.activeVersion = 0 }},
		{"config-schema", func(p *originalHeldControlPrefix) { p.configSchema = "foreign" }},
		{"disabled", func(p *originalHeldControlPrefix) { p.enabled = false }},
		{"task-schema", func(p *originalHeldControlPrefix) { p.taskSchema = "foreign" }},
		{"installation", func(p *originalHeldControlPrefix) { p.origin = "foreign" }},
		{"task-kind", func(p *originalHeldControlPrefix) { p.kind = "preflight" }},
		{"request", func(p *originalHeldControlPrefix) { p.request = "foreign" }},
		{"claim-owner", func(p *originalHeldControlPrefix) { p.owner = "foreign" }},
		{"claim-version", func(p *originalHeldControlPrefix) { p.taskVersion++ }},
		{"deadline", func(p *originalHeldControlPrefix) { p.deadline = p.deadline.Add(time.Microsecond) }},
		{"config-version", func(p *originalHeldControlPrefix) { p.configVersion++ }},
		{"config-pin", func(p *originalHeldControlPrefix) { p.configHash = "foreign" }},
		{"config-size", func(p *originalHeldControlPrefix) { p.configSize++ }},
		{"config-bytes", func(p *originalHeldControlPrefix) {
			p.snapshot.config = append([]byte(nil), p.snapshot.config...)
			p.snapshot.config[2] = 'x'
		}},
		{"task-status", func(p *originalHeldControlPrefix) { p.snapshot.status = "succeeded" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.change(&p)
			if _, err := p.validated(a); err == nil {
				t.Fatal("changed original prefix admitted")
			}
		})
	}
}
