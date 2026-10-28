package systembackupsecurity

import (
	"encoding/json"
	"testing"
	"time"
)

func responseBindingFixture(t *testing.T) (ConfigMutationResponsePreparation, ConfigMutationRequest) {
	t.Helper()
	svc, actor, raw, s, _ := mutationTransactionFixture(t)
	r, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewConfigMutationResponsePreparation(svc.Database, actor, s.data.rows[1], ConfigMutationResponseContentPolicy{InstallationID: svc.InstallationID, CreatedBy: actor.UserID, Version: 2, Config: r.Config(), CreatedAt: s.now, DeploymentEnabled: true}, s.now.Add(5*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return p, r
}
func TestConfigMutationResponseBindingPreservesPublicHashAndSeparatesAttempts(t *testing.T) {
	p, r := responseBindingFixture(t)
	a, err := p.BindRequest(r, "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := a.RequestBinding()
	want, err := r.RequestHash(p.ContentPolicy().InstallationID, "admin", "42")
	if !ok || err != nil || b.RequestHash() != want || b.Endpoint() != ConfigUpdateEndpoint || b.Method() != "PUT" || b.ExpectedVersion() != 1 || b.CurrentRowVersion() != 1 || b.InstallationRowVersion() != 1 || b.HighestVersion() != 1 || b.RollbackFromVersion() != 0 {
		t.Fatal("incorrect public/request snapshot binding", err)
	}
	other, err := p.BindRequest(r, b.IdempotencyKey(), "request-2", "sop_aaaaaaaa-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := other.RequestBinding()
	if b.ScopeSHA256() != b2.ScopeSHA256() || b.RequestHash() != b2.RequestHash() || b.AttemptSHA256() == b2.AttemptSHA256() {
		t.Fatal("transport/operation was added to public hash or attempts were conflated")
	}
	other, err = p.BindRequest(r, "another_key_0123456789", "request-1", b.OperationPublicID(), 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ = other.RequestBinding()
	if b.RequestHash() != b2.RequestHash() || b.ScopeSHA256() == b2.ScopeSHA256() {
		t.Fatal("idempotency key not separately bound")
	}
	for _, value := range []any{a, b} {
		if _, err = json.Marshal(value); err == nil {
			t.Fatal("internal publication facts serialized")
		}
	}
	copy := b
	copy.operation = "changed"
	again, _ := a.RequestBinding()
	if again.OperationPublicID() == copy.operation {
		t.Fatal("request binding aliases caller mutation")
	}
	if _, ok = p.RequestBinding(); ok {
		t.Fatal("binding mutated original preparation")
	}
}
func TestConfigMutationResponseBindingPinsSessionAndLockedVersions(t *testing.T) {
	for _, name := range []string{"session", "current-row", "installation-row"} {
		t.Run(name, func(t *testing.T) {
			p, r := responseBindingFixture(t)
			a, err := p.BindRequest(r, "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			row, state := int64(1), int64(1)
			switch name {
			case "session":
				p.actor.Session = "different-session"
			case "current-row":
				row++
			case "installation-row":
				state++
			}
			other, err := p.BindRequest(r, "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc", row, state, 1)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := a.RequestBinding()
			b2, _ := other.RequestBinding()
			if b.ScopeSHA256() != b2.ScopeSHA256() || b.AttemptSHA256() == b2.AttemptSHA256() {
				t.Fatal("same public slot accepted different session/snapshot as original attempt")
			}
		})
	}
}
func TestConfigMutationResponseBindingRejectsInvalidOrReboundFacts(t *testing.T) {
	for _, name := range []string{"zero", "request", "endpoint", "key", "request-id", "operation", "row", "state", "highest", "new-version", "proposed", "rollback-future", "rebound"} {
		t.Run(name, func(t *testing.T) {
			p, r := responseBindingFixture(t)
			key, id, op := "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc"
			row, state, highest := int64(1), int64(1), int64(1)
			switch name {
			case "zero":
				p = ConfigMutationResponsePreparation{}
			case "request":
				r = ConfigMutationRequest{}
			case "endpoint":
				r.endpoint = "arbitrary"
			case "key":
				key = "bad"
			case "request-id":
				id = "../not-transport"
			case "operation":
				op = "request-selected-id"
			case "row":
				row = 0
			case "state":
				state = 9007199254740991
			case "highest":
				highest = 9007199254740991
			case "new-version":
				p.policy.Version = 3
			case "proposed":
				p.policy.Config = ConfigValues{}
			case "rollback-future":
				var err error
				r, err = DecodeConfigMutationRequest(ConfigRollbackEndpoint, []byte(`{"expected_version":1,"change_reason":null,"rollback_from_version":2}`))
				if err != nil {
					t.Fatal(err)
				}
			case "rebound":
				var err error
				p, err = p.BindRequest(r, key, id, op, row, state, highest)
				if err != nil {
					t.Fatal(err)
				}
			}
			if out, err := p.BindRequest(r, key, id, op, row, state, highest); err != ErrRegistrationUnavailable || len(out.Bytes()) != 0 {
				t.Fatal("invalid binding accepted", name, err)
			}
		})
	}
}
func TestConfigMutationResponseRollbackBindingKeepsSourceAndMethod(t *testing.T) {
	p, _ := responseBindingFixture(t)
	r, err := DecodeConfigMutationRequest(ConfigRollbackEndpoint, []byte(`{"expected_version":1,"change_reason":"raw request reason","rollback_from_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := p.BindRequest(r, "mutation_key_0123456789", "rollback-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := bound.RequestBinding()
	if b.Method() != "POST" || b.Endpoint() != ConfigRollbackEndpoint || b.RollbackFromVersion() != 1 {
		t.Fatal("rollback lost exact source/method binding")
	}
}

func TestConfigMutationResponsePublicSlotCollidesForDifferentRequestBodies(t *testing.T) {
	p, r := responseBindingFixture(t)
	one, err := p.BindRequest(r, "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(r.CanonicalJSON(), &raw) != nil {
		t.Fatal("request fixture")
	}
	// Only raw reason changes. The reviewed redacted response may stay equal;
	// request hash must still distinguish the two bodies within the SAME slot.
	raw["change_reason"] = json.RawMessage(`"different raw reason"`)
	encoded, _ := json.Marshal(raw)
	otherRequest, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, encoded)
	if err != nil {
		t.Fatal(err)
	}
	two, err := p.BindRequest(otherRequest, "mutation_key_0123456789", "request-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := one.RequestBinding()
	b, _ := two.RequestBinding()
	if a.ScopeSHA256() != b.ScopeSHA256() || a.RequestHash() == b.RequestHash() || a.AttemptSHA256() == b.AttemptSHA256() {
		t.Fatal("different body/key conflict escaped public slot or lost raw request binding")
	}
}
