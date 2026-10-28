package systembackupbusinessa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type gatewayAliasProofFixture struct {
	calls              int
	directTokenCleared bool
	failure            error
	mutateInput        bool
}

func (p *gatewayAliasProofFixture) VerifyGatewayAliasRestore(_ context.Context,
	registry, schema, evidence string, sources []GatewayAliasRestoreSource,
	aliasMappings []GatewayAliasRestoreMapping, instances []GatewayAliasInstanceMapping,
	targetNow time.Time) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_gateway_alias" || !p.directTokenCleared ||
		len(aliasMappings) != len(sources) || len(instances) != 1 ||
		!targetNow.Equal(time.Date(2026, 10, 13, 4, 5, 6, 123456000, time.UTC)) {
		return errors.New("unbound gateway alias proof")
	}
	if p.mutateInput && len(sources) == 1 {
		sources[0].TokenHash = strings.Repeat("d", 64)
		*sources[0].LastUsedAt = targetNow
		aliasMappings[0].TargetID = 999
		instances[0].TargetID = 999
	}
	return p.failure
}

func gatewayAliasRestoreFixture(t *testing.T) (*CaptureScope, GatewayAliasRestoreSource,
	GatewayAliasRestoreMapping, []GatewayAliasInstanceMapping, time.Time) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	lastUsed := created.Add(20 * time.Minute)
	source := GatewayAliasRestoreSource{
		ID: 20, InstanceID: 8, TokenHash: strings.Repeat("c", 64),
		ExpiresAt: created.Add(30 * 24 * time.Hour),
		CreatedAt: created, UpdatedAt: created.Add(time.Hour), LastUsedAt: &lastUsed,
	}
	return scope, source, GatewayAliasRestoreMapping{SourceID: 20, TargetID: 120},
		[]GatewayAliasInstanceMapping{{SourceID: 8, TargetID: 108}},
		time.Date(2026, 10, 13, 4, 5, 6, 123456000, time.UTC)
}

func TestGatewayAliasRestoreExpiresAndRemapsFullRow(t *testing.T) {
	scope, source, mapping, instances, targetNow := gatewayAliasRestoreFixture(t)
	proof := &gatewayAliasProofFixture{directTokenCleared: true, mutateInput: true}
	rows, err := NormalizeGatewayAliasesForRestore(context.Background(), scope,
		[]GatewayAliasRestoreSource{source}, []GatewayAliasRestoreMapping{mapping},
		instances, targetNow, "sev_gateway_alias", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("incomplete alias restore: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if !source.ExpiresAt.After(targetNow) || row.ID != 120 ||
		row.InstanceID != 108 || row.TokenHash != source.TokenHash ||
		!row.ExpiresAt.Equal(time.Date(2026, 10, 13, 4, 5, 5, 0, time.UTC)) ||
		!row.ExpiresAt.Before(targetNow) || !row.CreatedAt.Equal(source.CreatedAt) ||
		!row.UpdatedAt.Equal(source.UpdatedAt) || row.LastUsedAt == nil ||
		!row.LastUsedAt.Equal(*source.LastUsedAt) {
		t.Fatalf("historical token alias remained usable or lost columns: %+v", row)
	}
	*source.LastUsedAt = targetNow
	if row.LastUsedAt.Equal(targetNow) {
		t.Fatal("normalized alias aliases mutable source timestamp")
	}
}

func TestGatewayAliasRestoreRequiresBProofAndTargetClock(t *testing.T) {
	scope, source, mapping, instances, targetNow := gatewayAliasRestoreFixture(t)
	proof := &gatewayAliasProofFixture{directTokenCleared: true}
	rows, err := NormalizeGatewayAliasesForRestore(context.Background(), scope,
		nil, nil, instances, targetNow, "sev_gateway_alias", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty alias table not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]GatewayAliasRestoreProofVerifier{
		"nil": nil, "typed nil": (*gatewayAliasProofFixture)(nil),
	} {
		rows, err := NormalizeGatewayAliasesForRestore(context.Background(), scope,
			[]GatewayAliasRestoreSource{source}, []GatewayAliasRestoreMapping{mapping},
			instances, targetNow, "sev_gateway_alias", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	proof = &gatewayAliasProofFixture{}
	rows, err = NormalizeGatewayAliasesForRestore(context.Background(), scope,
		[]GatewayAliasRestoreSource{source}, []GatewayAliasRestoreMapping{mapping},
		instances, targetNow, "sev_gateway_alias", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("B direct-token proof failure emitted aliases: %+v, err=%v", rows, err)
	}
	proof = &gatewayAliasProofFixture{directTokenCleared: true, failure: errors.New("target clock untrusted")}
	rows, err = NormalizeGatewayAliasesForRestore(context.Background(), scope,
		[]GatewayAliasRestoreSource{source}, []GatewayAliasRestoreMapping{mapping},
		instances, targetNow, "sev_gateway_alias", proof)
	if err == nil || rows != nil {
		t.Fatalf("B target-clock proof failure emitted aliases: %+v, err=%v", rows, err)
	}
}

func TestGatewayAliasRestoreRejectsInvalidMappingsAndSource(t *testing.T) {
	scope, source, mapping, instances, targetNow := gatewayAliasRestoreFixture(t)
	for name, mutate := range map[string]func(*GatewayAliasRestoreSource, *GatewayAliasRestoreMapping,
		*[]GatewayAliasInstanceMapping, *time.Time){
		"invalid alias ID": func(s *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			s.ID = 0
		},
		"wrong alias mapping": func(_ *GatewayAliasRestoreSource, m *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			m.SourceID = 21
		},
		"duplicate target ID zero": func(_ *GatewayAliasRestoreSource, m *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			m.TargetID = 0
		},
		"unmapped instance": func(s *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			s.InstanceID = 9
		},
		"invalid target instance": func(_ *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, i *[]GatewayAliasInstanceMapping, _ *time.Time) {
			(*i)[0].TargetID = 0
		},
		"invalid token hash": func(s *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			s.TokenHash = strings.Repeat("G", 64)
		},
		"zero source expiry": func(s *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			s.ExpiresAt = time.Time{}
		},
		"last use after update": func(s *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, _ *time.Time) {
			last := s.UpdatedAt.Add(time.Second)
			s.LastUsedAt = &last
		},
		"zero target clock": func(_ *GatewayAliasRestoreSource, _ *GatewayAliasRestoreMapping, _ *[]GatewayAliasInstanceMapping, now *time.Time) {
			*now = time.Time{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			badInstances := append([]GatewayAliasInstanceMapping(nil), instances...)
			badNow := targetNow
			mutate(&badSource, &badMapping, &badInstances, &badNow)
			proof := &gatewayAliasProofFixture{directTokenCleared: true}
			rows, err := NormalizeGatewayAliasesForRestore(context.Background(), scope,
				[]GatewayAliasRestoreSource{badSource}, []GatewayAliasRestoreMapping{badMapping},
				badInstances, badNow, "sev_gateway_alias", proof)
			if !errors.Is(err, ErrGatewayAliasRestore) || rows != nil || proof.calls != 0 {
				t.Fatalf("invalid alias reached B proof or emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
			}
		})
	}
}

func TestGatewayAliasRestoreRejectsDuplicateHash(t *testing.T) {
	scope, source, mapping, instances, targetNow := gatewayAliasRestoreFixture(t)
	other := source
	other.ID = 21
	proof := &gatewayAliasProofFixture{directTokenCleared: true}
	rows, err := NormalizeGatewayAliasesForRestore(context.Background(), scope,
		[]GatewayAliasRestoreSource{source, other},
		[]GatewayAliasRestoreMapping{mapping, {SourceID: 21, TargetID: 121}},
		instances, targetNow, "sev_gateway_alias", proof)
	if !errors.Is(err, ErrGatewayAliasRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("duplicate token hash emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}
