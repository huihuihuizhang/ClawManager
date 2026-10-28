package systembackupconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

const responseTestEvidenceID = "sev_12345678-1234-1234-1234-123456789abc"

func responseContentFixture(t *testing.T, large bool) (sec.ConfigMutationResponsePreparation, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/evidence/a-config-canonical-request-vectors-20261014.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Input struct {
				Request struct {
					Config json.RawMessage `json:"config"`
				} `json:"request"`
			} `json:"input"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Vectors) < 1 {
		t.Fatal("synthetic vectors missing")
	}
	current, err := sec.DecodeConfigValues(vectors.Vectors[0].Input.Request.Config)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(current.CanonicalJSON(), &config) != nil {
		t.Fatal("fixture config")
	}
	config["enabled"] = json.RawMessage("true")
	if large {
		registries, refs := current.Registries(), current.References()
		for i := range registries {
			registries[i].Version = strings.Repeat("v", 128)
		}
		for i := range refs {
			refs[i].Version = strings.Repeat("r", 128)
		}
		config["registries"], _ = json.Marshal(registries)
		config["references"], _ = json.Marshal(refs)
	}
	raw, _ = json.Marshal(config)
	proposed, err := sec.DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	actor := sec.RegistrationActor{UserID: 42, Subject: "user:42", Session: strings.Repeat("a", 64), SessionIssuedAt: now.Add(-time.Minute), SessionExpiresAt: now.Add(time.Hour)}
	reason := "reviewed reason"
	policy := sec.ConfigMutationResponseContentPolicy{InstallationID: "installation_synthetic", CreatedBy: 42, Version: 2, Config: proposed, RedactedReason: &reason, CreatedAt: now, DeploymentEnabled: true}
	input, err := sec.NewConfigMutationResponsePreparation(sec.DatabaseIdentity{ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "synthetic"}, actor, current, policy, now.Add(5*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	body := input.Bytes()
	if large && len(body) <= 8192 || !large && len(body) > 8192 {
		t.Fatal("fixture must exercise actual size branch", len(body))
	}
	return input, body
}
func responseContent(t *testing.T, large bool) ConfigMutationResponseContent {
	t.Helper()
	input, _ := responseContentFixture(t, large)
	c, err := PrepareConfigMutationResponseContent(context.Background(), input, responseTestEvidenceID)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// This is a live-call protocol double, not a production producer/write grant.
type responseContentAuthorityFixture struct{ c ConfigMutationResponseContent }

func (a responseContentAuthorityFixture) AuthorizeContent(_ context.Context, i ev.Identity) (ev.ContentAuthorization, error) {
	p := ev.ConfigResponseContentPolicy{EvidenceID: i.ID, Classification: i.Classification, Response: a.c.input.ContentPolicy(), ValidUntil: a.c.until}
	return ev.ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: a.c.until, ConfigResponse: &p}, nil
}

func TestConfigResponseHistoricalParserRejectsMutatedBody(t *testing.T) {
	for _, name := range []string{"actor", "installation", "schema", "null-active", "inactive", "duplicate-config-field", "unknown-field", "noncanonical"} {
		t.Run(name, func(t *testing.T) {
			_, body := responseContentFixture(t, false)
			installation, actorID := "installation_synthetic", "42"
			switch name {
			case "actor":
				actorID = "7"
			case "installation":
				installation = "installation_foreign"
			case "schema":
				body = bytes.Replace(body, []byte(`"schema_version":"system-backup-config.v1"`), []byte(`"schema_version":"other"`), 1)
			case "null-active":
				body = bytes.Replace(body, []byte(`"active":true`), []byte(`"active":null`), 1)
			case "inactive":
				body = bytes.Replace(body, []byte(`"active":true`), []byte(`"active":false`), 1)
			case "duplicate-config-field":
				body = bytes.Replace(body, []byte(`"enabled":true`), []byte(`"enabled":true,"enabled":false`), 1)
			case "unknown-field":
				body = append([]byte(`{"approved":true,`), body[1:]...)
			case "noncanonical":
				body = append([]byte(" "), body...)
			}
			if _, _, _, err := decodeConfigMutationResponseResource(installation, actorID, body); err != sec.ErrConfigMutation {
				t.Fatal("historical parser accepted unbound body", err)
			}
		})
	}
}

func TestConfigResponsePreparationOwnsPolicyAndPayload(t *testing.T) {
	input, expected := responseContentFixture(t, false)
	p := input.ContentPolicy()
	*p.RedactedReason = "changed outside"
	view := input.Bytes()
	view[0] = '!'
	if !bytes.Equal(input.Bytes(), expected) || *input.ContentPolicy().RedactedReason == "changed outside" {
		t.Fatal("writer facts leaked mutable aliases")
	}
	if _, err := json.Marshal(input); err == nil {
		t.Fatal("writer input serialized")
	}
	if c, err := PrepareConfigMutationResponseContent(context.Background(), sec.ConfigMutationResponsePreparation{}, responseTestEvidenceID); err != sec.ErrRegistrationUnavailable || len(c.Bytes()) != 0 {
		t.Fatal("zero preparation accepted", err)
	}
}
