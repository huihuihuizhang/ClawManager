package systembackupbusinessa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type llmModelProofFixture struct {
	calls       int
	wantDirect  string
	wantRef     string
	failure     error
	mutateInput bool
}

func (p *llmModelProofFixture) VerifyLLMModelSources(_ context.Context, registry, schema,
	evidence string, sources []LLMModelRestoreSource) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) || evidence != "sev_llm_models" {
		return errors.New("unbound model source proof")
	}
	if len(sources) == 1 && (sources[0].APIKeySecretVersion != p.wantDirect ||
		sources[0].APIKeyRefSecretVersion != p.wantRef) {
		return ErrLLMModelRestore
	}
	if p.mutateInput && len(sources) == 1 {
		*sources[0].Description = "changed"
		*sources[0].ProtocolType = "changed"
		*sources[0].ProviderModelsJSON = "[]"
		sources[0].InputPrice = "9999999999.99999999"
	}
	return p.failure
}

func llmModelRestoreFixture(t *testing.T) (*CaptureScope, LLMModelRestoreSource, LLMModelRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	description := "historical model"
	protocol := "openai"
	providers := `[{"id":"model-v1","display_name":"Model V1"}]`
	created := time.Date(2026, 9, 20, 1, 2, 3, 123456000, time.UTC)
	source := LLMModelRestoreSource{
		ID: 5, DisplayName: "Historical Model", Description: &description,
		ProviderType: "openai", ProtocolType: &protocol,
		BaseURL: "https://api.example.invalid/v1", ProviderModelName: "model-v1",
		ProviderModelsJSON: &providers, ReasoningEnabled: true,
		APIKeyState: LLMModelCredentialNonempty, APIKeySecretVersion: "inline-key-version-1",
		APIKeySecretRefState: LLMModelCredentialNonempty, APIKeyRefSecretVersion: "k8s-ref-version-1",
		IsSecure: true, IsActive: true,
		InputPrice: "0.00000001", OutputPrice: "9999999999.99999999",
		Currency: "USD", CreatedAt: created, UpdatedAt: created.Add(time.Hour),
	}
	return scope, source, LLMModelRestoreMapping{SourceID: 5, TargetID: 105}
}

func TestLLMModelRestoreCompleteInertRowAndExactPrices(t *testing.T) {
	scope, source, mapping := llmModelRestoreFixture(t)
	proof := &llmModelProofFixture{
		wantDirect: source.APIKeySecretVersion, wantRef: source.APIKeyRefSecretVersion,
		mutateInput: true,
	}
	rows, err := NormalizeLLMModelsForRestore(context.Background(), scope,
		[]LLMModelRestoreSource{source}, []LLMModelRestoreMapping{mapping}, "sev_llm_models", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("incomplete LLM model restore: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 105 || row.DisplayName != source.DisplayName ||
		row.Description == nil || *row.Description != *source.Description ||
		row.ProviderType != source.ProviderType || row.ProtocolType == nil ||
		*row.ProtocolType != *source.ProtocolType || row.BaseURL != source.BaseURL ||
		row.ProviderModelName != source.ProviderModelName ||
		row.ProviderModelsJSON == nil || *row.ProviderModelsJSON != *source.ProviderModelsJSON ||
		!row.ReasoningEnabled || !row.IsSecure || row.IsActive ||
		row.APIKey != nil || row.APIKeySecretRef != nil ||
		row.InputPrice != "0.00000001" || row.OutputPrice != "9999999999.99999999" ||
		row.Currency != "USD" || !row.CreatedAt.Equal(source.CreatedAt) ||
		!row.UpdatedAt.Equal(source.UpdatedAt) {
		t.Fatalf("model row leaked a credential or lost a SQL field: %+v", row)
	}
	*source.Description = "source changed"
	*source.ProtocolType = "changed"
	*source.ProviderModelsJSON = "[]"
	if *row.Description != "historical model" || *row.ProtocolType != "openai" ||
		*row.ProviderModelsJSON != `[{"id":"model-v1","display_name":"Model V1"}]` {
		t.Fatal("normalized model aliases mutable source pointers")
	}
}

func TestLLMModelRestoreProofRequiredAndNoPartialRows(t *testing.T) {
	scope, source, mapping := llmModelRestoreFixture(t)
	proof := &llmModelProofFixture{}
	rows, err := NormalizeLLMModelsForRestore(context.Background(), scope, nil, nil, "sev_llm_models", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty table not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]LLMModelSourceProofVerifier{
		"nil": nil, "typed nil": (*llmModelProofFixture)(nil),
	} {
		rows, err := NormalizeLLMModelsForRestore(context.Background(), scope,
			[]LLMModelRestoreSource{source}, []LLMModelRestoreMapping{mapping},
			"sev_llm_models", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	proof = &llmModelProofFixture{wantDirect: source.APIKeySecretVersion,
		wantRef: source.APIKeyRefSecretVersion, failure: errors.New("dump unavailable")}
	rows, err = NormalizeLLMModelsForRestore(context.Background(), scope,
		[]LLMModelRestoreSource{source}, []LLMModelRestoreMapping{mapping},
		"sev_llm_models", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("failed proof emitted model rows: %+v, err=%v", rows, err)
	}
}

func TestLLMModelRestoreRejectsSecretDriftAndMalformedRows(t *testing.T) {
	scope, source, mapping := llmModelRestoreFixture(t)
	proof := &llmModelProofFixture{wantDirect: source.APIKeySecretVersion, wantRef: source.APIKeyRefSecretVersion}
	drift := source
	drift.APIKeyRefSecretVersion = "k8s-ref-version-2"
	rows, err := NormalizeLLMModelsForRestore(context.Background(), scope,
		[]LLMModelRestoreSource{drift}, []LLMModelRestoreMapping{mapping}, "sev_llm_models", proof)
	if !errors.Is(err, ErrLLMModelRestore) || rows != nil || proof.calls != 1 {
		t.Fatalf("secret ref drift accepted: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, mutate := range map[string]func(*LLMModelRestoreSource, *LLMModelRestoreMapping){
		"wrong source ID":     func(_ *LLMModelRestoreSource, m *LLMModelRestoreMapping) { m.SourceID = 6 },
		"bad target ID":       func(_ *LLMModelRestoreSource, m *LLMModelRestoreMapping) { m.TargetID = 0 },
		"missing key version": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.APIKeySecretVersion = "" },
		"ref version alias":   func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.APIKeyRefSecretVersion = "latest" },
		"unknown key state":   func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.APIKeyState = "unknown" },
		"version on null":     func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.APIKeyState = LLMModelCredentialNull },
		"URL user info": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) {
			s.BaseURL = "https://key@api.example.invalid/v1"
		},
		"URL query": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) {
			s.BaseURL = "https://api.example.invalid/v1?api_key=secret"
		},
		"unknown provider JSON key": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) {
			value := `[{"id":"x","display_name":"X","api_key":"secret"}]`
			s.ProviderModelsJSON = &value
		},
		"duplicate provider model": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) {
			value := `[{"id":"x","display_name":"X"},{"id":"X","display_name":"X"}]`
			s.ProviderModelsJSON = &value
		},
		"negative price":          func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.InputPrice = "-1.00" },
		"too many price decimals": func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.OutputPrice = "1.123456789" },
		"price overflow":          func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.InputPrice = "10000000000.00000000" },
		"invalid currency":        func(s *LLMModelRestoreSource, _ *LLMModelRestoreMapping) { s.Currency = strings.Repeat("X", 17) },
	} {
		t.Run(name, func(t *testing.T) {
			bad, badMapping := source, mapping
			mutate(&bad, &badMapping)
			candidate := &llmModelProofFixture{wantDirect: source.APIKeySecretVersion, wantRef: source.APIKeyRefSecretVersion}
			rows, err := NormalizeLLMModelsForRestore(context.Background(), scope,
				[]LLMModelRestoreSource{bad}, []LLMModelRestoreMapping{badMapping}, "sev_llm_models", candidate)
			if !errors.Is(err, ErrLLMModelRestore) || rows != nil || candidate.calls != 0 {
				t.Fatalf("invalid row reached B proof or emitted output: %+v, calls=%d, err=%v", rows, candidate.calls, err)
			}
		})
	}
}

func TestLLMModelRestoreRejectsDuplicateDisplayNames(t *testing.T) {
	scope, source, mapping := llmModelRestoreFixture(t)
	other := source
	other.ID, other.DisplayName = 6, "historical model"
	proof := &llmModelProofFixture{}
	rows, err := NormalizeLLMModelsForRestore(context.Background(), scope,
		[]LLMModelRestoreSource{source, other},
		[]LLMModelRestoreMapping{mapping, {SourceID: 6, TargetID: 106}},
		"sev_llm_models", proof)
	if !errors.Is(err, ErrLLMModelRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("colliding display names emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}

func TestLLMModelRestoreNullCredentialsStillWriteNulls(t *testing.T) {
	_, source, mapping := llmModelRestoreFixture(t)
	source.APIKeyState, source.APIKeySecretVersion = LLMModelCredentialNull, ""
	source.APIKeySecretRefState, source.APIKeyRefSecretVersion = LLMModelCredentialEmpty, ""
	row, err := NormalizeLLMModelForRestore(source, mapping)
	if err != nil || row.IsActive || row.APIKey != nil || row.APIKeySecretRef != nil {
		t.Fatalf("null or empty source credentials resumed: %+v, err=%v", row, err)
	}
	row, err = NormalizeLLMModelForRestore(LLMModelRestoreSource{
		ID: 5, DisplayName: "x", ProviderType: "openai", BaseURL: "https://api.example.invalid",
		ProviderModelName: "model", APIKeyState: LLMModelCredentialNull,
		APIKeySecretRefState: LLMModelCredentialNull, InputPrice: "1.23", OutputPrice: "0",
		Currency: "USD", CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt,
	}, mapping)
	if err != nil || row.InputPrice != "1.23000000" || row.OutputPrice != "0.00000000" {
		t.Fatalf("decimal string was not normalized exactly: %+v, err=%v", row, err)
	}
}
