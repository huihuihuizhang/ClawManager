package systembackupbusinessa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/models"
)

const (
	LLMModelCredentialNull     = "null"
	LLMModelCredentialEmpty    = "empty"
	LLMModelCredentialNonempty = "nonempty"
)

// LLMModelRestoreSource projects every migration-045/056 model column except
// raw credential values. B must classify SQL NULL, empty and nonempty values
// independently for api_key and api_key_secret_ref. A nonempty source requires
// an authenticated immutable Secret/ref version from B's sealed bundle.
type LLMModelRestoreSource struct {
	ID                     int
	DisplayName            string
	Description            *string
	ProviderType           string
	ProtocolType           *string
	BaseURL                string
	ProviderModelName      string
	ProviderModelsJSON     *string
	ReasoningEnabled       bool
	APIKeyState            string
	APIKeySecretVersion    string
	APIKeySecretRefState   string
	APIKeyRefSecretVersion string
	IsSecure               bool
	IsActive               bool
	InputPrice             string
	OutputPrice            string
	Currency               string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type LLMModelRestoreMapping struct {
	SourceID int
	TargetID int
}

// NormalizedLLMModel is a complete parameterized SQL row. Prices remain
// decimal strings because the runtime model's float64 fields lose SQL scale.
type NormalizedLLMModel struct {
	ID                 int
	DisplayName        string
	Description        *string
	ProviderType       string
	ProtocolType       *string
	BaseURL            string
	ProviderModelName  string
	ProviderModelsJSON *string
	ReasoningEnabled   bool
	APIKey             *string
	APIKeySecretRef    *string
	IsSecure           bool
	IsActive           bool
	InputPrice         string
	OutputPrice        string
	Currency           string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// LLMModelSourceProofVerifier belongs to B. It must authenticate each source
// SQL row, both original credential states, the exact typed Secret/ref identity
// and version for every nonempty credential, and the registered dump evidence.
// An empty table also needs proof. Caller-supplied versions prove nothing alone.
type LLMModelSourceProofVerifier interface {
	VerifyLLMModelSources(context.Context, string, string, string, []LLMModelRestoreSource) error
}

var ErrLLMModelRestore = errors.New("A LLM model restore normalization failed")

// NormalizeLLMModelsForRestore returns no partial rows. B must additionally
// verify the user-approved ID map, isolated target occupancy/collation and SQL
// write authority; this function never executes SQL or resolves old secrets.
func NormalizeLLMModelsForRestore(ctx context.Context, scope *CaptureScope,
	sources []LLMModelRestoreSource, mappings []LLMModelRestoreMapping,
	evidenceRef string, proof LLMModelSourceProofVerifier) ([]NormalizedLLMModel, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrLLMModelRestore
	}
	if nilLLMModelProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneLLMModelSources(sources)
	bySource := make(map[int]LLMModelRestoreMapping, len(mappings))
	targetIDs := make(map[int]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 {
			return nil, ErrLLMModelRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrLLMModelRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrLLMModelRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]NormalizedLLMModel, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	seenNames := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrLLMModelRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrLLMModelRestore
		}
		row, err := NormalizeLLMModelForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		nameKey := strings.ToLower(row.DisplayName)
		if _, duplicate := seenNames[nameKey]; duplicate {
			return nil, ErrLLMModelRestore
		}
		seenSources[source.ID] = struct{}{}
		seenNames[nameKey] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyLLMModelSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneLLMModelSources(projection)); err != nil {
		return nil, fmt.Errorf("A LLM model source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeLLMModelForRestore is a pure row transformation. A production
// batch must use the proof-gated entry above; a single row has no provenance.
func NormalizeLLMModelForRestore(source LLMModelRestoreSource,
	mapping LLMModelRestoreMapping) (NormalizedLLMModel, error) {
	created := source.CreatedAt.UTC().Truncate(time.Microsecond)
	updated := source.UpdatedAt.UTC().Truncate(time.Microsecond)
	inputPrice, inputOK := canonicalLLMPrice(source.InputPrice)
	outputPrice, outputOK := canonicalLLMPrice(source.OutputPrice)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.DisplayName, 255) ||
		!validUserRestoreText(source.ProviderType, 100) ||
		!validUserRestoreText(source.ProviderModelName, 255) ||
		!validUserRestoreText(source.Currency, 16) ||
		!validLLMModelBaseURL(source.BaseURL) ||
		(source.Description != nil && (len(*source.Description) > 65535 ||
			!validEnterpriseAuthText(*source.Description, 65535))) ||
		(source.ProtocolType != nil && !validEnterpriseAuthText(*source.ProtocolType, 100)) ||
		!validLLMProviderModelsJSON(source.ProviderModelsJSON) ||
		!validLLMCredentialSource(source.APIKeyState, source.APIKeySecretVersion) ||
		!validLLMCredentialSource(source.APIKeySecretRefState, source.APIKeyRefSecretVersion) ||
		!inputOK || !outputOK || !validMySQLDateTime(created) ||
		!validMySQLDateTime(updated) || updated.Before(created) {
		return NormalizedLLMModel{}, ErrLLMModelRestore
	}
	return NormalizedLLMModel{
		ID: mapping.TargetID, DisplayName: source.DisplayName,
		Description: copyLLMString(source.Description), ProviderType: source.ProviderType,
		ProtocolType: copyLLMString(source.ProtocolType), BaseURL: source.BaseURL,
		ProviderModelName:  source.ProviderModelName,
		ProviderModelsJSON: copyLLMString(source.ProviderModelsJSON),
		ReasoningEnabled:   source.ReasoningEnabled,
		APIKey:             nil, APIKeySecretRef: nil,
		IsSecure: source.IsSecure, IsActive: false,
		InputPrice: inputPrice, OutputPrice: outputPrice,
		Currency: source.Currency, CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func validLLMCredentialSource(state, version string) bool {
	switch state {
	case LLMModelCredentialNull, LLMModelCredentialEmpty:
		return version == ""
	case LLMModelCredentialNonempty:
		return validImmutableSecretVersion(version)
	default:
		return false
	}
}

func validImmutableSecretVersion(version string) bool {
	if version == "" || len(version) > 128 || version == "latest" ||
		version == "current" || version == "default" {
		return false
	}
	for _, char := range version {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-') {
			return false
		}
	}
	return true
}

func canonicalLLMPrice(raw string) (string, bool) {
	whole, fraction, dot := strings.Cut(raw, ".")
	if whole == "" || len(whole) > 10 || len(whole) > 1 && whole[0] == '0' ||
		dot && (len(fraction) == 0 || len(fraction) > 8) {
		return "", false
	}
	for _, part := range []string{whole, fraction} {
		for _, char := range part {
			if char < '0' || char > '9' {
				return "", false
			}
		}
	}
	return whole + "." + fraction + strings.Repeat("0", 8-len(fraction)), true
}

func validLLMModelBaseURL(raw string) bool {
	if !validUserRestoreText(raw, 500) {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" &&
		parsed.Fragment == "" && parsed.Opaque == ""
}

func validLLMProviderModelsJSON(raw *string) bool {
	if raw == nil || *raw == "" {
		return true
	}
	if len(*raw) > 65535 || !validEnterpriseAuthText(*raw, 65535) {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(*raw))
	decoder.DisallowUnknownFields()
	var entries []models.LLMProviderModel
	if decoder.Decode(&entries) != nil || entries == nil {
		return false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return false
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !validUserRestoreText(entry.ID, 255) ||
			!validEnterpriseAuthText(entry.DisplayName, 255) {
			return false
		}
		key := strings.ToLower(entry.ID)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func copyLLMString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneLLMModelSources(sources []LLMModelRestoreSource) []LLMModelRestoreSource {
	result := append([]LLMModelRestoreSource(nil), sources...)
	for i := range result {
		result[i].Description = copyLLMString(result[i].Description)
		result[i].ProtocolType = copyLLMString(result[i].ProtocolType)
		result[i].ProviderModelsJSON = copyLLMString(result[i].ProviderModelsJSON)
	}
	return result
}

func nilLLMModelProof(proof LLMModelSourceProofVerifier) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
