package domain

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"clawreef/internal/models"
	businessa "clawreef/internal/systembackupbusinessa"
)

const LLMModel071Normalizer = "llm-model.071"
const LLMModelGrant062Normalizer = "llm-model-user-grant.062"
const model071Columns = "id display_name description provider_type protocol_type base_url provider_model_name api_key api_key_secret_ref is_secure is_active input_price output_price currency created_at updated_at reasoning_enabled provider_models_json model_group deployment_priority max_concurrent_requests context_window_tokens quality_tier supports_tools supports_vision capability_source tools_support_override reasoning_control_mode visibility_scope access_policy_version vision_support_override model_kind image_generation_enabled image_edit_enabled image_price_per_image"
const modelGrant062Columns = "model_id user_id created_at"

type LLMSecretVersions struct{ APIKey, APIKeySecretRef string }

func validateModelAdapter(a TableAdapter, t Table) error {
	if a.InterruptedAt != "" {
		return ErrSchema
	}
	columns, pk, name := model071Columns, []string{"id"}, "llm_models"
	if a.Normalizer == LLMModelGrant062Normalizer {
		columns, pk, name = modelGrant062Columns, []string{"model_id", "user_id"}, "llm_model_user_grants"
		if len(a.LLMSecrets) != 0 {
			return ErrSchema
		}
	}
	fields := strings.Fields(columns)
	if t.Name != name || len(t.Columns) != len(fields) || !slices.Equal(t.PrimaryKey, pk) {
		return ErrSchema
	}
	for _, field := range fields {
		if !hasColumn(t, field) || a.Columns[field] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}

func validateModelRestoreInputs(ctx context.Context, s Snapshot, adapters map[string]TableAdapter) error {
	modelsAdapter := adapters["llm_models"]
	neededVersions := map[string]bool{}
	for _, table := range s.Tables {
		if table.Name == "llm_model_user_grants" && len(table.Rows) > 0 && (adapters[table.Name].Normalizer != LLMModelGrant062Normalizer || modelsAdapter.Normalizer != LLMModel071Normalizer) {
			return ErrNormalization
		}
		if table.Name != "llm_models" || modelsAdapter.Normalizer != LLMModel071Normalizer {
			continue
		}
		if modelsAdapter.validate(table) != nil {
			return ErrSchema
		}
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, field := range []string{"api_key", "api_key_secret_ref"} {
				if cell := row[field]; !cell.Null && len(cell.Bytes) > 0 {
					neededVersions[row["id"].String()] = true
				}
			}
		}
	}
	if modelsAdapter.Normalizer == LLMModel071Normalizer {
		if len(neededVersions) != len(modelsAdapter.LLMSecrets) {
			return ErrData
		}
		for id := range modelsAdapter.LLMSecrets {
			if !neededVersions[id] {
				return ErrData
			}
		}
	}
	return nil
}

var modelPrice = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})(\.[0-9]{1,8})?$`)

// Explicit current extensions; SQL decimals remain strings, nullable capability
// overrides remain pointers. No runtime model float64 conversion is used.
func validateModel071Extensions(row Row) error {
	var group, reasoning, visibility, kind, capability string
	var priority, concurrency, contextWindow, tier, version int
	var tools, vision, generation, edit bool
	var toolsOverride, visionOverride *bool
	var price *string
	if err := decodeOwnerCells(row, map[string]any{"model_group": &group, "deployment_priority": &priority, "max_concurrent_requests": &concurrency, "context_window_tokens": &contextWindow, "quality_tier": &tier, "supports_tools": &tools, "supports_vision": &vision, "capability_source": &capability, "tools_support_override": &toolsOverride, "reasoning_control_mode": &reasoning, "visibility_scope": &visibility, "access_policy_version": &version, "vision_support_override": &visionOverride, "model_kind": &kind, "image_generation_enabled": &generation, "image_edit_enabled": &edit, "image_price_per_image": &price}); err != nil {
		return err
	}
	if !utf8.ValidString(group) || utf8.RuneCountInString(group) > 100 || !utf8.ValidString(capability) || utf8.RuneCountInString(capability) > 64 || !models.ValidReasoningControlMode(reasoning) || !slices.Contains([]string{models.ModelVisibilityAll, models.ModelVisibilitySelected}, visibility) || !slices.Contains([]string{models.ModelKindChat, models.ModelKindImage, models.ModelKindOther}, kind) || priority < 0 || priority > math.MaxInt32 || concurrency < 0 || concurrency > math.MaxInt32 || contextWindow < 0 || contextWindow > math.MaxInt32 || tier < 0 || tier > 4 || version < 1 || version > math.MaxInt32 || (price != nil && !modelPrice.MatchString(*price)) {
		return ErrData
	}
	// Validate explicit operation definitions without rediscovering capabilities
	// or backfilling a missing protocol from the provider's current defaults.
	protocol := row["protocol_type"]
	openAI := !protocol.Null && (protocol.String() == models.ProtocolTypeOpenAI || protocol.String() == models.ProtocolTypeOpenAICompatible)
	if (reasoning != "" && reasoning != "none" && !openAI) || ((generation || edit) && (kind != models.ModelKindImage || !openAI)) {
		return ErrData
	}
	return nil
}

func model071Source(row Row, versions LLMSecretVersions) (businessa.LLMModelRestoreSource, error) {
	var source businessa.LLMModelRestoreSource
	if err := decodeOwnerCells(row, map[string]any{"id": &source.ID, "display_name": &source.DisplayName, "description": &source.Description, "provider_type": &source.ProviderType, "protocol_type": &source.ProtocolType, "base_url": &source.BaseURL, "provider_model_name": &source.ProviderModelName, "provider_models_json": &source.ProviderModelsJSON, "reasoning_enabled": &source.ReasoningEnabled, "is_secure": &source.IsSecure, "is_active": &source.IsActive, "input_price": &source.InputPrice, "output_price": &source.OutputPrice, "currency": &source.Currency, "created_at": &source.CreatedAt, "updated_at": &source.UpdatedAt}); err != nil {
		return source, err
	}
	credential := func(name string) (string, error) {
		cell, present := row[name]
		if !present {
			return "", ErrSchema
		}
		if cell.Null {
			return businessa.LLMModelCredentialNull, nil
		}
		if len(cell.Bytes) == 0 {
			return businessa.LLMModelCredentialEmpty, nil
		}
		return businessa.LLMModelCredentialNonempty, nil
	}
	var err error
	if source.APIKeyState, err = credential("api_key"); err != nil {
		return source, err
	}
	if source.APIKeySecretRefState, err = credential("api_key_secret_ref"); err != nil {
		return source, err
	}
	source.APIKeySecretVersion, source.APIKeyRefSecretVersion = versions.APIKey, versions.APIKeySecretRef
	return source, nil
}

func normalizeModel071(row Row, versions map[string]LLMSecretVersions) error {
	if err := validateModel071Extensions(row); err != nil {
		return err
	}
	source, err := model071Source(row, versions[row["id"].String()])
	if err != nil {
		return err
	}
	// Use A's pure row contract after common archived-input/schema checks. The
	// production full-source composition must still prove both version bindings;
	// this map and this transformation are not a replacement for that proof.
	if _, err = businessa.NormalizeLLMModelForRestore(source, businessa.LLMModelRestoreMapping{SourceID: source.ID, TargetID: source.ID}); err != nil {
		return ErrData
	}
	row["is_active"] = Text("0")
	row["api_key"], row["api_key_secret_ref"] = Cell{Null: true}, Cell{Null: true}
	row["base_url"] = Text("https://disabled.invalid")
	return nil
}

func VerifyModelGrantQuarantine(ctx context.Context, snapshot Snapshot) error {
	users := map[string]bool{}
	modelRows := map[string]Row{}
	currentModels := false
	for _, table := range snapshot.Tables {
		if table.Name == "users" {
			for _, row := range table.Rows {
				users[row["id"].String()] = true
			}
		}
		if table.Name != "llm_models" {
			continue
		}
		currentModels = hasColumn(table, "access_policy_version")
		if currentModels && len(table.Columns) != len(strings.Fields(model071Columns)) {
			return ErrSchema
		}
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			modelRows[row["id"].String()] = row
			if !currentModels {
				continue
			}
			if row["is_active"].String() != "0" || !row["api_key"].Null || !row["api_key_secret_ref"].Null || row["base_url"].String() != "https://disabled.invalid" {
				return ErrNormalization
			}
			copy := cloneRow(row)
			if err := normalizeModel071(copy, nil); err != nil {
				return err
			}
		}
	}
	for _, table := range snapshot.Tables {
		if table.Name != "llm_model_user_grants" || len(table.Rows) == 0 {
			continue
		}
		if !currentModels || len(table.Columns) != 3 || !slices.Equal(table.PrimaryKey, []string{"model_id", "user_id"}) {
			return ErrSchema
		}
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			var model, user int
			var created time.Time
			if err := decodeOwnerCells(row, map[string]any{"model_id": &model, "user_id": &user, "created_at": &created}); err != nil {
				return err
			}
			if model <= 0 || model > math.MaxInt32 || user <= 0 || user > math.MaxInt32 || created.Year() < 1000 || created.Year() > 9999 || modelRows[strconv.Itoa(model)] == nil || !users[strconv.Itoa(user)] {
				return ErrData
			}
		}
	}
	return nil
}
