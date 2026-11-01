package domain

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func modelRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := fixture()
	row := Row{"id": Text("5"), "display_name": Text("Original image model"), "description": Text("模型历史"), "provider_type": Text("openai"), "protocol_type": Text("openai"), "base_url": Text("https://original-model.invalid/v1"), "provider_model_name": Text("original-model"), "api_key": Text("named-original-secret"), "api_key_secret_ref": Text("named-original-ref"), "is_secure": Text("1"), "is_active": Text("1"), "input_price": Text("0.00000001"), "output_price": Text("9999999999.99999999"), "currency": Text("USD"), "created_at": Text("2026-10-01 01:02:03"), "updated_at": Text("2026-10-01 01:02:04"), "reasoning_enabled": Text("1"), "provider_models_json": Text(`[{"id":"original-model","display_name":"Original"}]`), "model_group": Text("original-group"), "deployment_priority": Text("100"), "max_concurrent_requests": Text("8"), "context_window_tokens": Text("128000"), "quality_tier": Text("4"), "supports_tools": Text("1"), "supports_vision": Text("1"), "capability_source": Text("provider_metadata"), "tools_support_override": Text("0"), "reasoning_control_mode": Text("none"), "visibility_scope": Text("selected_users"), "access_policy_version": Text("2147483647"), "vision_support_override": Cell{Null: true}, "model_kind": Text("image"), "image_generation_enabled": Text("1"), "image_edit_enabled": Text("1"), "image_price_per_image": Text("9999999999.99999999")}
	second := cloneRow(row)
	second["id"], second["display_name"], second["model_kind"] = Text("6"), Text("Original chat model"), Text("chat")
	second["api_key"], second["api_key_secret_ref"], second["image_price_per_image"] = Cell{Null: true}, Text(""), Cell{Null: true}
	second["access_policy_version"], second["image_generation_enabled"], second["image_edit_enabled"] = Text("1"), Text("0"), Text("0")
	second["tools_support_override"], second["vision_support_override"] = Cell{Null: true}, Text("0")
	modelTable := table("llm_models", row, second)
	modelTable.UniqueKeys = []UniqueKey{{Name: "display_name", Columns: []string{"display_name"}}}
	grants := table("llm_model_user_grants", Row{"model_id": Text("5"), "user_id": Text("4"), "created_at": Text("2026-10-01 01:02:03")}, Row{"model_id": Text("6"), "user_id": Text("1"), "created_at": Text("2026-10-01 01:02:04")})
	grants.PrimaryKey = []string{"model_id", "user_id"}
	grants.ForeignKeys = []ForeignKey{{"model_id", "llm_models", "id"}, {"user_id", "users", "id"}}
	s.Tables = append(s.Tables, modelTable, grants)
	p.Dependencies = map[string]TableAdapter{}
	for _, item := range []struct {
		table              Table
		normalizer, fields string
	}{{modelTable, LLMModel071Normalizer, model071Columns}, {grants, LLMModelGrant062Normalizer, modelGrant062Columns}} {
		a := TableAdapter{SchemaSHA256: SchemaDigest(item.table), Normalizer: item.normalizer, Columns: map[string]string{}}
		for _, name := range strings.Fields(item.fields) {
			a.Columns[name] = "preserve"
		}
		if item.normalizer == LLMModel071Normalizer {
			a.LLMSecrets = map[string]LLMSecretVersions{"5": {APIKey: "named-inline-version-1", APIKeySecretRef: "named-reference-version-2"}}
		}
		p.Dependencies[item.table.Name] = a
	}
	p.Configs = JSONRegistry{"llm_models.provider_models_json": {{Path: []string{"*", "id"}, Action: "preserve"}, {Path: []string{"*", "display_name"}, Action: "preserve"}}}
	return s, copyTables(s.Tables), p
}

func TestModel071AndGrant062PreserveDefinitionsAndDisableProviders(t *testing.T) {
	s, target, p := modelRestoreFixture()
	before, _ := Digest(s)
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range find(plan.Data, "llm_models").Rows {
		if row["is_active"].String() != "0" || !row["api_key"].Null || !row["api_key_secret_ref"].Null || row["base_url"].String() != "https://disabled.invalid" {
			t.Fatal("provider remains usable")
		}
		for name, value := range find(s, "llm_models").Rows[i] {
			if name == "provider_models_json" {
				var providers []struct {
					ID          string `json:"id"`
					DisplayName string `json:"display_name"`
				}
				if json.Unmarshal(row[name].Bytes, &providers) != nil || len(providers) != 1 || providers[0].ID != "original-model" || providers[0].DisplayName != "Original" {
					t.Fatal("provider definitions changed")
				}
				continue
			}
			if name == "is_active" || name == "api_key" || name == "api_key_secret_ref" || name == "base_url" {
				continue
			}
			if !reflect.DeepEqual(value, row[name]) {
				t.Fatal("model definition/precision/NULL lost", name)
			}
		}
	}
	if !reflect.DeepEqual(find(s, "llm_model_user_grants").Rows, find(plan.Data, "llm_model_user_grants").Rows) {
		t.Fatal("access definitions changed")
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source changed")
	}
}

func TestModel071RejectsMissingOrInventedCredentialMappings(t *testing.T) {
	for _, mode := range []string{"no-model-adapter", "no-grant-adapter", "missing-map", "missing-key-version", "missing-ref-version", "orphan-map", "version-on-null", "mutable-version", "fixed-key-before-validation", "unknown-column", "unique-drift", "missing-model", "missing-user", "invalid-price", "unknown-visibility", "null-access-version", "invalid-override", "invalid-original-url", "invalid-original-provider-json", "image-chat-kind", "image-unknown-protocol", "reasoning-unknown-protocol"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := modelRestoreFixture()
			a := p.Dependencies["llm_models"]
			row := find(s, "llm_models").Rows[0]
			switch mode {
			case "no-model-adapter":
				a.Normalizer = ""
			case "no-grant-adapter":
				delete(p.Dependencies, "llm_model_user_grants")
			case "missing-map":
				a.LLMSecrets = nil
			case "missing-key-version":
				a.LLMSecrets["5"] = LLMSecretVersions{APIKeySecretRef: "named-version"}
			case "missing-ref-version":
				a.LLMSecrets["5"] = LLMSecretVersions{APIKey: "named-version"}
			case "orphan-map":
				a.LLMSecrets["777"] = LLMSecretVersions{APIKey: "invented-version"}
			case "version-on-null":
				row["api_key"] = Cell{Null: true}
			case "mutable-version":
				a.LLMSecrets["5"] = LLMSecretVersions{APIKey: "latest", APIKeySecretRef: "named-version"}
			case "fixed-key-before-validation":
				a.Columns["api_key"] = "null"
			case "unknown-column":
				target[len(target)-2].Columns = append(target[len(target)-2].Columns, Column{Name: "future_provider_token", Type: "text"})
			case "unique-drift":
				target[len(target)-2].UniqueKeys = nil
			case "missing-model":
				find(s, "llm_model_user_grants").Rows[0]["model_id"] = Text("777")
			case "missing-user":
				find(s, "llm_model_user_grants").Rows[0]["user_id"] = Text("777")
			case "invalid-price":
				row["image_price_per_image"] = Text("0.000000001")
			case "unknown-visibility":
				row["visibility_scope"] = Text("public")
			case "null-access-version":
				row["access_policy_version"] = Cell{Null: true}
			case "invalid-override":
				row["tools_support_override"] = Text("2")
			case "invalid-original-url":
				row["base_url"] = Text("https://provider.invalid?secret=unapproved")
			case "invalid-original-provider-json":
				row["provider_models_json"] = Text(`[{"id":"model","future_secret":"unapproved"}]`)
			case "image-chat-kind":
				row["model_kind"] = Text("chat")
			case "image-unknown-protocol":
				row["protocol_type"] = Cell{Null: true}
			case "reasoning-unknown-protocol":
				row["image_generation_enabled"], row["image_edit_enabled"] = Text("0"), Text("0")
				row["reasoning_control_mode"], row["protocol_type"] = Text("enable-thinking"), Text("anthropic")
			}
			p.Dependencies["llm_models"] = a
			if _, err := Normalize(context.Background(), s, target, p); err == nil {
				t.Fatal("unsafe model accepted")
			}
		})
	}
}

func TestModel071PreservesTriStateZeroPriceAndHistoricalDefinitions(t *testing.T) {
	for _, override := range []Cell{{Null: true}, Text("0"), Text("1")} {
		for _, imagePrice := range []Cell{{Null: true}, Text("0.00000000"), Text("1000001.12345678")} {
			s, target, p := modelRestoreFixture()
			row := find(s, "llm_models").Rows[0]
			row["tools_support_override"], row["vision_support_override"] = override, override
			row["supports_tools"], row["supports_vision"] = Text("0"), Text("0")
			row["image_price_per_image"] = imagePrice
			row["deployment_priority"], row["max_concurrent_requests"], row["context_window_tokens"] = Text("0"), Text("0"), Text("0")
			row["reasoning_control_mode"] = Text("")
			before := cloneRow(row)
			plan, err := Normalize(context.Background(), s, target, p)
			if err != nil {
				t.Fatal("historical storage definition rejected", err)
			}
			got := find(plan.Data, "llm_models").Rows[0]
			for _, name := range []string{"tools_support_override", "vision_support_override", "supports_tools", "supports_vision", "image_price_per_image", "model_group", "deployment_priority", "max_concurrent_requests", "context_window_tokens", "reasoning_control_mode", "protocol_type"} {
				if !reflect.DeepEqual(got[name], before[name]) {
					t.Fatal("definition re-inferred", name)
				}
			}
		}
	}
}

func TestModel071VerifierRejectsCredentialAndGrantTampering(t *testing.T) {
	for _, field := range []string{"is_active", "api_key", "api_key_secret_ref", "base_url", "user_id"} {
		s, target, p := modelRestoreFixture()
		plan, err := Normalize(context.Background(), s, target, p)
		if err != nil {
			t.Fatal(err)
		}
		if field == "user_id" {
			find(plan.Data, "llm_model_user_grants").Rows[0][field] = Text("777")
		} else {
			find(plan.Data, "llm_models").Rows[0][field] = Text("1")
		}
		if VerifyModelGrantQuarantine(context.Background(), plan.Data) == nil {
			t.Fatal("unsafe model expected data accepted", field)
		}
	}
}

func TestModel071UsesUTF8CharacterLimits(t *testing.T) {
	for _, field := range []struct {
		name  string
		limit int
	}{{"model_group", 100}, {"capability_source", 64}} {
		for _, char := range []string{"组", "🧭"} {
			for _, extra := range []int{0, 1} {
				s, target, p := modelRestoreFixture()
				value := Text(strings.Repeat(char, field.limit+extra))
				find(s, "llm_models").Rows[0][field.name] = value
				plan, err := Normalize(context.Background(), s, target, p)
				if extra == 1 {
					if err == nil {
						t.Fatal("VARCHAR character limit bypassed", field.name)
					}
					continue
				}
				if err != nil || !reflect.DeepEqual(find(plan.Data, "llm_models").Rows[0][field.name], value) {
					t.Fatal("valid UTF8 VARCHAR rejected or changed", field.name, err)
				}
			}
		}
		s, target, p := modelRestoreFixture()
		find(s, "llm_models").Rows[0][field.name] = Cell{Bytes: []byte{0xff}}
		if _, err := Normalize(context.Background(), s, target, p); err == nil {
			t.Fatal("invalid UTF8 accepted", field.name)
		}
	}
}
