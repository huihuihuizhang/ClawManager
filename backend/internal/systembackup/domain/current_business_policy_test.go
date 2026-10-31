package domain

import (
	"context"
	"testing"
)

func TestCurrentAuthenticationHistoryNeverRestoresSourceSessions(t *testing.T) {
	for _, name := range []string{"iei_session_revocations", "northbound_auth_challenges", "northbound_sessions"} {
		source, target, policy := fixture()
		source.Tables = append(source.Tables, table(name, Row{"id": Text("1")}))
		target = append(target, table(name))
		plan, err := Normalize(context.Background(), source, target, policy)
		if err != nil {
			t.Fatal("original authentication archive policy", name, err)
		}
		for _, actual := range plan.Data.Tables {
			if actual.Name == name {
				t.Fatal("source authentication state restored", name)
			}
		}
		if len(find(source, name).Rows) != 1 {
			t.Fatal("archive source was mutated by target normalization")
		}
	}
}

func TestCurrentBusinessSecretsAndConfigRequireExactOwnerRestoreAdapters(t *testing.T) {
	for _, name := range []string{"gateway_keys", "gateway_key_budget_reservations", "gateway_key_budget_ledger", "gateway_image_artifacts", "gateway_image_jobs", "llm_model_user_grants", "routing_classifier_settings", "northbound_admin_settings", "northbound_caller_policies", "northbound_owner_records", "northbound_settings_audit"} {
		source, target, policy := fixture()
		source.Tables = append(source.Tables, table(name, Row{"id": Text("1"), "owner_specific_secret_or_execution_state": Text("named-fixture-private-value")}))
		target = append(target, table(name, Row{"id": Text("1"), "owner_specific_secret_or_execution_state": Text("unused-target-fixture")}))
		if _, err := Normalize(context.Background(), source, target, policy); err == nil {
			t.Fatal("unadapted owner secret/config/execution schema received identity fallback", name)
		}
	}
}
