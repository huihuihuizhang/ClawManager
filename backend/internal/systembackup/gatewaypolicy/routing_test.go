package gatewaypolicy

import (
	"reflect"
	"testing"

	"clawreef/internal/systembackup/team"
)

func TestRoutingOwnerPolicyRetainsLegacyNullabilityAndOriginal(t *testing.T) {
	for _, nullable := range []bool{false, true} {
		source := team.Row{"routing_mode": team.Value("hybrid"), "base_url": team.Value("private"), "encrypted_api_key": team.Value("cipher"), "timeout_ms": team.Value("5000")}
		original := team.Clone(source)
		change := DisableRoutingClassifier(source, map[string]bool{"base_url": nullable, "encrypted_api_key": nullable})
		if !change.Quarantined || string(change.After["routing_mode"].Data) != "rules" || change.After["base_url"].IsNull != nullable || change.After["encrypted_api_key"].IsNull != nullable || len(change.After["base_url"].Data) != 0 || len(change.After["encrypted_api_key"].Data) != 0 || !reflect.DeepEqual(change.Before, original) || !reflect.DeepEqual(source, original) {
			t.Fatal("owner rule lost original or nullability")
		}
		change.After["timeout_ms"].Data[0] = '9'
		if !reflect.DeepEqual(source, original) {
			t.Fatal("owner output aliases source")
		}
	}
}
