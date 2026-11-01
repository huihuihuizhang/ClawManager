package systembackupbusinessa

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCurrentCallerRestoreDiscardsKeysWithoutErasingOriginalVersion(t *testing.T) {
	for _, raw := range []*string{nil, callerKeysString("[]"), callerKeysString(`[{"id":"historical-key","secret_hash":"named-source-hash","scopes":["teams:read"],"enabled":true}]`)} {
		for _, version := range []int64{0, 7, 9223372036854775807} {
			users, source := callerPolicyRestoreFixture(t)
			source.APIKeysJSON, source.APIKeysVersion = raw, &version
			frozen := cloneBusinessRestoreInput(BusinessRestoreInput{CallerPolicies: []NorthboundCallerPolicyRestoreSource{source}}).CallerPolicies[0]
			row, err := NormalizeNorthboundCallerPolicyForRestore(users, source)
			if err != nil || row.Enabled || row.APIKeysJSON == nil || *row.APIKeysJSON != "[]" || row.APIKeysVersion != version || !reflect.DeepEqual(source, frozen) {
				t.Fatal("current caller lost source evidence or retained usable keys", err)
			}
			*row.APIKeysJSON = "target-changed"
			if !reflect.DeepEqual(source, frozen) {
				t.Fatal("target key list aliases source")
			}
		}
	}
	users, old := callerPolicyRestoreFixture(t)
	row, err := NormalizeNorthboundCallerPolicyForRestore(users, old)
	if err != nil || row.APIKeysJSON != nil || row.APIKeysVersion != 0 {
		t.Fatal("old schema silently became current")
	}
}

func callerKeysString(s string) *string { return &s }

func TestCurrentCallerRestoreRejectsPartialColumnsAndMalformedKeys(t *testing.T) {
	for _, raw := range []string{"", "{}", "[", "[] []", strings.Repeat(" ", 65537) + "[]", "[" + strings.Repeat("{},", 20) + "{}]"} {
		users, source := callerPolicyRestoreFixture(t)
		version := int64(1)
		source.APIKeysJSON, source.APIKeysVersion = &raw, &version
		if _, err := NormalizeNorthboundCallerPolicyForRestore(users, source); !errors.Is(err, ErrNorthboundCallerPolicyRestore) {
			t.Fatal("invalid key document accepted")
		}
	}
	users, source := callerPolicyRestoreFixture(t)
	source.APIKeysJSON = callerKeysString("[]")
	if _, err := NormalizeNorthboundCallerPolicyForRestore(users, source); !errors.Is(err, ErrNorthboundCallerPolicyRestore) {
		t.Fatal("missing version accepted")
	}
	negative := int64(-1)
	source.APIKeysVersion = &negative
	if _, err := NormalizeNorthboundCallerPolicyForRestore(users, source); !errors.Is(err, ErrNorthboundCallerPolicyRestore) {
		t.Fatal("negative version accepted")
	}
}

func TestBusinessRestoreFreezesCurrentCallerColumnsAcrossAuthorityCallbacks(t *testing.T) {
	scope, binding, input, proof := businessRestoreFixture(t)
	version := int64(7)
	input.CallerPolicies[0].APIKeysJSON = callerKeysString("[]")
	input.CallerPolicies[0].APIKeysVersion = &version
	proof.wantInput = cloneBusinessRestoreInput(input)
	proof.onVerify = func(_ BusinessRestoreBinding, observed BusinessRestoreInput) {
		*observed.CallerPolicies[0].APIKeysJSON = "invalid-callback-value"
		*observed.CallerPolicies[0].APIKeysVersion = 99
		*input.CallerPolicies[0].APIKeysJSON = "invalid-caller-value"
		*input.CallerPolicies[0].APIKeysVersion = 100
	}
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil || len(rows.CallerPolicies) != 1 || rows.CallerPolicies[0].APIKeysVersion != 7 || rows.CallerPolicies[0].APIKeysJSON == nil || *rows.CallerPolicies[0].APIKeysJSON != "[]" {
		t.Fatal("callback changed frozen caller columns", err)
	}
}
