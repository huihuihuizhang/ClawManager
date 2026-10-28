package systembackupevidence

import (
	"strings"
	"testing"
)

func TestTransitRetentionRequiresCompleteReferencesAndStableRouting(t *testing.T) {
	ref := KeyRef{Identity: strings.Repeat("a", 64), Version: "v1"}
	old := TransitConfig{Installation: "installation_test", Key: ref, Endpoint: "https://example.test", KeyName: "evidence", KeyVersion: 1}
	cases := []struct {
		name  string
		next  []TransitConfig
		refs  []KeyRef
		valid bool
	}{
		{"retained", []TransitConfig{old}, []KeyRef{ref}, true},
		{"empty scan", []TransitConfig{}, []KeyRef{}, true},
		{"unavailable next snapshot", nil, []KeyRef{}, false},
		{"unavailable scan", []TransitConfig{old}, nil, false},
		{"removed referenced", []TransitConfig{}, []KeyRef{ref}, false},
		{"unknown reference", []TransitConfig{old}, []KeyRef{{Identity: strings.Repeat("b", 64), Version: "v1"}}, false},
		{"duplicate", []TransitConfig{old, old}, []KeyRef{}, false},
	}
	if err := ValidateTransitKeyRetention("installation_test", nil, []TransitConfig{old}, []KeyRef{}); err == nil {
		t.Fatal("unavailable previous snapshot accepted")
	}
	changed := old
	changed.KeyVersion = 2
	cases = append(cases, struct {
		name  string
		next  []TransitConfig
		refs  []KeyRef
		valid bool
	}{"rebound", []TransitConfig{changed}, []KeyRef{}, false})
	changed = old
	changed.Endpoint = "https://other.test"
	cases = append(cases, struct {
		name  string
		next  []TransitConfig
		refs  []KeyRef
		valid bool
	}{"provider changed", []TransitConfig{changed}, []KeyRef{ref}, false})
	changed = old
	changed.KeyName = "other"
	cases = append(cases, struct {
		name  string
		next  []TransitConfig
		refs  []KeyRef
		valid bool
	}{"provider key changed", []TransitConfig{changed}, []KeyRef{ref}, false})
	changed = old
	changed.Installation = "installation_other"
	cases = append(cases, struct {
		name  string
		next  []TransitConfig
		refs  []KeyRef
		valid bool
	}{"wrong installation", []TransitConfig{changed}, []KeyRef{ref}, false})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTransitKeyRetention("installation_test", []TransitConfig{old}, tc.next, tc.refs)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
