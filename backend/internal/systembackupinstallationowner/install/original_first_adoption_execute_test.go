package install

import (
	"context"
	"strings"
	"testing"
)

func TestOriginalFirstAdoptionExecuteRejectsInvalidSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		session   *PreparedOriginalFirstAdoption
		file, pin string
	}{
		{"nil", nil, "issuer", strings.Repeat("a", 64)},
		{"zero", &PreparedOriginalFirstAdoption{}, "issuer", strings.Repeat("a", 64)},
		{"missing_material", &PreparedOriginalFirstAdoption{}, "", strings.Repeat("a", 64)},
		{"wrong_pin", &PreparedOriginalFirstAdoption{}, "issuer", "bad-pin"},
		{"repeat", &PreparedOriginalFirstAdoption{executionStarted: true}, "issuer", strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.session.AdoptOriginalFilesystem(context.Background(), tc.file, tc.pin); err == nil || got.State != "" {
				t.Fatal("invalid session executed real source issuance/adoption")
			}
		})
	}
}
