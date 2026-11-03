package systembackupexecution

import (
	ma "clawreef/internal/systembackupminioauthority"
	"strings"
	"testing"
	"time"
)

func TestRuntimePublicationSourceStampRetainsEveryConcreteIdentity(t *testing.T) {
	// Detached private identity DATA projection only, not successful provider
	// observation/admission. Production obtains it from actual C concrete APIs.
	base := MinIOPublicationPermissionObservation{configuration: strings.Repeat("1", 64), owner: strings.Repeat("2", 64), resources: strings.Repeat("3", 64), native: strings.Repeat("4", 64)}
	original, err := runtimePublicationSourceStamp(base, ma.PermissionProfile)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{original: true}
	september, err := runtimePublicationSourceStamp(base, ma.SeptemberPermissionProfile)
	if err != nil || september == original {
		t.Fatal("profile replacement concealed by identical provider identities", err)
	}
	if _, err := runtimePublicationSourceStamp(base, ""); err == nil {
		t.Fatal("missing profile stamped")
	}
	for _, field := range []string{"configuration", "owner", "resources", "native"} {
		changed := base
		switch field {
		case "configuration":
			changed.configuration = strings.Repeat("5", 64)
		case "owner":
			changed.owner = strings.Repeat("5", 64)
		case "resources":
			changed.resources = strings.Repeat("5", 64)
		case "native":
			changed.native = strings.Repeat("5", 64)
		}
		stamp, err := runtimePublicationSourceStamp(changed, ma.PermissionProfile)
		if err != nil || seen[stamp] {
			t.Fatal("different original identity concealed", field, err)
		}
		seen[stamp] = true
	}
	base.checkedAt = time.Now().UTC()
	if stamp, err := runtimePublicationSourceStamp(base, ma.PermissionProfile); err != nil || stamp != original {
		t.Fatal("new observation time renewed identity", err)
	}
	for _, missing := range []string{"configuration", "owner", "resources", "native"} {
		changed := base
		switch missing {
		case "configuration":
			changed.configuration = ""
		case "owner":
			changed.owner = ""
		case "resources":
			changed.resources = ""
		case "native":
			changed.native = ""
		}
		if stamp, err := runtimePublicationSourceStamp(changed, ma.PermissionProfile); err == nil || stamp != "" {
			t.Fatal("partial provider identity admitted", missing)
		}
	}
}
