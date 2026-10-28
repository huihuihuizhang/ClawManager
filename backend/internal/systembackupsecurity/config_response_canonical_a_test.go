package systembackupsecurity

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestConfigResponseCanonicalPolicyMatchesWriter(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		raw := bootstrapFixture(t)
		if enabled {
			raw = bytes.Replace(raw, []byte(`"enabled":false`), []byte(`"enabled":true`), 1)
		}
		config, err := DecodeConfigValues(raw)
		if err != nil {
			t.Fatal(err)
		}
		reason := "已审核的维护原因 <保留原始 Unicode>"
		p := ConfigMutationResponseContentPolicy{InstallationID: "installation_test", CreatedBy: 42, Version: 4, Config: config, RedactedReason: &reason, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), DeploymentEnabled: true}
		got, err := CanonicalConfigMutationResponse(p)
		want, e := configMutationResponse(p.InstallationID, RegistrationActor{UserID: p.CreatedBy}, p.Version, p.Config, p.RedactedReason, p.CreatedAt, p.DeploymentEnabled)
		if err != nil || e != nil || !bytes.Equal(got, want) {
			t.Fatal("complete writer response parity", err, e)
		}
		saved := append([]byte(nil), got...)
		reason = "later mutation"
		config.CanonicalJSON()[0] = 'x'
		if !bytes.Equal(got, saved) {
			t.Fatal("response aliases policy")
		}
	}
}

func TestConfigResponseCanonicalPolicyRejectsInvalidFacts(t *testing.T) {
	config, err := DecodeConfigValues(bootstrapFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"installation", "actor", "bootstrap-version", "unsafe-version", "config", "zero-time", "non-utc", "empty-reason", "oversize-reason", "invalid-unicode"} {
		t.Run(name, func(t *testing.T) {
			p := ConfigMutationResponseContentPolicy{InstallationID: "installation_test", CreatedBy: 42, Version: 2, Config: config, CreatedAt: time.Now().UTC()}
			switch name {
			case "installation":
				p.InstallationID = "foreign"
			case "actor":
				p.CreatedBy = 0
			case "bootstrap-version":
				p.Version = 1
			case "unsafe-version":
				p.Version = 9007199254740992
			case "config":
				p.Config = ConfigValues{}
			case "zero-time":
				p.CreatedAt = time.Time{}
			case "non-utc":
				p.CreatedAt = p.CreatedAt.In(time.FixedZone("wrong", 3600))
			case "empty-reason":
				s := ""
				p.RedactedReason = &s
			case "oversize-reason":
				s := strings.Repeat("x", 513)
				p.RedactedReason = &s
			case "invalid-unicode":
				s := string([]byte{0xff})
				p.RedactedReason = &s
			}
			if raw, err := CanonicalConfigMutationResponse(p); err != ErrConfigMutation || len(raw) != 0 {
				t.Fatal("invalid policy produced response", err)
			}
		})
	}
}
