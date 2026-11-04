package install

import (
	c "clawreef/internal/systembackupcontroller"
	"strings"
	"testing"
)

// Data boundary only; no fake record or caller hash is promoted to authority.
// The actual issuer still authenticates original admin/enrollment/current SQL
// head and all native purpose proofs before it may call this comparison.
func TestOriginalPublicationBootstrapBindingUsesOriginalRequestAndFixedFirstVersion(t *testing.T) {
	f := newAuthorityFixture(t)
	request, e := readRequest(f.i, f.files)
	if e != nil {
		t.Fatal(e)
	}
	defer request.observer.Close()
	g := c.ExecutionGrant{InstallationID: f.i.plan.Target.InstallationID, ServerUUID: f.i.plan.Target.ServerUUID, Database: f.i.plan.Target.Database, DatabaseAccount: f.i.plan.Target.DatabaseAccount, ConfigVersion: 1, ConfigSHA256: f.record.ConfigSHA256}
	selected := BootstrapSourceFilePin{File: f.files.ConfigFile, SHA256: f.files.ConfigFileSHA256}
	for _, mode := range []string{"original", "future-version", "record-revision-is-not-config-version", "wrong-installation", "foreign-record-config", "changed-registry-selection", "changed-file", "changed-hash"} {
		t.Run(mode, func(t *testing.T) {
			grant := g
			record := f.record
			pin := selected
			switch mode {
			case "future-version":
				grant.ConfigVersion = 2
			case "record-revision-is-not-config-version":
				record.Revision = 19
			case "wrong-installation":
				record.Target.InstallationID = "installation_foreign"
			case "foreign-record-config":
				record.ConfigSHA256 = strings.Repeat("f", 64)
			case "changed-registry-selection":
				record.RegistrySetSHA256 = strings.Repeat("f", 64)
			case "changed-file":
				pin.File += ".foreign"
			case "changed-hash":
				pin.SHA256 = strings.Repeat("f", 64)
			}
			e := originalPublicationBootstrapBinding(f.i.plan.Target, grant, record, pin, request)
			expected := mode == "original" || mode == "record-revision-is-not-config-version"
			if expected && e != nil || !expected && e == nil {
				t.Fatalf("wrong comparison result for %s", mode)
			}
		})
	}
}
