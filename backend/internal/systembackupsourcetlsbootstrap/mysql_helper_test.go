package systembackupsourcetlsbootstrap

import "testing"

func TestMySQLBootstrapRejectsUnreviewedReloadVersions(t *testing.T) {
	for _, version := range []string{"5.7.44", "8.0.15", "10.6.0-MariaDB", "9.0.0", "8.0.bad"} {
		if supportedMySQLReload(version) {
			t.Fatal("unreviewed version accepted", version)
		}
	}
	for _, version := range []string{"8.0.16", "8.0.44-ubuntu", "8.4.1"} {
		if !supportedMySQLReload(version) {
			t.Fatal("reviewed reload version rejected", version)
		}
	}
}
