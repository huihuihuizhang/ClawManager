package systembackupinstallationowner

import a "clawreef/internal/systembackupkekadapter"

// Keep the original installation entry on the same RSA identity comparison
// used by the runtime permission and publication owners.
func installedVaultPublicKeysEqual(actual, expected []string) bool {
	return a.VaultRSAPublicKeysEqual(actual, expected)
}
