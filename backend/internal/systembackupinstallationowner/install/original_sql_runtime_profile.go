package install

// The profile is frozen by the ORIGINAL SQL operation version. Selecting a
// larger runtime is a fresh prepare before account creation, never a rewrite
// of an in-flight historical plan or a grant to a business/source account.
const originalSQLHistoricalRuntimeProfile = "controller-historical14.v1"
const originalSQLPublicRuntimeProfile = "public-runtime-publication-permits-control-evidence.v1"

func originalSQLProfileOperationVersion(profile string) string {
	switch profile {
	case "", originalSQLHistoricalRuntimeProfile:
		return "original198-sql-accounts-operation.v1"
	case originalSQLPublicRuntimeProfile:
		return "original198-sql-accounts-operation.v2"
	default:
		return ""
	}
}

func originalSQLProfileName(profile string) string {
	if profile == "" {
		return originalSQLHistoricalRuntimeProfile
	}
	return profile
}
