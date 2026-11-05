package install

// The profile is frozen by the ORIGINAL SQL operation version. Selecting a
// larger runtime is a fresh prepare before account creation, never a rewrite
// of an in-flight historical plan or a grant to a business/source account.
const originalSQLHistoricalRuntimeProfile = "controller-historical14.v1"
const originalSQLC1Profile = "public-runtime-c1-installer-bootstrap.v1"
const originalSQLMinIOMetadataProfile = "public-runtime-c1-minio-metadata-read.v1"

func originalSQLC1Selected(profile string) bool {
	return profile == originalSQLC1Profile || profile == originalSQLMinIOMetadataProfile
}

const originalSQLPublicRuntimeProfile = "public-runtime-publication-permits-control-evidence.v1"

func originalSQLProfileOperationVersion(profile string) string {
	switch profile {
	case "", originalSQLHistoricalRuntimeProfile:
		return "original198-sql-accounts-operation.v1"
	case originalSQLMinIOMetadataProfile:
		return "original-c1-minio-metadata-sql-accounts-operation.v4"
	case originalSQLC1Profile:
		return "original-c1-sql-accounts-operation.v3"
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

func originalSQLMaterialsVersion(profile string) string {
	if originalSQLC1Selected(profile) {
		return "original-c1-sql-account-materials.v3"
	}
	return "original198-sql-account-materials.v1"
}

func originalSQLStatePrefix(profile string) string {
	if originalSQLC1Selected(profile) {
		return "original_c1_sql_accounts"
	}
	return "original198_sql_accounts"
}
