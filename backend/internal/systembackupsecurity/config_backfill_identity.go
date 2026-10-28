package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"
)

const ConfigBackfillRowProfile = "a-config-canonical-backfill-row.v1"
const ConfigBackfillProvenanceProfile = "a-config-canonical-backfill-provenance.v1"

// These are independently scanned locked SQL facts, not values reconstructed
// from the source file. Materialized contains ALL effective SQL columns, as
// exact SQL text: booleans 0/1, integers decimal, DECIMAL(4,2) two places.
// RowID is an unsigned BIGINT decimal string, avoiding JSON precision loss.
type ConfigBackfillRowFacts struct {
	TargetServerUUID, TargetDatabase, InstallationID string
	RowID, SchemaVersion                             string
	Version, RowVersion, ConfigSizeBytes             int64
	CopiedFromVersion                                *int64
	ConfigSHA256, CreatedBy                          string
	ChangeReason                                     *string
	CreatedAt                                        time.Time
	Materialized                                     map[string]string
}

// CanonicalConfigBackfillRowIdentity verifies exact source/row agreement and
// hashes the immutable row facts. It authenticates neither the facts nor the
// source, grants no write authority, and performs no SQL. The writer must lock
// and scan the real row in its transaction, and compare this digest with the
// independently authenticated grant/request before and after a write.
// canonical_config_json is excluded because NULL->original is the one allowed
// change. Its NULL/same/different state must be checked separately under lock.
func CanonicalConfigBackfillRowIdentity(f ConfigBackfillRowFacts, original []byte) ([]byte, string, error) {
	fail := func() ([]byte, string, error) { return nil, "", ErrConfigMutation }
	if len(original) < 2 || len(original) > 262144 || len(f.Materialized) > 256 ||
		!backfillIdentityTarget(f.TargetServerUUID, f.TargetDatabase, f.InstallationID, f.Version, f.ConfigSHA256, f.ConfigSizeBytes) ||
		f.SchemaVersion != "system-backup-config.v1" || f.RowVersion != 1 ||
		len(f.CreatedBy) < 1 || len(f.CreatedBy) > 128 || !utf8.ValidString(f.CreatedBy) ||
		f.ChangeReason != nil && (len(*f.ChangeReason) < 1 || len(*f.ChangeReason) > 512 || !utf8.ValidString(*f.ChangeReason)) {
		return fail()
	}
	id, err := strconv.ParseUint(f.RowID, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != f.RowID {
		return fail()
	}
	if f.CopiedFromVersion != nil && (*f.CopiedFromVersion < 1 || *f.CopiedFromVersion >= f.Version) {
		return fail()
	}
	_, offset := f.CreatedAt.Zone()
	if f.CreatedAt.IsZero() || offset != 0 || f.CreatedAt.Year() < 1000 || f.CreatedAt.Year() > 9999 || f.CreatedAt.Nanosecond()%1000 != 0 {
		return fail()
	}
	original = append([]byte(nil), original...)
	values, err := DecodeConfigValues(original)
	if err != nil || !bytes.Equal(values.CanonicalJSON(), original) || values.SHA256() != f.ConfigSHA256 || int64(len(original)) != f.ConfigSizeBytes {
		return fail()
	}
	columns, expected, err := values.sqlValues(f.InstallationID, f.CreatedBy, "unused", f.Version)
	if err != nil {
		return fail()
	}
	materialized := make(map[string]any, len(f.Materialized))
	for i, column := range columns {
		switch column {
		case "origin_installation_id", "version", "config_sha256", "config_size_bytes", "created_by", "change_reason", "canonical_config_json":
			continue
		}
		var text string
		switch v := expected[i].(type) {
		case string:
			text = v
		case int64:
			text = strconv.FormatInt(v, 10)
		case bool:
			text = "0"
			if v {
				text = "1"
			}
		default:
			return fail()
		}
		if column == "source_size_safety_factor" {
			// ConfigValues uses shortest JCS numbers; MySQL DECIMAL(4,2)
			// returns a fixed scale. Convert from the validated scaled integer,
			// without float64 and without trimming independently scanned SQL.
			scaled := values.snapshot.numbers[column]
			text = strconv.FormatInt(scaled/100, 10) + "." + strconv.FormatInt(100+scaled%100, 10)[1:]
		}
		actual, present := f.Materialized[column]
		if !present || actual != text {
			return fail()
		}
		materialized[column] = actual
	}
	if len(materialized) != len(f.Materialized) {
		return fail()
	}
	var copied, reason any
	if f.CopiedFromVersion != nil {
		copied = json.Number(strconv.FormatInt(*f.CopiedFromVersion, 10))
	}
	if f.ChangeReason != nil {
		reason = *f.ChangeReason
	}
	return backfillIdentityResult(map[string]any{
		"domain":             "clawmanager.system-backup.config-canonical-backfill-row.v1",
		"target_server_uuid": f.TargetServerUUID, "target_database": f.TargetDatabase,
		"row_id": f.RowID, "schema_version": f.SchemaVersion, "origin_installation_id": f.InstallationID,
		"version": json.Number(strconv.FormatInt(f.Version, 10)), "row_version": json.Number("1"),
		"copied_from_version": copied, "config_sha256": f.ConfigSHA256,
		"config_size_bytes": json.Number(strconv.FormatInt(f.ConfigSizeBytes, 10)),
		"created_by":        f.CreatedBy, "change_reason": reason,
		"created_at": f.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z"), "materialized": materialized,
	})
}

// The source issuer, immutable archive record ID/version and attestation hash
// must come from independent reviewed source authentication. They are NOT a
// signature or proof merely because this representation accepts their shape.
// AttestationSHA256 pins the exact authenticated archive manifest bytes that
// bind the original source and the full target/config tuple below.
type ConfigBackfillProvenanceFacts struct {
	TargetServerUUID, TargetDatabase, InstallationID string
	Version, ConfigSizeBytes                         int64
	ConfigSHA256, SourceIssuer, SourceID             string
	SourceVersion, AttestationSHA256                 string
}

func CanonicalConfigBackfillProvenance(f ConfigBackfillProvenanceFacts) ([]byte, string, error) {
	if !backfillIdentityTarget(f.TargetServerUUID, f.TargetDatabase, f.InstallationID, f.Version, f.ConfigSHA256, f.ConfigSizeBytes) ||
		!canonicalMaintenanceText(f.SourceIssuer, 2048) || !canonicalMaintenanceText(f.SourceID, 2048) ||
		!bootstrapVersion.MatchString(f.SourceVersion) || !providerHashPattern.MatchString(f.AttestationSHA256) {
		return nil, "", ErrConfigMutation
	}
	return backfillIdentityResult(map[string]any{
		"domain":             "clawmanager.system-backup.config-canonical-backfill-provenance.v1",
		"target_server_uuid": f.TargetServerUUID, "target_database": f.TargetDatabase,
		"origin_installation_id": f.InstallationID, "config_version": json.Number(strconv.FormatInt(f.Version, 10)),
		"original_config_sha256": f.ConfigSHA256, "original_config_size_bytes": json.Number(strconv.FormatInt(f.ConfigSizeBytes, 10)),
		"source_issuer": f.SourceIssuer, "source_id": f.SourceID, "source_version": f.SourceVersion,
		"attestation_sha256": f.AttestationSHA256,
	})
}

func backfillIdentityTarget(server, database, installation string, version int64, hash string, size int64) bool {
	return canonicalMaintenanceServer.MatchString(server) && canonicalMaintenanceDatabase.MatchString(database) &&
		configMutationInstallation.MatchString(installation) && version >= 1 && version <= 9007199254740991 &&
		providerHashPattern.MatchString(hash) && size >= 2 && size <= 262144
}

func backfillIdentityResult(fields map[string]any) ([]byte, string, error) {
	raw, digest := canonicalMaintenanceDigest(fields)
	return raw, digest, nil
}
