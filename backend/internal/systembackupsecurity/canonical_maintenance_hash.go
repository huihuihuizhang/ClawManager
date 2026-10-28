package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

const ConfigMaintenanceDigestProfile = "a-config-canonical-maintenance-digests.v1"

var canonicalMaintenanceServer = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var canonicalMaintenanceDatabase = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func canonicalMaintenanceText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) != ""
}

func canonicalMaintenanceDigest(input map[string]any) ([]byte, string) {
	var out strings.Builder
	canonicalMutationJSON(&out, input)
	raw := []byte(out.String())
	return raw, registrationHash(out.String())
}

// ConfigMaintenanceActorSHA256 identifies an independently authenticated stable
// issuer/principal. It is not authentication or a grant. Never substitute a
// rotating key/certificate/session/role ID for either stable identity.
func ConfigMaintenanceActorSHA256(issuer, subject string) (string, error) {
	if !canonicalMaintenanceText(issuer, 2048) || !canonicalMaintenanceText(subject, 256) {
		return "", ErrConfigMutation
	}
	_, digest := canonicalMaintenanceDigest(map[string]any{"domain": "clawmanager.system-backup.config-canonical-maintenance-actor.v1", "issuer": issuer, "subject": subject})
	return digest, nil
}

// ConfigMaintenanceGrantIdentitySHA256 hashes a stable logical grant identity.
// Its immutable version belongs in the request hash, never in the actor/key
// namespace. This function verifies no grant signature, revocation or purpose.
func ConfigMaintenanceGrantIdentitySHA256(issuer, grantID string) (string, error) {
	if !canonicalMaintenanceText(issuer, 2048) || !bootstrapVersion.MatchString(grantID) {
		return "", ErrConfigMutation
	}
	_, digest := canonicalMaintenanceDigest(map[string]any{"domain": "clawmanager.system-backup.config-canonical-maintenance-grant.v1", "issuer": issuer, "grant_id": grantID})
	return digest, nil
}

// CanonicalConfigMaintenanceRequest implements the accepted closed v1 digest
// profile. It returns an owned JCS byte slice and its lowercase SHA-256. None of
// the supplied target/provenance/row/grant digests become trusted by parsing:
// the maintenance writer must authenticate and compare all of them separately.
// Idempotency key, request ID, proof and session are separate trusted bindings;
// adding them as body members is rejected rather than silently ignored.
func CanonicalConfigMaintenanceRequest(raw []byte) ([]byte, string, error) {
	fail := func() ([]byte, string, error) { return nil, "", ErrConfigMutation }
	if len(raw) < 2 || len(raw) > 262144 || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || len(fields) != 17 {
		return fail()
	}
	get := func(name string) string { value, _ := fields[name].(string); return value }
	if get("domain") != "clawmanager.system-backup.config-canonical-backfill-request.v1" || get("action") != "config_canonical_backfill" ||
		!canonicalMaintenanceServer.MatchString(get("target_server_uuid")) || !canonicalMaintenanceDatabase.MatchString(get("target_database")) ||
		!configMutationInstallation.MatchString(get("origin_installation_id")) || !bootstrapVersion.MatchString(get("grant_version")) || !canonicalMaintenanceText(get("reason"), 512) {
		return fail()
	}
	for _, name := range []string{"maintenance_actor_sha256", "grant_identity_sha256", "original_config_sha256", "expected_row_sha256", "source_provenance_sha256", "schema_sha256", "catalog_sha256", "migration_sha256"} {
		if !providerHashPattern.MatchString(get(name)) {
			return fail()
		}
	}
	for _, bound := range []struct {
		name     string
		min, max int64
	}{{"config_version", 1, 9007199254740991}, {"original_config_size_bytes", 2, 262144}} {
		number, ok := fields[bound.name].(json.Number)
		if !ok {
			return fail()
		}
		value, valid := bootstrapNumber(number, bootstrapNumberRule{Min: bound.min, Max: bound.max, Scale: 1})
		if !valid {
			return fail()
		}
		fields[bound.name] = json.Number(fieldsVersion(value))
	}
	canonical, digest := canonicalMaintenanceDigest(fields)
	return canonical, digest, nil
}
