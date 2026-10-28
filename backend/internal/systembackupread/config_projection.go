package systembackupread

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type configNumberBound struct{ min, max, scale int64 }

var configVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ConfigResourceDTO is the v12 redacted active configuration resource. The
// source bytes are exposed only after the entire closed ConfigValues shape
// and its semantic invariants have been verified.
type ConfigResourceDTO struct {
	SchemaVersion        string          `json:"schema_version"`
	OriginInstallationID string          `json:"origin_installation_id"`
	Version              uint64          `json:"version"`
	RowVersion           uint64          `json:"row_version"`
	Active               bool            `json:"active"`
	EffectiveEnabled     bool            `json:"effective_enabled"`
	Config               json.RawMessage `json:"config"`
	CreatedBy            string          `json:"created_by"`
	ChangeReason         *string         `json:"change_reason"`
	CreatedAt            string          `json:"created_at"`
}

func ProjectConfigResource(row ConfigSnapshot) (ConfigResourceDTO, error) {
	if !validConfigSnapshot(row, row.installationID, "system-backup-config.v1", int64(len(row.canonical))) {
		return ConfigResourceDTO{}, ErrUnavailable
	}
	enabled, ok := validConfigValues(row.canonical)
	if !ok || row.effective && !enabled {
		return ConfigResourceDTO{}, ErrUnavailable
	}
	var reason *string
	if row.changeReason.Valid {
		value := row.changeReason.String
		reason = &value
	}
	return ConfigResourceDTO{
		SchemaVersion: "system-backup-config.v1", OriginInstallationID: row.installationID,
		Version: row.version, RowVersion: row.rowVersion, Active: row.active,
		EffectiveEnabled: row.effective, Config: append(json.RawMessage(nil), row.canonical...),
		CreatedBy: row.createdBy, ChangeReason: reason,
		CreatedAt: row.createdAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *Service) ReadActiveConfigDTO(ctx context.Context) (ConfigResourceDTO, error) {
	if s == nil || s.reader == nil {
		return ConfigResourceDTO{}, ErrDenied
	}
	row, err := s.reader.ReadActiveConfig(ctx)
	if err != nil {
		return ConfigResourceDTO{}, err
	}
	return ProjectConfigResource(row)
}

func (s *Service) ReadConfigVersionDTO(ctx context.Context, version uint64) (ConfigResourceDTO, error) {
	if s == nil || s.reader == nil {
		return ConfigResourceDTO{}, ErrDenied
	}
	row, err := s.reader.ReadConfigVersion(ctx, version)
	if err != nil {
		return ConfigResourceDTO{}, err
	}
	return ProjectConfigResource(row)
}

func validConfigValues(raw []byte) (bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := configParseJSON(dec, 0)
	if err != nil {
		return false, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false, false
	}
	root, ok := configObject(value, "enabled", "alert_profile", "minimum_recovery_points", "durations", "capacity", "concurrency", "preflight_limits", "registries", "references")
	if !ok {
		return false, false
	}
	enabled, ok := root["enabled"].(bool)
	if !ok || root["alert_profile"] != "production" && root["alert_profile"] != "development" {
		return false, false
	}
	if _, ok := configBoundedNumber(root["minimum_recovery_points"], configNumberBound{1, 100, 1}); !ok {
		return false, false
	}
	numbers := map[string]int64{}
	for group, bounds := range configNumericBounds {
		members, ok := root[group].(map[string]any)
		if !ok || len(members) != len(bounds) {
			return false, false
		}
		for name, bound := range bounds {
			num, exists := members[name]
			if !exists {
				return false, false
			}
			scaled, valid := configBoundedNumber(num, bound)
			if !valid {
				return false, false
			}
			key := name
			if group == "preflight_limits" {
				key = "preflight_" + name
			}
			numbers[key] = scaled
		}
	}
	if !configRelationships(numbers) || !configReferences(root) {
		return false, false
	}
	return enabled, true
}

// Token parsing rejects duplicate names at every level. The depth bound is
// well above ConfigValues' shape and keeps malformed inputs from exhausting
// the parser before the closed-schema checks run.
func configParseJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, ErrInvalid
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	start, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch start {
	case '{':
		object := map[string]any{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrInvalid
			}
			if _, exists := object[key]; exists {
				return nil, ErrInvalid
			}
			value, err := configParseJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return object, nil
	case '[':
		var list []any
		for dec.More() {
			value, err := configParseJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return list, nil
	default:
		return nil, ErrInvalid
	}
}

func configObject(value any, keys ...string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return nil, false
		}
	}
	return object, true
}

func configBoundedNumber(value any, bound configNumberBound) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || len(number) == 0 || len(number) > 32 {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(string(number))
	if !ok {
		return 0, false
	}
	rational.Mul(rational, new(big.Rat).SetInt64(bound.scale))
	if !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, false
	}
	scaled := rational.Num().Int64()
	if scaled < bound.min || scaled > bound.max {
		return 0, false
	}
	canonical := strconv.FormatInt(scaled, 10)
	if bound.scale == 100 {
		whole := strconv.FormatInt(scaled/100, 10)
		fraction := scaled % 100
		canonical = whole
		if fraction != 0 {
			canonical += "." + strings.TrimRight(strconv.FormatInt(100+fraction, 10)[1:], "0")
		}
	}
	return scaled, string(number) == canonical
}

func configReferences(root map[string]any) bool {
	registries, ok := root["registries"].([]any)
	if !ok || len(registries) != len(configRegistryKinds) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range registries {
		item, ok := configObject(value, "registry_kind", "version", "sha256")
		if !ok {
			return false
		}
		kind, ok := item["registry_kind"].(string)
		if !ok || !configRegistryKinds[kind] || seen[kind] || !configReferenceFields(item, "sha256") {
			return false
		}
		seen[kind] = true
	}
	references, ok := root["references"].([]any)
	if !ok || len(references) != len(configReferencePurposes) {
		return false
	}
	seen = map[string]bool{}
	identities := map[string]string{}
	for _, value := range references {
		item, ok := configObject(value, "purpose", "identity_hash", "version")
		if !ok {
			return false
		}
		purpose, ok := item["purpose"].(string)
		if !ok || !configReferencePurposes[purpose] || seen[purpose] || !configReferenceFields(item, "identity_hash") {
			return false
		}
		identity := item["identity_hash"].(string)
		if prior, exists := identities[identity]; exists && (configSigningPurpose(prior) || configSigningPurpose(purpose)) {
			return false
		}
		seen[purpose] = true
		identities[identity] = purpose
	}
	return true
}

func configReferenceFields(item map[string]any, hashKey string) bool {
	version, ok := item["version"].(string)
	if !ok || !configVersion.MatchString(version) {
		return false
	}
	hash, ok := item[hashKey].(string)
	return ok && taskHash.MatchString(hash)
}

func configSigningPurpose(purpose string) bool {
	return purpose == "capture_signing" || purpose == "acceptance_signing" || purpose == "catalog_signing"
}

func configRelationships(n map[string]int64) bool {
	for _, prefix := range []string{"controller_claim", "mutation_lease", "artifact_lease"} {
		if n[prefix+"_heartbeat_seconds"]*3 > n[prefix+"_ttl_seconds"] {
			return false
		}
	}
	return n["maintenance_lock_ttl_seconds"] >= n["quiesce_max_hold_seconds"]+n["watchdog_safety_margin_seconds"]+2*n["controller_claim_ttl_seconds"] &&
		n["retry_max_backoff_seconds"] >= n["retry_initial_backoff_seconds"] &&
		n["evidence_retention_seconds"] >= n["retention_seconds"] &&
		n["control_metadata_retention_seconds"] >= n["retention_seconds"] &&
		n["control_metadata_retention_seconds"] >= n["evidence_retention_seconds"] &&
		n["control_metadata_retention_seconds"] >= n["logs_retention_seconds"] &&
		n["staging_capacity_bytes"]*10 >= n["max_artifact_bytes"]*11+n["max_index_bytes"]*10 &&
		n["log_chunk_bytes"] <= n["max_log_bytes"] && n["log_chunk_lines"] <= n["max_log_lines"] &&
		n["capture_certificate_ttl_seconds"] > n["backup_task_deadline_seconds"]
}
