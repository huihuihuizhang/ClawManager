package systembackupresources

// Offline helpers for the revised resources proposal. No writer or production
// entry point calls these helpers. Validating values does not authenticate B/C
// facts, approve the proposal, or authorize restoring a row.

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

type restoreIDKind string

const (
	restoreUserID       restoreIDKind = "user"
	restoreInstanceID   restoreIDKind = "instance"
	restoreScanJobID    restoreIDKind = "scan_job"
	restoreSkillID      restoreIDKind = "skill"
	restoreScanResultID restoreIDKind = "skill_scan_result"
	restoreAuditID      restoreIDKind = "audit_log"
	restoreNBAuditID    restoreIDKind = "northbound_settings_audit"
)

type restoreIDBinding struct {
	Kind           restoreIDKind
	Source, Target int64
}

// The maps are privately copied and never returned. Their provenance and target
// occupancy still need B/C verification in the eventual write transaction.
type restoreIDMap struct {
	targets map[restoreIDKind]map[int64]int64
}

func validRestoreID(kind restoreIDKind, id int64) bool {
	if id <= 0 {
		return false
	}
	switch kind {
	case restoreNBAuditID:
		return true // This table uses signed BIGINT; the others use signed INT.
	case restoreUserID, restoreInstanceID, restoreScanJobID, restoreSkillID, restoreScanResultID, restoreAuditID:
		return id <= math.MaxInt32
	}
	return false
}

func newRestoreIDMap(bindings []restoreIDBinding) (*restoreIDMap, error) {
	result := &restoreIDMap{targets: make(map[restoreIDKind]map[int64]int64)}
	used := make(map[restoreIDKind]map[int64]bool)
	for _, binding := range bindings {
		if !validRestoreID(binding.Kind, binding.Source) || !validRestoreID(binding.Kind, binding.Target) {
			return nil, errors.New("invalid typed restore mapping")
		}
		if result.targets[binding.Kind] == nil {
			result.targets[binding.Kind] = make(map[int64]int64)
			used[binding.Kind] = make(map[int64]bool)
		}
		_, duplicate := result.targets[binding.Kind][binding.Source]
		if duplicate || used[binding.Kind][binding.Target] {
			return nil, errors.New("duplicate or merged restore mapping")
		}
		result.targets[binding.Kind][binding.Source] = binding.Target
		used[binding.Kind][binding.Target] = true
	}
	return result, nil
}

func (mapping *restoreIDMap) nullable(kind restoreIDKind, source *int64) (*int64, error) {
	if mapping == nil || mapping.targets == nil || !validRestoreID(kind, 1) {
		return nil, errors.New("typed restore mapping is required")
	}
	if source == nil {
		return nil, nil
	}
	if !validRestoreID(kind, *source) {
		return nil, errors.New("invalid restore reference")
	}
	target, ok := mapping.targets[kind][*source]
	if !ok {
		return nil, errors.New("restore reference mapping is missing")
	}
	return &target, nil
}

// The v2 proposal supports these exact audit resource types. An installation
// control reference cannot become a current target object, even with a mapping.
func (mapping *restoreIDMap) auditReference(resourceType string, source *int64) (*int64, error) {
	switch resourceType {
	case "user":
		return mapping.nullable(restoreUserID, source)
	case "instance":
		return mapping.nullable(restoreInstanceID, source)
	case "system_backup":
		if source == nil && mapping != nil && mapping.targets != nil {
			return nil, nil
		}
	}
	return nil, errors.New("unsupported historical audit reference")
}

// Both historical audit tables use explicit, separately authenticated target
// IDs. Existing target history (including this restore's audit) is never reused.
// B must repeat this check under the actual transaction's allocation/row locks.
func (mapping *restoreIDMap) validateHistoryTargets(kind restoreIDKind, occupied []int64) error {
	if mapping == nil || mapping.targets == nil || (kind != restoreAuditID && kind != restoreNBAuditID) {
		return errors.New("historical audit mapping is required")
	}
	used := make(map[int64]bool, len(mapping.targets[kind]))
	for _, target := range mapping.targets[kind] {
		used[target] = true
	}
	seen := make(map[int64]bool, len(occupied))
	for _, id := range occupied {
		if !validRestoreID(kind, id) || seen[id] || used[id] {
			return errors.New("invalid or occupied historical audit target")
		}
		seen[id] = true
	}
	return nil
}

func redactRestoreText(source *string) *string {
	if source == nil {
		return nil
	}
	value := "[REDACTED]"
	return &value
}

func redactRestoreJSON(source *string) *string {
	if source == nil {
		return nil
	}
	value := `"[REDACTED]"`
	return &value
}

// This computes a proposal only. Nil means B must prove the singleton absent;
// otherwise B must lock and compare the exact observed target version. The
// source version is deliberately not an input.
func nextRestoreNorthboundVersion(observed *int64) (int64, error) {
	if observed == nil {
		return 1, nil
	}
	if *observed < 1 || *observed == math.MaxInt64 {
		return 0, errors.New("invalid or exhausted northbound target version")
	}
	return *observed + 1, nil
}

// CPU columns are DECIMAL(4,2). Accept the exact SQL decimal representation,
// without exponent, float conversion, rounding or implicit defaults. Service
// bounds and the stricter target policy remain separate required checks.
func restoreCPUHundredths(raw string) (int64, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 2 || len(parts[1]) != 2 || (len(parts[0]) > 1 && parts[0][0] == '0') {
		return 0, errors.New("invalid CPU decimal")
	}
	for _, digit := range parts[0] + parts[1] {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid CPU decimal")
		}
	}
	value, err := strconv.ParseInt(parts[0]+parts[1], 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("invalid CPU decimal")
	}
	return value, nil
}

type restoreNetworkAllowance struct {
	Prefix netip.Prefix
	Port   int
}

// Link-local exceptions are excluded: they may contain metadata/control
// endpoints. A target policy must additionally deny all installation-specific
// control/provider ranges. A private address alone is never an allowance.
func privateRestorePrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return false
	}
	for _, root := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		block := netip.MustParsePrefix(root)
		if block.Addr().BitLen() == prefix.Addr().BitLen() && prefix.Bits() >= block.Bits() && block.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func validateRestoreNetwork(raw string, port int, allowed []restoreNetworkAllowance, denied []netip.Prefix) error {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !privateRestorePrefix(prefix) || port < 1 || port > 65535 || len(allowed) == 0 {
		return errors.New("invalid restore network exception")
	}
	matched := false
	for _, rule := range allowed {
		if !privateRestorePrefix(rule.Prefix) || rule.Port < 1 || rule.Port > 65535 {
			return errors.New("invalid target network allowance")
		}
		if rule.Port == port && rule.Prefix.Addr().BitLen() == prefix.Addr().BitLen() && prefix.Bits() >= rule.Prefix.Bits() && rule.Prefix.Contains(prefix.Addr()) {
			matched = true
		}
	}
	for _, block := range denied {
		if !block.IsValid() || block != block.Masked() || block.Addr().Is4In6() || block.Addr().Zone() != "" {
			return errors.New("invalid target network exclusion")
		}
		if block.Overlaps(prefix) {
			return errors.New("restore network overlaps a target exclusion")
		}
	}
	if !matched {
		return errors.New("restore network is outside target allowances")
	}
	return nil
}

type restoreScanScope struct {
	ScanScope string `json:"scan_scope"`
	AssetID   *int64 `json:"asset_id,omitempty"`
}

// Unlike the runtime's permissive parser, missing/NULL/malformed scope is not
// replaced with incremental. C still has to review this exact closed shape and
// authenticate each skill mapping and its result/version association.
func parseRestoreScanScope(raw string, mapping *restoreIDMap) (restoreScanScope, error) {
	invalid := errors.New("invalid restore scan scope")
	if len(raw) > 4096 || !utf8.ValidString(raw) {
		return restoreScanScope{}, invalid
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return restoreScanScope{}, invalid
	}
	seen := make(map[string]bool)
	result := restoreScanScope{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return restoreScanScope{}, invalid
		}
		seen[key] = true
		switch key {
		case "scan_scope":
			if decoder.Decode(&result.ScanScope) != nil || (result.ScanScope != "full" && result.ScanScope != "incremental") {
				return restoreScanScope{}, invalid
			}
		case "asset_id":
			var id int64
			var value json.RawMessage
			if decoder.Decode(&value) != nil || string(value) == "null" || json.Unmarshal(value, &id) != nil || !validRestoreID(restoreSkillID, id) {
				return restoreScanScope{}, invalid
			}
			result.AssetID, err = mapping.nullable(restoreSkillID, &id)
			if err != nil {
				return restoreScanScope{}, invalid
			}
		default:
			return restoreScanScope{}, invalid
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || !seen["scan_scope"] {
		return restoreScanScope{}, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return restoreScanScope{}, invalid
	}
	return result, nil
}
