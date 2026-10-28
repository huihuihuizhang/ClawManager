package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"clawreef/internal/models"
)

const (
	EnterpriseAuthBindInherited     = "inherited_env"
	EnterpriseAuthBindExplicitClear = "explicit_clear"
	EnterpriseAuthBindCiphertextRef = "ciphertext_ref"
)

// EnterpriseAuthRestoreSource is migration-050's complete non-secret row
// projection. B's dump reader classifies the original SQL NULL, empty and
// nonempty bind-password values without passing ciphertext into A's normalizer.
// SecretRefVersion is a redacted immutable version, never a credential or a
// self-authenticating proof.
type EnterpriseAuthRestoreSource struct {
	ID                     int
	Provider               string
	Enabled                bool
	AllowLocalFallback     bool
	SyncRole               bool
	LDAPHost               string
	LDAPPort               int
	LDAPUseTLS             bool
	LDAPStartTLS           bool
	LDAPSkipTLSVerify      bool
	LDAPTLSCAFile          string
	LDAPTLSServerName      string
	LDAPBindDN             string
	BindPasswordSourceKind string
	SecretRefVersion       string
	LDAPBaseDN             string
	LDAPUserFilter         string
	LDAPUsernameAttribute  string
	LDAPEmailAttribute     string
	LDAPGroupBaseDN        string
	LDAPGroupFilter        string
	LDAPAdminGroupDNs      *string
	LDAPDefaultRole        string
	Version                int64
	UpdatedBy              *int
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type EnterpriseAuthRestoreMapping struct {
	SourceID int
	TargetID int
}

// EnterpriseAuthSourceProofVerifier is B's authority over the exact source
// dump projection and typed Secret/ref. It must verify the source SQL password
// state, exact immutable Secret/ref version and registered dump evidence,
// including when the table is empty. A's caller-supplied version is not proof.
type EnterpriseAuthSourceProofVerifier interface {
	VerifyEnterpriseAuthSource(context.Context, string, string, string, []EnterpriseAuthRestoreSource) error
}

var ErrEnterpriseAuthRestore = errors.New("A enterprise auth restore normalization failed")

// NormalizeEnterpriseAuthSettingsForRestore produces complete migration-050
// target rows after B attests the redacted source projection. The only runtime
// provider is ldap, so any other or duplicate provider fails closed. B still
// owns target occupancy, SQL writes and the proof implementation.
func NormalizeEnterpriseAuthSettingsForRestore(ctx context.Context, scope *CaptureScope,
	users *UserRestoreBatch, sources []EnterpriseAuthRestoreSource,
	mappings []EnterpriseAuthRestoreMapping, evidenceRef string,
	proof EnterpriseAuthSourceProofVerifier) ([]models.EnterpriseAuthSetting, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || users == nil ||
		len(scope.tables) != len(tables) || !hashPattern.MatchString(scope.registrySHA) ||
		!hashPattern.MatchString(scope.schemaSHA) || !evidencePattern.MatchString(evidenceRef) ||
		len(sources) != len(mappings) || len(sources) > 1 {
		return nil, ErrEnterpriseAuthRestore
	}
	if nilEnterpriseAuthProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	// Freeze caller-owned pointer fields before constructing rows and before B
	// sees the projection. Both operations must refer to the same source values.
	projection := cloneEnterpriseAuthSources(sources)
	bySource := make(map[int]EnterpriseAuthRestoreMapping, len(mappings))
	targets := make(map[int]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 {
			return nil, ErrEnterpriseAuthRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrEnterpriseAuthRestore
		}
		if _, duplicate := targets[mapping.TargetID]; duplicate {
			return nil, ErrEnterpriseAuthRestore
		}
		bySource[mapping.SourceID] = mapping
		targets[mapping.TargetID] = struct{}{}
	}
	rows := make([]models.EnterpriseAuthSetting, 0, len(projection))
	seen := make(map[int]struct{}, len(projection))
	for _, source := range projection {
		if _, duplicate := seen[source.ID]; duplicate {
			return nil, ErrEnterpriseAuthRestore
		}
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrEnterpriseAuthRestore
		}
		row, err := NormalizeEnterpriseAuthSettingForRestore(users, source, mapping)
		if err != nil {
			return nil, err
		}
		seen[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	// Give B a copy so a proof implementation cannot mutate output through
	// source pointers. Proof failure never exposes partially normalized rows.
	proofSources := cloneEnterpriseAuthSources(projection)
	if err := proof.VerifyEnterpriseAuthSource(ctx, scope.registrySHA, scope.schemaSHA, evidenceRef, proofSources); err != nil {
		return nil, fmt.Errorf("A enterprise auth source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func cloneEnterpriseAuthSources(sources []EnterpriseAuthRestoreSource) []EnterpriseAuthRestoreSource {
	result := append([]EnterpriseAuthRestoreSource(nil), sources...)
	for i := range result {
		if result[i].LDAPAdminGroupDNs != nil {
			value := *result[i].LDAPAdminGroupDNs
			result[i].LDAPAdminGroupDNs = &value
		}
		if result[i].UpdatedBy != nil {
			value := *result[i].UpdatedBy
			result[i].UpdatedBy = &value
		}
	}
	return result
}

// NormalizeEnterpriseAuthSettingForRestore is a pure complete-row transform.
// It does not authenticate the source projection or authorize target writes;
// callers needing a restore-ready batch use the proof-gated batch entry above.
func NormalizeEnterpriseAuthSettingForRestore(users *UserRestoreBatch,
	source EnterpriseAuthRestoreSource, mapping EnterpriseAuthRestoreMapping) (models.EnterpriseAuthSetting, error) {
	created := source.CreatedAt.UTC().Truncate(time.Microsecond)
	updated := source.UpdatedAt.UTC().Truncate(time.Microsecond)
	if users == nil || source.ID <= 0 || source.ID > math.MaxInt32 ||
		mapping.SourceID != source.ID || mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		source.Provider != "ldap" || source.Version < 1 || source.LDAPPort < 1 || source.LDAPPort > 65535 ||
		!validMySQLDateTime(created) || !validMySQLDateTime(updated) || updated.Before(created) ||
		!validEnterpriseAuthText(source.LDAPHost, 255) ||
		!validEnterpriseAuthText(source.LDAPTLSCAFile, 1000) ||
		!validEnterpriseAuthText(source.LDAPTLSServerName, 255) ||
		!validEnterpriseAuthText(source.LDAPBindDN, 500) ||
		!validEnterpriseAuthText(source.LDAPBaseDN, 500) ||
		!validEnterpriseAuthText(source.LDAPUserFilter, 1000) ||
		!validEnterpriseAuthText(source.LDAPUsernameAttribute, 100) ||
		!validEnterpriseAuthText(source.LDAPEmailAttribute, 100) ||
		!validEnterpriseAuthText(source.LDAPGroupBaseDN, 500) ||
		!validEnterpriseAuthText(source.LDAPGroupFilter, 1000) ||
		(source.LDAPDefaultRole != "admin" && source.LDAPDefaultRole != "user") ||
		!validEnterpriseAuthBindSource(source.BindPasswordSourceKind, source.SecretRefVersion) ||
		(source.LDAPAdminGroupDNs != nil && (len(*source.LDAPAdminGroupDNs) > 65535 ||
			!validEnterpriseAuthText(*source.LDAPAdminGroupDNs, 65535))) {
		return models.EnterpriseAuthSetting{}, ErrEnterpriseAuthRestore
	}
	var targetUpdatedBy *int
	if source.UpdatedBy != nil {
		if *source.UpdatedBy <= 0 {
			return models.EnterpriseAuthSetting{}, ErrEnterpriseAuthRestore
		}
		actor, found := users.TargetID(*source.UpdatedBy)
		if !found {
			return models.EnterpriseAuthSetting{}, ErrEnterpriseAuthRestore
		}
		targetUpdatedBy = &actor
	}
	var groupDNs *string
	if source.LDAPAdminGroupDNs != nil {
		value := *source.LDAPAdminGroupDNs
		groupDNs = &value
	}
	// SQL NULL inherits LDAP_BIND_PASSWORD from the target environment.
	// A non-nil empty value is the production runtime's explicit clear marker.
	cleared := ""
	return models.EnterpriseAuthSetting{
		ID: mapping.TargetID, Provider: source.Provider, Enabled: false,
		AllowLocalFallback: source.AllowLocalFallback, SyncRole: source.SyncRole,
		LDAPHost: source.LDAPHost, LDAPPort: source.LDAPPort,
		LDAPUseTLS: source.LDAPUseTLS, LDAPStartTLS: source.LDAPStartTLS,
		LDAPSkipTLSVerify: source.LDAPSkipTLSVerify,
		LDAPTLSCAFile:     source.LDAPTLSCAFile, LDAPTLSServerName: source.LDAPTLSServerName,
		LDAPBindDN: source.LDAPBindDN, LDAPBindPasswordCiphertext: &cleared,
		LDAPBaseDN: source.LDAPBaseDN, LDAPUserFilter: source.LDAPUserFilter,
		LDAPUsernameAttribute: source.LDAPUsernameAttribute,
		LDAPEmailAttribute:    source.LDAPEmailAttribute,
		LDAPGroupBaseDN:       source.LDAPGroupBaseDN, LDAPGroupFilter: source.LDAPGroupFilter,
		LDAPAdminGroupDNs: groupDNs, LDAPDefaultRole: source.LDAPDefaultRole,
		Version: source.Version, UpdatedBy: targetUpdatedBy,
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func validEnterpriseAuthText(value string, maxRunes int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxRunes && !strings.ContainsRune(value, '\x00')
}

func validEnterpriseAuthBindSource(kind, version string) bool {
	switch kind {
	case EnterpriseAuthBindInherited, EnterpriseAuthBindExplicitClear:
		return version == ""
	case EnterpriseAuthBindCiphertextRef:
		if version == "" || len(version) > 128 || version == "latest" || version == "current" || version == "default" {
			return false
		}
		for _, char := range version {
			if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
				char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-') {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func nilEnterpriseAuthProof(proof EnterpriseAuthSourceProofVerifier) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
