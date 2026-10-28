package systembackupbusinessa

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"clawreef/internal/models"
)

// NorthboundSessionRestoreSource contains the SQL columns that are retained
// as historical data. The source token hashes are never treated as active
// credentials by this normalizer; B must keep the authenticated dump sealed.
type NorthboundSessionRestoreSource struct {
	ID                       int64
	SessionID                string
	UserID                   int
	RefreshTokenHash         string
	PreviousRefreshTokenHash *string
	RefreshTokenHistory      string
	ScopesJSON               string
	Status                   string
	AccessExpiresAt          time.Time
	RefreshExpiresAt         time.Time
	LastUsedAt               *time.Time
	LastIP                   *string
	UserAgent                *string
	CreatedAt                time.Time
	UpdatedAt                time.Time
	RevokedAt                *time.Time
}

type NorthboundSessionRestoreMapping struct {
	SourceID        int64
	TargetID        int64
	TargetSessionID string
}

var ErrNorthboundSessionRestore = errors.New("A northbound session restore normalization failed")

// These are the runtime scopes in northbound/types.go and the caller-policy
// allowlist. An added scope requires an explicit A restore-policy review before
// historical sessions or caller policies can carry it into an isolated target.
var northboundRestoreScopes = map[string]struct{}{
	"teams:read":              {},
	"teams:create":            {},
	"teams:manage":            {},
	"teams:delete":            {},
	"teams:tasks:read":        {},
	"teams:tasks:write":       {},
	"teams:files:read":        {},
	"teams:files:write":       {},
	"team-templates:read":     {},
	"team-templates:write":    {},
	"team-templates:generate": {},

	"lite-instances:create": {}, "lite-instances:read": {},
	"pro-instances:create": {}, "pro-instances:read": {},
	"lite-instances:restart": {}, "lite-instances:reset": {},
	"pro-instances:restart": {}, "pro-instances:reset": {},
	"lite-instances:share-link:manage": {}, "lite-instances:share-link:reset": {},
	// Preserve these permissions only as history: sessions are revoked and
	// caller policies are disabled by both restore normalizers.
	"lite-instances:delete": {}, "pro-instances:delete": {}, "owners:usage:read": {},
}

// NormalizeNorthboundSessionsForRestore closes the ID, session-ID and refresh
// hash mappings before returning any row. targetNow must come from B's
// authenticated target database clock; this pure function cannot certify it.
func NormalizeNorthboundSessionsForRestore(users *UserRestoreBatch,
	sources []NorthboundSessionRestoreSource, mappings []NorthboundSessionRestoreMapping,
	targetNow time.Time) ([]models.NorthboundSession, error) {
	if users == nil || len(sources) != len(mappings) ||
		!validMySQLDateTime(targetNow.UTC().Truncate(time.Microsecond).Add(-time.Microsecond)) {
		return nil, ErrNorthboundSessionRestore
	}
	bySource := make(map[int64]NorthboundSessionRestoreMapping, len(mappings))
	targetIDs := make(map[int64]struct{}, len(mappings))
	targetNames := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.TargetID <= 0 || !validUserRestoreText(mapping.TargetSessionID, 64) {
			return nil, ErrNorthboundSessionRestore
		}
		name := strings.ToLower(mapping.TargetSessionID)
		if _, exists := bySource[mapping.SourceID]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		if _, exists := targetIDs[mapping.TargetID]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		if _, exists := targetNames[name]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
		targetNames[name] = struct{}{}
	}
	rows := make([]models.NorthboundSession, 0, len(sources))
	sourceIDs := make(map[int64]struct{}, len(sources))
	sourceNames := make(map[string]struct{}, len(sources))
	refreshHashes := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if _, exists := sourceIDs[source.ID]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		name := strings.ToLower(source.SessionID)
		if _, exists := sourceNames[name]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		if _, exists := refreshHashes[source.RefreshTokenHash]; exists {
			return nil, ErrNorthboundSessionRestore
		}
		mapping, exists := bySource[source.ID]
		if !exists {
			return nil, ErrNorthboundSessionRestore
		}
		row, err := NormalizeNorthboundSessionForRestore(users, source, mapping, targetNow)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
		sourceIDs[source.ID] = struct{}{}
		sourceNames[name] = struct{}{}
		refreshHashes[source.RefreshTokenHash] = struct{}{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

// NormalizeNorthboundSessionForRestore produces all writable migration-045
// columns. The historical token hashes and scope JSON remain for accounting,
// while both token lifetimes and status are made unusable. A separate operator
// action would be needed to create a new, active target session.
func NormalizeNorthboundSessionForRestore(users *UserRestoreBatch,
	source NorthboundSessionRestoreSource, mapping NorthboundSessionRestoreMapping,
	targetNow time.Time) (models.NorthboundSession, error) {
	cutoff := targetNow.UTC().Truncate(time.Microsecond).Add(-time.Microsecond)
	created := source.CreatedAt.UTC().Truncate(time.Microsecond)
	updated := source.UpdatedAt.UTC().Truncate(time.Microsecond)
	if users == nil || source.ID <= 0 || source.UserID <= 0 ||
		mapping.SourceID != source.ID || mapping.TargetID <= 0 ||
		!validUserRestoreText(source.SessionID, 64) || !validUserRestoreText(mapping.TargetSessionID, 64) ||
		!lowerHexSHA256(source.RefreshTokenHash) ||
		(source.Status != "active" && source.Status != "revoked" && source.Status != "expired") ||
		!validMySQLDateTime(created) || !validMySQLDateTime(updated) ||
		!validMySQLDateTime(source.AccessExpiresAt.UTC()) || !validMySQLDateTime(source.RefreshExpiresAt.UTC()) ||
		!validMySQLDateTime(cutoff) || updated.Before(created) || cutoff.Before(updated) ||
		!validOptionalHash(source.PreviousRefreshTokenHash) ||
		!validOptionalRestoreText(source.LastIP, 64) || !validOptionalRestoreText(source.UserAgent, 512) ||
		!validOptionalSourceTime(source.LastUsedAt, created, cutoff) ||
		!validOptionalSourceTime(source.RevokedAt, created, cutoff) {
		return models.NorthboundSession{}, ErrNorthboundSessionRestore
	}
	targetUserID, exists := users.TargetID(source.UserID)
	if !exists {
		return models.NorthboundSession{}, ErrNorthboundSessionRestore
	}
	history, err := normalizedSessionHistory(source.RefreshTokenHistory, source.RefreshTokenHash)
	if err != nil {
		return models.NorthboundSession{}, ErrNorthboundSessionRestore
	}
	scopes, err := normalizedNorthboundScopes(source.ScopesJSON)
	if err != nil {
		return models.NorthboundSession{}, ErrNorthboundSessionRestore
	}
	return models.NorthboundSession{
		ID: mapping.TargetID, SessionID: mapping.TargetSessionID, UserID: targetUserID,
		RefreshTokenHash:         source.RefreshTokenHash,
		PreviousRefreshTokenHash: cloneString(source.PreviousRefreshTokenHash),
		RefreshTokenHistory:      history, ScopesJSON: scopes, Status: "revoked",
		AccessExpiresAt: cutoff, RefreshExpiresAt: cutoff,
		LastUsedAt: cloneTime(source.LastUsedAt), LastIP: cloneString(source.LastIP),
		UserAgent: cloneString(source.UserAgent), CreatedAt: created,
		UpdatedAt: cutoff, RevokedAt: &cutoff,
	}, nil
}

func normalizedSessionHistory(raw, currentHash string) (string, error) {
	if len(raw) > 1<<20 || strings.TrimSpace(raw) == "null" {
		return "", ErrNorthboundSessionRestore
	}
	var history []string
	if err := json.Unmarshal([]byte(raw), &history); err != nil || history == nil {
		return "", ErrNorthboundSessionRestore
	}
	seen := make(map[string]struct{}, len(history))
	for _, hash := range history {
		if !lowerHexSHA256(hash) || hash == currentHash {
			return "", ErrNorthboundSessionRestore
		}
		if _, duplicate := seen[hash]; duplicate {
			return "", ErrNorthboundSessionRestore
		}
		seen[hash] = struct{}{}
	}
	encoded, err := json.Marshal(history)
	return string(encoded), err
}

func normalizedNorthboundScopes(raw string) (string, error) {
	if len(raw) > 1<<16 || strings.TrimSpace(raw) == "null" {
		return "", ErrNorthboundSessionRestore
	}
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil || scopes == nil {
		return "", ErrNorthboundSessionRestore
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, known := northboundRestoreScopes[scope]; !known {
			return "", ErrNorthboundSessionRestore
		}
		if _, duplicate := seen[scope]; duplicate {
			return "", ErrNorthboundSessionRestore
		}
		seen[scope] = struct{}{}
	}
	encoded, err := json.Marshal(scopes)
	return string(encoded), err
}

func validOptionalHash(value *string) bool {
	return value == nil || lowerHexSHA256(*value)
}

func validOptionalRestoreText(value *string, max int) bool {
	return value == nil || validUserRestoreText(*value, max)
}

func validOptionalSourceTime(value *time.Time, created, cutoff time.Time) bool {
	return value == nil ||
		(validMySQLDateTime(value.UTC()) && !value.UTC().Before(created) && !value.UTC().After(cutoff))
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC().Truncate(time.Microsecond)
	return &copy
}
