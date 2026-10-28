package systembackupbusinessa

import (
	"errors"
	"sort"
	"strings"
	"time"

	"clawreef/internal/models"
)

// NorthboundChallengeRestoreSource is the SQL projection needed to restore a
// historical challenge. The original source IP and used_at are deliberately
// omitted: both are replaced before the row can reach the isolated target.
// The nonce hash is retained as the v12 object policy requires, but the
// challenge is expired and consumed before any target write is permitted.
type NorthboundChallengeRestoreSource struct {
	ID          int64
	ChallengeID string
	NonceHash   string
	KeyID       string
	Status      string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NorthboundChallengeRestoreMapping is an independently approved target row
// identity. B must still prove target occupancy and MySQL collation uniqueness.
type NorthboundChallengeRestoreMapping struct {
	SourceID          int64
	TargetID          int64
	TargetChallengeID string
}

var ErrNorthboundChallengeRestore = errors.New("A northbound challenge restore normalization failed")

// NormalizeNorthboundChallengesForRestore rejects an incomplete or ambiguous
// mapping and returns no partial rows. targetNow must be an authenticated UTC
// target-database time supplied by B; this pure function cannot prove its
// origin. Every returned challenge is expired and marked used before that time.
func NormalizeNorthboundChallengesForRestore(sources []NorthboundChallengeRestoreSource,
	mappings []NorthboundChallengeRestoreMapping, targetNow time.Time) ([]models.NorthboundAuthChallenge, error) {
	if len(sources) != len(mappings) || !validMySQLDateTime(targetNow.UTC().Truncate(time.Microsecond).Add(-time.Microsecond)) {
		return nil, ErrNorthboundChallengeRestore
	}
	bySource := make(map[int64]NorthboundChallengeRestoreMapping, len(mappings))
	targetIDs := make(map[int64]struct{}, len(mappings))
	targetNames := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.TargetID <= 0 || !validUserRestoreText(mapping.TargetChallengeID, 64) {
			return nil, ErrNorthboundChallengeRestore
		}
		name := strings.ToLower(mapping.TargetChallengeID)
		if _, exists := bySource[mapping.SourceID]; exists {
			return nil, ErrNorthboundChallengeRestore
		}
		if _, exists := targetIDs[mapping.TargetID]; exists {
			return nil, ErrNorthboundChallengeRestore
		}
		if _, exists := targetNames[name]; exists {
			return nil, ErrNorthboundChallengeRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
		targetNames[name] = struct{}{}
	}
	rows := make([]models.NorthboundAuthChallenge, 0, len(sources))
	sourceIDs := make(map[int64]struct{}, len(sources))
	sourceNames := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if _, exists := sourceIDs[source.ID]; exists {
			return nil, ErrNorthboundChallengeRestore
		}
		name := strings.ToLower(source.ChallengeID)
		if _, exists := sourceNames[name]; exists {
			return nil, ErrNorthboundChallengeRestore
		}
		mapping, exists := bySource[source.ID]
		if !exists {
			return nil, ErrNorthboundChallengeRestore
		}
		row, err := NormalizeNorthboundChallengeForRestore(source, mapping, targetNow)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
		sourceIDs[source.ID] = struct{}{}
		sourceNames[name] = struct{}{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows, nil
}

// NormalizeNorthboundChallengeForRestore produces the complete writable row
// for northbound_auth_challenges. It never returns an issued or unconsumed
// challenge. It does not authenticate a dump, authorize SQL, or certify that
// the target time and mapping came from B's isolated restore environment.
func NormalizeNorthboundChallengeForRestore(source NorthboundChallengeRestoreSource,
	mapping NorthboundChallengeRestoreMapping, targetNow time.Time) (models.NorthboundAuthChallenge, error) {
	created := source.CreatedAt.UTC().Truncate(time.Microsecond)
	updated := source.UpdatedAt.UTC().Truncate(time.Microsecond)
	cutoff := targetNow.UTC().Truncate(time.Microsecond).Add(-time.Microsecond)
	if source.ID <= 0 || mapping.SourceID != source.ID || mapping.TargetID <= 0 ||
		!validUserRestoreText(source.ChallengeID, 64) || !validUserRestoreText(mapping.TargetChallengeID, 64) ||
		!validUserRestoreText(source.KeyID, 128) || !lowerHexSHA256(source.NonceHash) ||
		(source.Status != "issued" && source.Status != "processing" && source.Status != "consumed" && source.Status != "expired") ||
		!validMySQLDateTime(created) || !validMySQLDateTime(updated) || !validMySQLDateTime(source.ExpiresAt.UTC()) ||
		!validMySQLDateTime(cutoff) || updated.Before(created) || cutoff.Before(updated) {
		return models.NorthboundAuthChallenge{}, ErrNorthboundChallengeRestore
	}
	return models.NorthboundAuthChallenge{
		ID: mapping.TargetID, ChallengeID: mapping.TargetChallengeID,
		NonceHash: source.NonceHash, KeyID: source.KeyID, Status: "expired",
		ExpiresAt: cutoff, UsedAt: &cutoff, CreatedAt: created, UpdatedAt: cutoff,
	}, nil
}

func lowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validMySQLDateTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1000 && value.Year() <= 9999
}
