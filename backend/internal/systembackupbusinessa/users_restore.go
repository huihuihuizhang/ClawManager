package systembackupbusinessa

import (
	"errors"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"clawreef/internal/models"
)

// UserRestoreSource is the non-credential projection of one authenticated
// source row. Dump readers must never put password_hash or directory identity
// material into this type.
type UserRestoreSource struct {
	ID        int
	Username  string
	Email     string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserRestoreMapping is an independently approved identity mapping for an
// isolated target. Its provenance and target uniqueness are checked by the
// restore coordinator before any SQL write.
type UserRestoreMapping struct {
	SourceID       int
	TargetID       int
	TargetUsername string
	TargetEmail    string
}

const DisabledUserPasswordHash = "!system-backup-password-reset-required!"

var ErrUserRestoreMapping = errors.New("A user restore identity mapping invalid")

// UserRestoreBatch keeps the source-to-target identity map private so callers
// cannot change it after normalization. SQL collation conflicts and target
// occupancy must still be checked by the isolated target writer.
type UserRestoreBatch struct {
	rows           []models.User
	targetBySource map[int]int
}

func (b *UserRestoreBatch) Rows() []models.User {
	if b == nil {
		return nil
	}
	return append([]models.User(nil), b.rows...)
}

func (b *UserRestoreBatch) TargetID(sourceID int) (int, bool) {
	if b == nil {
		return 0, false
	}
	id, ok := b.targetBySource[sourceID]
	return id, ok
}

// NormalizeUsersForRestore requires one mapping per source row and returns no
// partial batch. The deterministic target-ID order feeds dependent tables.
func NormalizeUsersForRestore(sources []UserRestoreSource, mappings []UserRestoreMapping) (*UserRestoreBatch, error) {
	if len(sources) != len(mappings) {
		return nil, ErrUserRestoreMapping
	}
	bySource := make(map[int]UserRestoreMapping, len(mappings))
	targets := make(map[int]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 {
			return nil, ErrUserRestoreMapping
		}
		if _, exists := bySource[mapping.SourceID]; exists {
			return nil, ErrUserRestoreMapping
		}
		if _, exists := targets[mapping.TargetID]; exists {
			return nil, ErrUserRestoreMapping
		}
		bySource[mapping.SourceID] = mapping
		targets[mapping.TargetID] = struct{}{}
	}
	batch := &UserRestoreBatch{rows: make([]models.User, 0, len(sources)), targetBySource: make(map[int]int, len(sources))}
	for _, source := range sources {
		if _, exists := batch.targetBySource[source.ID]; exists {
			return nil, ErrUserRestoreMapping
		}
		mapping, exists := bySource[source.ID]
		if !exists {
			return nil, ErrUserRestoreMapping
		}
		row, err := NormalizeUserForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		batch.rows = append(batch.rows, row)
		batch.targetBySource[source.ID] = mapping.TargetID
	}
	sort.Slice(batch.rows, func(i, j int) bool { return batch.rows[i].ID < batch.rows[j].ID })
	return batch, nil
}

// NormalizeUserForRestore constructs the complete writable users row. It
// never transfers local passwords, LDAP bindings, login aliases or last-login
// state. The target account remains disabled until a separate enrollment.
// This pure transformation does not certify a dump or authorize a SQL write.
func NormalizeUserForRestore(source UserRestoreSource, mapping UserRestoreMapping) (models.User, error) {
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.Username, 255) || !validUserRestoreText(source.Email, 320) ||
		!validUserRestoreText(mapping.TargetUsername, 255) || !validUserRestoreText(mapping.TargetEmail, 320) ||
		(source.Role != "admin" && source.Role != "user") ||
		source.CreatedAt.IsZero() || source.UpdatedAt.IsZero() || source.UpdatedAt.Before(source.CreatedAt) {
		return models.User{}, ErrUserRestoreMapping
	}
	return models.User{
		ID:           mapping.TargetID,
		Username:     mapping.TargetUsername,
		Email:        mapping.TargetEmail,
		PasswordHash: DisabledUserPasswordHash,
		Role:         source.Role,
		AuthProvider: "local",
		IsActive:     false,
		CreatedAt:    source.CreatedAt,
		UpdatedAt:    source.UpdatedAt,
	}, nil
}

func validUserRestoreText(value string, maxRunes int) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
