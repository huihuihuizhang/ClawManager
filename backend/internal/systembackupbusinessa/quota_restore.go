package systembackupbusinessa

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CPU quantities use exact hundredths because migration 009 stores quotas in
// DECIMAL(10,2). A float64 cannot be a restore or capacity comparison input.
type UserQuotaRestoreSource struct {
	ID           int
	UserID       int
	MaxInstances *int
	MaxCPUCores  string
	MaxMemoryGB  *int
	MaxStorageGB *int
	MaxGPUCount  *int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserQuotaRestoreMapping struct {
	SourceID int
	TargetID int
}

// UserQuotaCapacity must come from independently verified target policy, not
// from the source dump or a task request.
type UserQuotaCapacity struct {
	MaxInstances int
	MaxCPUCores  string
	MaxMemoryGB  int
	MaxStorageGB int
	MaxGPUCount  int
}

// NormalizedUserQuota has only columns writable on the isolated target. CPU
// remains a canonical decimal string for a parameterized SQL DECIMAL value.
type NormalizedUserQuota struct {
	ID           int
	UserID       int
	MaxInstances int
	MaxCPUCores  string
	MaxMemoryGB  int
	MaxStorageGB int
	MaxGPUCount  int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

var ErrUserQuotaRestore = errors.New("A user quota restore normalization failed")

// NormalizeUserQuotasForRestore requires an exact quota ID mapping, an
// existing normalized user and a target capacity for every quota. A source
// quota above target capacity fails; it is never silently increased or cut.
// The target writer must still verify target identity, SQL uniqueness and
// restore-write authority before inserting any row.
func NormalizeUserQuotasForRestore(users *UserRestoreBatch, sources []UserQuotaRestoreSource,
	mappings []UserQuotaRestoreMapping, capacities map[int]UserQuotaCapacity) ([]NormalizedUserQuota, error) {
	if users == nil || len(sources) != len(mappings) {
		return nil, ErrUserQuotaRestore
	}
	bySource := make(map[int]UserQuotaRestoreMapping, len(mappings))
	targetIDs := make(map[int]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 {
			return nil, ErrUserQuotaRestore
		}
		if _, exists := bySource[mapping.SourceID]; exists {
			return nil, ErrUserQuotaRestore
		}
		if _, exists := targetIDs[mapping.TargetID]; exists {
			return nil, ErrUserQuotaRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	result := make([]NormalizedUserQuota, 0, len(sources))
	sourceIDs := make(map[int]struct{}, len(sources))
	sourceUsers := make(map[int]struct{}, len(sources))
	for _, source := range sources {
		mapping, exists := bySource[source.ID]
		if !exists || source.ID <= 0 || source.ID > math.MaxInt32 || source.UserID <= 0 ||
			source.CreatedAt.IsZero() || source.UpdatedAt.IsZero() || source.UpdatedAt.Before(source.CreatedAt) {
			return nil, ErrUserQuotaRestore
		}
		if _, duplicate := sourceIDs[source.ID]; duplicate {
			return nil, ErrUserQuotaRestore
		}
		sourceIDs[source.ID] = struct{}{}
		if _, duplicate := sourceUsers[source.UserID]; duplicate {
			return nil, ErrUserQuotaRestore
		}
		sourceUsers[source.UserID] = struct{}{}
		targetUserID, exists := users.TargetID(source.UserID)
		if !exists {
			return nil, ErrUserQuotaRestore
		}
		capacity, exists := capacities[targetUserID]
		if !exists || !quotaWithinCapacity(source, capacity) {
			return nil, ErrUserQuotaRestore
		}
		_, canonicalCPU, _ := quotaCPUCents(source.MaxCPUCores)
		result = append(result, NormalizedUserQuota{
			ID: mapping.TargetID, UserID: targetUserID,
			MaxInstances: *source.MaxInstances, MaxCPUCores: canonicalCPU,
			MaxMemoryGB: *source.MaxMemoryGB, MaxStorageGB: *source.MaxStorageGB,
			MaxGPUCount: *source.MaxGPUCount, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func quotaWithinCapacity(source UserQuotaRestoreSource, cap UserQuotaCapacity) bool {
	if source.MaxInstances == nil || source.MaxMemoryGB == nil || source.MaxStorageGB == nil || source.MaxGPUCount == nil {
		return false
	}
	sourceCPU, _, sourceOK := quotaCPUCents(source.MaxCPUCores)
	capCPU, _, capOK := quotaCPUCents(cap.MaxCPUCores)
	return sourceOK && capOK && sourceCPU <= capCPU &&
		validQuotaInt(*source.MaxInstances, cap.MaxInstances) &&
		validQuotaInt(*source.MaxMemoryGB, cap.MaxMemoryGB) &&
		validQuotaInt(*source.MaxStorageGB, cap.MaxStorageGB) &&
		validQuotaInt(*source.MaxGPUCount, cap.MaxGPUCount)
}

func validQuotaInt(value, capacity int) bool {
	return value >= 0 && capacity >= 0 && value <= math.MaxInt32 && capacity <= math.MaxInt32 && value <= capacity
}

func quotaCPUCents(raw string) (int64, string, bool) {
	whole, fractional, hasPoint := strings.Cut(raw, ".")
	if whole == "" || len(whole) > 8 || (len(whole) > 1 && whole[0] == '0') ||
		(hasPoint && (len(fractional) < 1 || len(fractional) > 2)) {
		return 0, "", false
	}
	for _, part := range []string{whole, fractional} {
		for _, char := range part {
			if char < '0' || char > '9' {
				return 0, "", false
			}
		}
	}
	integer, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, "", false
	}
	if len(fractional) == 1 {
		fractional += "0"
	} else if len(fractional) == 0 {
		fractional = "00"
	}
	fraction, err := strconv.ParseInt(fractional, 10, 64)
	if err != nil {
		return 0, "", false
	}
	return integer*100 + fraction, whole + "." + fractional, true
}
