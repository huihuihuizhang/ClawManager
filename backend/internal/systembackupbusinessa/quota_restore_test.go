package systembackupbusinessa

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestNormalizeUserQuotasForRestoreUsesUserMappingAndExactCapacity(t *testing.T) {
	when := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	users, err := NormalizeUsersForRestore([]UserRestoreSource{
		{ID: 7, Username: "seven", Email: "seven@example.invalid", Role: "user", CreatedAt: when, UpdatedAt: when},
		{ID: 8, Username: "eight", Email: "eight@example.invalid", Role: "user", CreatedAt: when, UpdatedAt: when},
	}, []UserRestoreMapping{
		{SourceID: 7, TargetID: 107, TargetUsername: "target-seven", TargetEmail: "target-seven@example.invalid"},
		{SourceID: 8, TargetID: 108, TargetUsername: "target-eight", TargetEmail: "target-eight@example.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := []UserQuotaRestoreSource{
		{ID: 12, UserID: 8, MaxInstances: quotaInt(2), MaxCPUCores: "40", MaxMemoryGB: quotaInt(20), MaxStorageGB: quotaInt(30), MaxGPUCount: quotaInt(0), CreatedAt: when, UpdatedAt: when},
		{ID: 11, UserID: 7, MaxInstances: quotaInt(1), MaxCPUCores: "1.2", MaxMemoryGB: quotaInt(10), MaxStorageGB: quotaInt(20), MaxGPUCount: quotaInt(1), CreatedAt: when, UpdatedAt: when},
	}
	mappings := []UserQuotaRestoreMapping{{SourceID: 11, TargetID: 211}, {SourceID: 12, TargetID: 212}}
	capacities := map[int]UserQuotaCapacity{
		107: {MaxInstances: 1, MaxCPUCores: "1.20", MaxMemoryGB: 10, MaxStorageGB: 20, MaxGPUCount: 1},
		108: {MaxInstances: 3, MaxCPUCores: "40.00", MaxMemoryGB: 30, MaxStorageGB: 40, MaxGPUCount: 0},
	}
	rows, err := NormalizeUserQuotasForRestore(users, sources, mappings, capacities)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != 211 || rows[0].UserID != 107 || rows[0].MaxCPUCores != "1.20" ||
		rows[1].ID != 212 || rows[1].UserID != 108 || rows[1].MaxCPUCores != "40.00" {
		t.Fatalf("quota normalization lost mapping or decimal precision: %+v", rows)
	}
	for name, modify := range map[string]func(*[]UserQuotaRestoreSource, *[]UserQuotaRestoreMapping, map[int]UserQuotaCapacity){
		"missing quota mapping": func(_ *[]UserQuotaRestoreSource, m *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			*m = (*m)[:1]
		},
		"duplicate quota ID": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].ID = 12
		},
		"duplicate target ID": func(_ *[]UserQuotaRestoreSource, m *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*m)[1].TargetID = 211
		},
		"target ID overflow": func(_ *[]UserQuotaRestoreSource, m *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*m)[1].TargetID = math.MaxInt32 + 1
		},
		"unknown user": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].UserID = 9
		},
		"duplicate user quota": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].UserID = 8
		},
		"missing capacity": func(_ *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, c map[int]UserQuotaCapacity) {
			delete(c, 107)
		},
		"CPU exceeds capacity": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].MaxCPUCores = "1.21"
		},
		"memory exceeds cap": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].MaxMemoryGB = quotaInt(11)
		},
		"negative quota": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].MaxInstances = quotaInt(-1)
		},
		"SQL NULL quota": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].MaxInstances = nil
		},
		"invalid CPU decimal": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].MaxCPUCores = "1.234"
		},
		"invalid cap decimal": func(_ *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, c map[int]UserQuotaCapacity) {
			v := c[107]
			v.MaxCPUCores = "01.20"
			c[107] = v
		},
		"invalid time": func(s *[]UserQuotaRestoreSource, _ *[]UserQuotaRestoreMapping, _ map[int]UserQuotaCapacity) {
			(*s)[1].CreatedAt = time.Time{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			copySources := append([]UserQuotaRestoreSource(nil), sources...)
			copyMappings := append([]UserQuotaRestoreMapping(nil), mappings...)
			copyCapacities := make(map[int]UserQuotaCapacity, len(capacities))
			for id, capacity := range capacities {
				copyCapacities[id] = capacity
			}
			modify(&copySources, &copyMappings, copyCapacities)
			got, err := NormalizeUserQuotasForRestore(users, copySources, copyMappings, copyCapacities)
			if !errors.Is(err, ErrUserQuotaRestore) || got != nil {
				t.Fatalf("invalid quota returned partial rows: %+v, %v", got, err)
			}
		})
	}
}

func quotaInt(value int) *int { return &value }
