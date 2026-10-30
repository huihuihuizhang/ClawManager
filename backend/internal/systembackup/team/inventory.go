package team

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const InventoryVersion = "teams-source-inventory.v1"

var ErrInventory = errors.New("teams source inventory incomplete or inconsistent")
var inventoryID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)
var digest64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var redisServer = regexp.MustCompile(`^[a-f0-9]{40}$`)

// This is a credential-free projection of the original SQL snapshot and D's
// independently authenticated storage/provider mapping, never user input.
type Inventory struct {
	SchemaSHA256 string        `json:"schema_sha256"`
	Version      string        `json:"version"`
	Teams        []SourceTeam  `json:"teams"`
	Mounts       []SharedMount `json:"mounts"`
	Redis        []RedisScope  `json:"redis"`
	Objects      []ObjectRef   `json:"objects"`
}
type SourceTeam struct {
	ID, UserID                   int
	ResourceScope, Owner, Status string
	SharedMountID, RedisScopeID  string
	Members                      []SourceMember
}
type SourceMember struct{ ID, InstanceID int }
type SharedMount struct {
	ID                        string
	TeamID                    int
	Namespace, PVC, UID, Root string
}
type RedisScope struct {
	ID       string
	ServerID string
	Database int
	TeamIDs  []int
}
type ObjectRef struct {
	TeamID                       int
	Bucket, Key, Version, SHA256 string
	Size                         int64
}

func (r RedisScope) Validate() error {
	if !inventoryID.MatchString(r.ID) || !redisServer.MatchString(r.ServerID) || r.Database < 0 || r.Database > 15 || len(r.TeamIDs) == 0 || len(r.TeamIDs) > 10000 {
		return ErrInventory
	}
	seen := map[int]bool{}
	for _, id := range r.TeamIDs {
		if id <= 0 || seen[id] {
			return ErrInventory
		}
		seen[id] = true
	}
	return nil
}
func (o ObjectRef) Validate() error {
	if !utf8.ValidString(o.Key) || !utf8.ValidString(o.Bucket) || !utf8.ValidString(o.Version) || strings.ContainsAny(o.Key+o.Bucket+o.Version, "\x00\r\n") {
		return ErrInventory
	}
	if o.TeamID <= 0 || o.Bucket == "" || o.Key == "" || o.Version == "" || o.Version == "null" || !digest64.MatchString(o.SHA256) || o.Size < 0 || len(o.Key) > 4096 {
		return ErrInventory
	}
	return nil
}
func (i Inventory) Validate(users map[int]bool, instanceOwners map[int]int) error {
	if i.SchemaSHA256 != SchemaSHA256() || i.Version != InventoryVersion || len(i.Teams) > 10000 || len(i.Mounts) > 10000 || len(i.Redis) > 10000 || len(i.Objects) > 100000 {
		return ErrInventory
	}
	teams := map[int]SourceTeam{}
	mounts := map[string]SharedMount{}
	scopes := map[string]RedisScope{}
	members := map[int]bool{}
	for _, t := range i.Teams {
		if t.ID <= 0 || teams[t.ID].ID != 0 || !users[t.UserID] || (t.ResourceScope != "cm" && t.ResourceScope != "northbound") || (t.ResourceScope == "cm" && t.Owner != "") || (t.ResourceScope == "northbound" && t.Owner == "") || (t.Status != "running" && t.Status != "creating" && t.Status != "deleting" && t.Status != "failed") || t.RedisScopeID == "" || len(t.Members) > 10000 {
			return ErrInventory
		}
		for _, m := range t.Members {
			if m.ID <= 0 || members[m.ID] || len(members) >= 100000 || m.InstanceID < 0 || (m.InstanceID != 0 && instanceOwners[m.InstanceID] != t.UserID) {
				return ErrInventory
			}
			members[m.ID] = true
		}
		teams[t.ID] = t
	}
	for _, m := range i.Mounts {
		if !inventoryID.MatchString(m.ID) || mounts[m.ID].ID != "" || teams[m.TeamID].ID == 0 || m.Namespace == "" || m.PVC == "" || m.UID == "" || !path.IsAbs(m.Root) || path.Clean(m.Root) != m.Root || m.Root == "/" || teams[m.TeamID].SharedMountID != m.ID {
			return ErrInventory
		}
		mounts[m.ID] = m
	}
	covered := map[int]bool{}
	for _, r := range i.Redis {
		if r.Validate() != nil || scopes[r.ID].ID != "" {
			return ErrInventory
		}
		for _, id := range r.TeamIDs {
			if teams[id].ID == 0 || teams[id].RedisScopeID != r.ID || covered[id] {
				return ErrInventory
			}
			covered[id] = true
		}
		scopes[r.ID] = r
	}
	for _, t := range i.Teams {
		if !covered[t.ID] || (t.SharedMountID != "" && mounts[t.SharedMountID].ID == "") {
			return ErrInventory
		}
	}
	objects := map[string]bool{}
	for _, o := range i.Objects {
		id := o.Bucket + "\x00" + o.Key
		if o.Validate() != nil || teams[o.TeamID].ID == 0 || objects[id] {
			return ErrInventory
		}
		objects[id] = true
	}
	return nil
}

func CloneInventory(i *Inventory) *Inventory {
	if i == nil {
		return nil
	}
	raw, err := json.Marshal(i)
	if err != nil {
		return nil
	}
	var out Inventory
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return &out
}
func (i Inventory) SHA256() string {
	raw, _ := json.Marshal(i)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
