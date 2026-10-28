package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// WorkBuddySchema is supplied by the source branch owner, keyed by the exact
// information_schema fingerprint. Field names are not guessed from instance IDs.
// All columns are preserved; the schema must exist on the isolated target.
type WorkBuddySchema struct {
	Version, SHA256                     string
	Instance, StorageIdentity, UID, GID string
	Layout                              string `json:",omitempty"`
	AllocatorSHA256                     string `json:",omitempty"`
}

func SchemaDigest(t Table) string {
	t.Rows = nil
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (w *WorkBuddySchema) columns(t Table) (map[string]bool, error) {
	if w != nil && w.Layout != "" {
		if !w.uidLayout() || !w.validUIDContract() || SchemaDigest(t) != w.SHA256 {
			return nil, ErrSchema
		}
		return map[string]bool{"instance_id": true, "user_id": true, "linux_uid": true, "created_at": true}, nil
	}
	if w == nil || w.Version == "" || len(w.SHA256) != 64 || SchemaDigest(t) != w.SHA256 || t.Name != "workbuddy_linux_identities" {
		return nil, ErrSchema
	}
	known := map[string]bool{}
	for _, c := range t.Columns {
		known[c.Name] = true
	}
	seen := map[string]bool{}
	for _, name := range []string{w.Instance, w.StorageIdentity, w.UID, w.GID} {
		if !known[name] || seen[name] {
			return nil, ErrSchema
		}
		seen[name] = true
	}
	return known, nil
}
func validateWorkBuddy(s Snapshot, w *WorkBuddySchema) error {
	if w != nil && w.Layout != "" {
		return validateWorkBuddyUID(s, w)
	}
	instances := map[string]string{}
	for _, t := range s.Tables {
		if t.Name == "instances" {
			for _, r := range t.Rows {
				if r["type"].String() == "workbuddy" {
					instances[r["id"].String()] = r["workbuddy_storage_identity"].String()
				}
			}
		}
	}
	var table *Table
	for i := range s.Tables {
		if s.Tables[i].Name == "workbuddy_linux_identities" {
			table = &s.Tables[i]
		}
	}
	// A missing table is not proof of a legacy identity layout. WorkBuddy needs
	// an explicit adapter even when its source branch stores identities elsewhere.
	if table == nil {
		if w != nil || len(instances) != 0 {
			return ErrSchema
		}
		return nil
	}
	if len(table.Rows) == 0 && len(instances) == 0 {
		return nil
	}
	if _, e := w.columns(*table); e != nil {
		return e
	}
	seenID, seenStorage, seenUID, seenGID := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range table.Rows {
		id, storage := r[w.Instance].String(), r[w.StorageIdentity].String()
		identity, ok := instances[id]
		if !ok || storage == "" || identity != storage || seenID[id] || seenStorage[storage] {
			return ErrData
		}
		for index, col := range []string{w.UID, w.GID} {
			v := r[col].String()
			n, e := strconv.ParseUint(v, 10, 32)
			if e != nil || n < 1000 || n == 65534 || strconv.FormatUint(n, 10) != v {
				return ErrData
			}
			seen := seenUID
			if index == 1 {
				seen = seenGID
			}
			if seen[v] {
				return ErrData
			}
			seen[v] = true
		}
		seenID[id] = true
		seenStorage[storage] = true
	}
	if len(seenID) != len(instances) {
		return ErrData
	}
	return nil
}
