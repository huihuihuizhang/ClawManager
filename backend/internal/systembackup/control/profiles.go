package control

import (
	"context"
	"encoding/json"
	"regexp"
	"time"
)

var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

// PublishProfiles is controller-only. API credentials receive SELECT, never
// INSERT/UPDATE on this table. Readiness expires if the controller disappears.
func (s SQLStore) PublishProfiles(ctx context.Context, profiles []Profile, ttl time.Duration) error {
	if ttl < time.Second || ttl > time.Minute || len(profiles) > 100 {
		return ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	seen := map[string]bool{}
	for _, p := range profiles {
		if !identifier.MatchString(p.ID) || seen[p.ID] || len(p.Kinds) == 0 || len(p.Kinds) > 3 || len(p.Reasons) > 32 {
			return ErrInvalid
		}
		seen[p.ID] = true
		if p.AcceptancePolicy != nil && (p.AcceptancePolicy.Validate() != nil || len(p.Kinds) != 1 || p.Kinds[0] != "backup") {
			return ErrInvalid
		}
		kinds := map[string]bool{}
		for _, k := range p.Kinds {
			if paths[k] == nil || kinds[k] {
				return ErrInvalid
			}
			kinds[k] = true
		}
		for _, r := range p.Reasons {
			if !identifier.MatchString(r) {
				return ErrInvalid
			}
		}
		if p.Ready && (len(p.Reasons) > 0 || !revision.MatchString(p.Revision)) {
			return ErrInvalid
		}
		b, _ := json.Marshal(p)
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_profiles(profile_id,profile_json,valid_until_ms) VALUES(?,?,"+dbNow+"+?) ON DUPLICATE KEY UPDATE profile_json=VALUES(profile_json),valid_until_ms=VALUES(valid_until_ms)", p.ID, b, ttl.Milliseconds())
		if e != nil {
			return ErrNotReady
		}
	}
	if tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (s SQLStore) Profiles(ctx context.Context) ([]Profile, error) {
	if s.DB == nil {
		return nil, ErrNotReady
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT profile_json,valid_until_ms>"+dbNow+" FROM system_backup_profiles ORDER BY profile_id LIMIT 101")
	if e != nil {
		return nil, ErrNotReady
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		var b []byte
		var alive bool
		var p Profile
		if rows.Scan(&b, &alive) != nil || json.Unmarshal(b, &p) != nil {
			return nil, ErrNotReady
		}
		if !alive {
			p.Ready = false
			p.Reasons = []string{"controller_unavailable"}
		}
		out = append(out, p)
	}
	if rows.Err() != nil || len(out) > 100 {
		return nil, ErrNotReady
	}
	return out, nil
}
