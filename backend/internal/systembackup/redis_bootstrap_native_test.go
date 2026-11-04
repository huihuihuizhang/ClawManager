package systembackup

import "testing"

func TestRedisNativeVersionIsFiniteAndRejectsUnreviewed74(t *testing.T) {
	for _, version := range []string{"7.2.0", "7.2.7", "7.4.11"} {
		if !RedisNativeReadGateVersion(version) {
			t.Fatalf("rejected finite profile %s", version)
		}
	}
	for _, version := range []string{"7.4.10", "7.4.12", "7.4", "7.4.11-enterprise", "7.4.011", "7.2.x", "7.2.01", "8.0.0", "6.2.0"} {
		if RedisNativeReadGateVersion(version) {
			t.Fatalf("accepted unknown profile %s", version)
		}
	}
}

// Command categories are read from the real native catalogue in production.
// This parser test ensures new 7.4 hash-field writes cannot become read-safe
// merely because the accepted server profile changed; it is not a Redis run.
func TestRedis74HashFieldWriteDoesNotBecomeReadCapability(t *testing.T) {
	all := map[string]bool{"hget": true, "hgetall": true, "hexpire": true, "hpexpire": true, "hpersist": true}
	categories := map[string][]string{"read": {"hget", "hgetall"}, "write": {"hexpire", "hpexpire", "hpersist"}}
	allowed, e := redisGateAllowed("-@all +@read", all, categories)
	if e != nil || !allowed["hget"] || !allowed["hgetall"] {
		t.Fatal("native read category not preserved")
	}
	for _, name := range []string{"hexpire", "hpexpire", "hpersist"} {
		if allowed[name] {
			t.Fatal("hash-field write escaped read reduction")
		}
	}
	if _, e := redisGateAllowed("-@all +@unknown", all, categories); e == nil {
		t.Fatal("unknown category accepted")
	}
}
