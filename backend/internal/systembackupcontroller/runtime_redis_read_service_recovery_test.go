package systembackupcontroller

import (
	"context"
	"testing"
	"time"

	sb "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// Public observation DATA, including plausible native timestamps/digests,
// cannot cross the new source-recovery branch without a real opaque sample.
func TestRedisReadServiceRecoveryRejectsDataOnlyObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	facts := RedisReadServiceRecoveryFacts{Version: "source-recovery-redis-native-acl.v1", Kind: "redis_read_service", Native: sb.RedisReadServiceObservationData{Version: "redis-native-read-service-observation.v1", Phase: "recovered", StartedAt: time.Now(), ValidUntil: time.Now().Add(time.Second)}}
	for _, proof := range []*sb.VerifiedRedisReadServiceObservation{nil, {}} {
		if _, e := NewRedisReadServiceRecoveryObservation(ctx, d.Authority{}, b.FrozenWriter{}, facts, proof); e == nil {
			t.Fatal("public data or zero opaque accepted as native recovery")
		}
	}
}
