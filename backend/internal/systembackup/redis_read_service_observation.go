package systembackup

import (
	"context"
	"reflect"
	"time"
)

// Native Redis only. This cannot be deserialized or stand in for the real
// SQL/application/original-source holder. Final composite SQL checks may use
// Recheck without issuing network or filesystem I/O under their SQL locks.
type VerifiedRedisReadServiceObservation struct {
	origin                              *VerifiedRedisReadServiceObservation
	gate                                *RedisReadServiceGate
	operation, inventory, digest, phase string
	started, until                      time.Time
}

func (*VerifiedRedisReadServiceObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrRedisReadGate
}

type RedisReadServiceObservationData struct {
	Version, Operation, InventorySHA256, ServerRunID, PodUID, ACLStateSHA256, Phase string
	StartedAt, ValidUntil                                                           time.Time
}

func (v *VerifiedRedisReadServiceObservation) Data() RedisReadServiceObservationData {
	if v == nil || v.origin != v || v.gate == nil {
		return RedisReadServiceObservationData{}
	}
	return RedisReadServiceObservationData{"redis-native-read-service-observation.v1", v.operation, v.inventory, v.gate.in.Policy.ServerID, v.gate.in.PodUID, v.digest, v.phase, v.started, v.until}
}
func (v *VerifiedRedisReadServiceObservation) Recheck(ctx context.Context, operation, inventory, phase string, now time.Time) error {
	if v == nil || v.origin != v || v.gate == nil || ctx == nil || ctx.Err() != nil || v.operation != operation || v.inventory != inventory || v.phase != phase || now.Before(v.started) || !now.Before(v.until) || !time.Now().Before(v.until) {
		return ErrRedisReadGate
	}
	g := v.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || g.transportFailed || phase == "held" && (!g.held || g.closed || v.digest != g.digest) || phase == "recovered" && (!g.closed || g.held || v.digest != redisGateHash(g.original)) {
		return ErrRedisReadGate
	}
	return nil
}
func (g *RedisReadServiceGate) ObserveHeld(ctx context.Context) (*VerifiedRedisReadServiceObservation, error) {
	if g == nil {
		return nil, ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	started := time.Now().UTC()
	if g.checkHeld(ctx) != nil {
		return nil, ErrRedisReadGate
	}
	until := started.Add(10 * time.Second)
	if d, ok := ctx.Deadline(); !ok {
		return nil, ErrRedisReadGate
	} else if d.Before(until) {
		until = d
	}
	if !time.Now().Before(until) {
		return nil, ErrRedisReadGate
	}
	v := &VerifiedRedisReadServiceObservation{gate: g, operation: g.in.Operation, inventory: g.in.InventorySHA256, digest: g.digest, phase: "held", started: started, until: until}
	v.origin = v
	return v, nil
}
func (g *RedisReadServiceGate) ObserveRecovered(ctx context.Context, fresh TeamSourceCheck) (*VerifiedRedisReadServiceObservation, error) {
	if g == nil || fresh == nil {
		return nil, ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	started := time.Now().UTC()
	old := g.check
	g.check = fresh
	defer func() { g.check = old }()
	if !g.closed || g.held || g.identity(ctx) != nil || g.readOriginalCustody(ctx) != nil {
		return nil, ErrRedisReadGate
	}
	owner, e := g.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if e != nil || owner != nil {
		return nil, ErrRedisReadGate
	}
	users, e := g.users(ctx)
	if e != nil || !reflect.DeepEqual(users, g.original) {
		return nil, ErrRedisReadGate
	}
	until := started.Add(10 * time.Second)
	if d, ok := ctx.Deadline(); !ok {
		return nil, ErrRedisReadGate
	} else if d.Before(until) {
		until = d
	}
	if !time.Now().Before(until) {
		return nil, ErrRedisReadGate
	}
	v := &VerifiedRedisReadServiceObservation{gate: g, operation: g.in.Operation, inventory: g.in.InventorySHA256, digest: redisGateHash(users), phase: "recovered", started: started, until: until}
	v.origin = v
	return v, nil
}
func (g *RedisReadServiceGate) OriginalDigest() string {
	if g == nil || g.origin != g {
		return ""
	}
	return redisGateHash(g.original)
}
