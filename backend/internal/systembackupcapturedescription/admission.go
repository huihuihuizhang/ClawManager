package systembackupcapturedescription

import (
	"math"
	"runtime"
	"runtime/debug"
	"sync"
)

var decodeMemoryMu sync.Mutex
var decodeMemoryReserved uint64

// AdmitDecodeMemory is resource admission, never source/key authorization.
// Require a finite process GOMEMLIMIT (or startup SetMemoryLimit), enough
// declared allowance and current Go-memory headroom BEFORE body allocation.
// The release must outlive all original/decoded/round-trip descriptor buffers.
// This does not claim a measured maximum RSS or an OS hard-limit guarantee.
func AdmitDecodeMemory(seed Seed) (func(), error) {
	budget, err := DecodeMemoryBudget(seed)
	if err != nil {
		return nil, err
	}
	decodeMemoryMu.Lock()
	defer decodeMemoryMu.Unlock()
	limit := debug.SetMemoryLimit(-1)
	var current runtime.MemStats
	runtime.ReadMemStats(&current)
	used := current.Sys - current.HeapReleased
	growth := 12*seed.MaxPlaintextBytes + (32 << 20)
	if limit == math.MaxInt64 || limit <= 0 || limit < budget || used > uint64(limit) || decodeMemoryReserved > uint64(limit)-used || uint64(limit)-used-decodeMemoryReserved < uint64(growth) {
		return nil, ErrDescription
	}
	// Account the full conservative growth for EACH concurrent pipeline.
	// Current used memory is also counted, even if part of an earlier reserved
	// pipeline is already allocated; this intentionally errs conservatively.
	decodeMemoryReserved += uint64(growth)
	var once sync.Once
	return func() {
		once.Do(func() { decodeMemoryMu.Lock(); decodeMemoryReserved -= uint64(growth); decodeMemoryMu.Unlock() })
	}, nil
}
