package worker

import (
	"sync/atomic"
	"time"
)

// Client-local completed-call DATA only. These counters contain no request,
// identity, credential, authority or receipt, and never control execution.
type CaptureControlCallTimingData struct {
	Calls        uint64
	HTTPAttempts uint64
	Failures     uint64
	ElapsedNanos int64
	MaxNanos     int64
	LastNanos    int64
}
type CaptureControlTimingData struct {
	KeyReserve, KeyBegin, KeyCheck, KeyEnd, Candidate CaptureControlCallTimingData
}
type captureControlCostBucket struct {
	calls, failures, httpAttempts atomic.Uint64
	elapsed                       atomic.Int64
	maximum, last                 atomic.Int64
}
type captureControlCosts struct{ reserve, begin, check, end, candidate captureControlCostBucket }

func (v *captureControlCosts) record(action string, elapsed time.Duration, failed, httpAttempted bool) {
	var bucket *captureControlCostBucket
	switch action {
	case "key-reserve":
		bucket = &v.reserve
	case "key-begin":
		bucket = &v.begin
	case "key-check":
		bucket = &v.check
	case "key-end":
		bucket = &v.end
	case "candidate":
		bucket = &v.candidate
	default:
		return
	}
	nanos := elapsed.Nanoseconds()
	bucket.elapsed.Add(nanos)
	bucket.last.Store(nanos)
	for old := bucket.maximum.Load(); nanos > old; old = bucket.maximum.Load() {
		if bucket.maximum.CompareAndSwap(old, nanos) {
			break
		}
	}
	if failed {
		bucket.failures.Add(1)
	}
	if httpAttempted {
		bucket.httpAttempts.Add(1)
	}
	bucket.calls.Add(1)
}
func (v *captureControlCostBucket) data() CaptureControlCallTimingData {
	return CaptureControlCallTimingData{Calls: v.calls.Load(), HTTPAttempts: v.httpAttempts.Load(), Failures: v.failures.Load(), ElapsedNanos: v.elapsed.Load(), MaxNanos: v.maximum.Load(), LastNanos: v.last.Load()}
}

// CaptureControlTimingData observes completed calls including local validation,
// serialization and full HTTP handling. HTTPAttempts counts Do calls, not
// acknowledged server receipts. Concurrent sends can
// finish between field loads; this is diagnostic DATA, never a consistency
// proof or permission to renew, repeat, skip or accept an operation.
func (c *ControlClient) CaptureControlTimingData() CaptureControlTimingData {
	if c == nil {
		return CaptureControlTimingData{}
	}
	v := &c.captureCosts
	return CaptureControlTimingData{KeyReserve: v.reserve.data(), KeyBegin: v.begin.data(), KeyCheck: v.check.data(), KeyEnd: v.end.data(), Candidate: v.candidate.data()}
}
