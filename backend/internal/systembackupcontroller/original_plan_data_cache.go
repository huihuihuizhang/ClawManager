package systembackupcontroller

import (
	"bytes"
	"container/list"
	"database/sql"
	"sync"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// Only immutable authenticated historical data lives here. No context,
// OriginalCapturePlan, authority guard, nonce, permit, key or DEK is cached.
// Every get is preceded by current SQL/input/ciphertext/key authorization.
var authenticatedOriginalPlanData = originalPlanDataCache{maxBytes: 32 << 20, maxEntries: 8, ttl: 5 * time.Minute}

type originalPlanDataKey struct {
	database *sql.DB
	hash     string
}
type originalPlanDataEntry struct {
	key       originalPlanDataKey
	plan      d.Plan
	discovery b.Discovery
	expires   time.Time
	size      int
}
type originalPlanDataCache struct {
	mu                          sync.Mutex
	items                       map[originalPlanDataKey]*list.Element
	order                       list.List
	bytes, maxBytes, maxEntries int
	ttl                         time.Duration
}

func cloneOriginalPlanData(plan d.Plan, desc b.Discovery) (d.Plan, b.Discovery) {
	plan.CanonicalJSON = bytes.Clone(plan.CanonicalJSON)
	desc.Source = bytes.Clone(desc.Source)
	if desc.Writers != nil {
		original := desc.Writers
		desc.Writers = make([]b.FrozenWriter, len(original))
		copy(desc.Writers, original)
	}
	if desc.Parts != nil {
		original := desc.Parts
		desc.Parts = make([]b.JobPart, len(original))
		copy(desc.Parts, original)
	}
	for index := range desc.Parts {
		desc.Parts[index].InvocationJSON = bytes.Clone(desc.Parts[index].InvocationJSON)
		desc.Parts[index].Intent.SpecJSON = bytes.Clone(desc.Parts[index].Intent.SpecJSON)
	}
	return plan, desc
}

func (c *originalPlanDataCache) remove(e *list.Element) {
	v := e.Value.(*originalPlanDataEntry)
	delete(c.items, v.key)
	c.order.Remove(e)
	c.bytes -= v.size
	clear(v.plan.CanonicalJSON)
	clear(v.discovery.Source)
	for _, part := range v.discovery.Parts {
		clear(part.InvocationJSON)
		clear(part.Intent.SpecJSON)
	}
}

func (c *originalPlanDataCache) get(key originalPlanDataKey, now time.Time) (d.Plan, b.Discovery, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.items[key]
	if e == nil {
		return d.Plan{}, b.Discovery{}, false
	}
	if !now.Before(e.Value.(*originalPlanDataEntry).expires) {
		c.remove(e)
		return d.Plan{}, b.Discovery{}, false
	}
	c.order.MoveToFront(e)
	v := e.Value.(*originalPlanDataEntry)
	p, desc := cloneOriginalPlanData(v.plan, v.discovery)
	return p, desc, true
}

func (c *originalPlanDataCache) put(key originalPlanDataKey, plan d.Plan, desc b.Discovery, now, deadline time.Time) {
	// Four times the outer base64 plan plus fixed bookkeeping conservatively
	// covers both owned byte copies, decoded strings, slices and map overhead.
	size := 4*len(plan.CanonicalJSON) + 64*1024
	if c.maxBytes < 1 || c.maxEntries < 1 || c.ttl <= 0 || len(plan.CanonicalJSON) < 1 || size > c.maxBytes || !now.Before(deadline) {
		return
	}
	expires := now.Add(c.ttl)
	if deadline.Before(expires) {
		expires = deadline
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[originalPlanDataKey]*list.Element{}
	}
	if old := c.items[key]; old != nil {
		c.remove(old)
	}
	for e := c.order.Back(); e != nil; {
		previous := e.Prev()
		if !now.Before(e.Value.(*originalPlanDataEntry).expires) {
			c.remove(e)
		}
		e = previous
	}
	for c.order.Len() >= c.maxEntries || c.bytes+size > c.maxBytes {
		c.remove(c.order.Back())
	}
	p, discovery := cloneOriginalPlanData(plan, desc)
	v := &originalPlanDataEntry{key: key, plan: p, discovery: discovery, expires: expires, size: size}
	c.items[key] = c.order.PushFront(v)
	c.bytes += size
}
