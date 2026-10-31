package systembackupcontroller

import (
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

func TestOriginalPlanDataCacheOwnsBytesAndBoundsMemory(t *testing.T) {
	_, empty := cloneOriginalPlanData(d.Plan{}, b.Discovery{Writers: []b.FrozenWriter{}, Parts: []b.JobPart{}})
	if empty.Writers == nil || empty.Parts == nil {
		t.Fatal("non-nil empty arrays changed shape")
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	c := originalPlanDataCache{maxBytes: 200000, maxEntries: 2, ttl: time.Minute}
	plan := d.Plan{CanonicalJSON: []byte("original")}
	desc := b.Discovery{Source: []byte("source"), Parts: []b.JobPart{{InvocationJSON: []byte("invocation"), Intent: d.JobIntent{SpecJSON: []byte("spec")}}}}
	key := originalPlanDataKey{hash: "one"}
	c.put(key, plan, desc, now, now.Add(time.Hour))
	plan.CanonicalJSON[0] = '!'
	desc.Source[0] = '!'
	desc.Parts[0].InvocationJSON[0] = '!'
	desc.Parts[0].Intent.SpecJSON[0] = '!'
	first, firstDesc, ok := c.get(key, now)
	if !ok || string(first.CanonicalJSON) != "original" || string(firstDesc.Source) != "source" || string(firstDesc.Parts[0].InvocationJSON) != "invocation" || string(firstDesc.Parts[0].Intent.SpecJSON) != "spec" {
		t.Fatal("cache retained caller aliases")
	}
	first.CanonicalJSON[0] = '!'
	firstDesc.Source[0] = '!'
	firstDesc.Parts[0].InvocationJSON[0] = '!'
	firstDesc.Parts[0].Intent.SpecJSON[0] = '!'
	again, againDesc, ok := c.get(key, now)
	if !ok || string(again.CanonicalJSON) != "original" || string(againDesc.Source) != "source" || string(againDesc.Parts[0].InvocationJSON) != "invocation" || string(againDesc.Parts[0].Intent.SpecJSON) != "spec" {
		t.Fatal("cache exposed internal aliases")
	}
	c.put(originalPlanDataKey{hash: "two"}, again, againDesc, now, now.Add(time.Hour))
	c.put(originalPlanDataKey{hash: "three"}, again, againDesc, now, now.Add(time.Hour))
	if c.order.Len() != 2 || c.bytes > c.maxBytes {
		t.Fatal("entry/byte bound exceeded")
	}
	if _, _, ok := c.get(key, now); ok {
		t.Fatal("old entry not evicted")
	}
	if _, _, ok := c.get(originalPlanDataKey{hash: "three"}, now.Add(time.Minute)); ok {
		t.Fatal("expired data remained usable")
	}
	c.put(originalPlanDataKey{hash: "large"}, d.Plan{CanonicalJSON: make([]byte, 50000)}, b.Discovery{}, now, now.Add(time.Hour))
	if _, _, ok := c.get(originalPlanDataKey{hash: "large"}, now); ok {
		t.Fatal("oversize entry retained")
	}
}
