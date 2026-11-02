package domain

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCaptureTimingsBoundedDetachedAndNested(t *testing.T) {
	var timing CaptureTimings
	timing.observe(CaptureDomain, 12*time.Millisecond, true)
	timing.observe(CaptureKeyCheck, 4*time.Millisecond, false)
	timing.observe(CaptureKeyCheck, 3*time.Millisecond, true)
	timing.observe(CaptureTimingStage(255), time.Hour, true)
	timing.observe(CaptureSQLQuery, -time.Second, true)
	want := []CaptureTimingSample{
		{"key_check", 2, 1, 7000000, 4000000},
		{"domain_capture", 1, 1, 12000000, 12000000},
	}
	got := timing.Snapshot()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("lost closed labels, failure or inclusive parent timing", got)
	}
	got[0].Stage, got[0].Calls = "foreign", 999
	if !reflect.DeepEqual(timing.Snapshot(), want) {
		t.Fatal("snapshot can mutate recorder")
	}
}

func TestCaptureTimingsPreserveContextAndDoNotAuthorize(t *testing.T) {
	type privateKey struct{}
	const private = "PRIVATE_SOURCE_ARGS_PASSWORD_TOKEN_ERROR"
	base := context.WithValue(context.Background(), privateKey{}, private)
	ctx, cancel := context.WithDeadline(base, time.Now().Add(time.Minute))
	defer cancel()
	var timing CaptureTimings
	timed := WithCaptureTimings(ctx, &timing)
	deadline, ok := timed.Deadline()
	want, _ := ctx.Deadline()
	if !ok || deadline != want || timed.Value(privateKey{}) != private || timed.Done() != ctx.Done() {
		t.Fatal("diagnostics replaced original deadline, values or cancellation")
	}
	finish := BeginCaptureTiming(timed, CaptureKeyCheck)
	cancel()
	finish.Finish(errors.New(private))
	if timed.Err() != context.Canceled {
		t.Fatal("recorder hid cancellation")
	}
	samples := timing.Snapshot()
	if len(samples) != 1 || samples[0].Calls != 1 || samples[0].Failures != 1 || samples[0].TotalNanos < 0 {
		t.Fatal("failed operation not recorded")
	}
	raw, err := json.Marshal(samples)
	if err != nil || strings.Contains(string(raw), private) {
		t.Fatal("diagnostic exposed context or error")
	}
	if WithCaptureTimings(ctx, nil) != ctx || WithCaptureTimings(nil, &timing) != nil {
		t.Fatal("untimed context changed")
	}
	BeginCaptureTiming(nil, CaptureGuard).Finish(nil)
	BeginCaptureTiming(ctx, CaptureGuard).Finish(nil)
	BeginCaptureTiming(timed, CaptureTimingStage(255)).Finish(nil)
	if len(timing.Snapshot()) != 1 {
		t.Fatal("untimed/invalid label created a measurement")
	}
}

func TestCaptureTimingsConcurrentSnapshots(t *testing.T) {
	var timing CaptureTimings
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 100; j++ {
				timing.observe(CaptureSourceAuthorize, time.Microsecond, true)
				_ = timing.Snapshot()
			}
		}()
	}
	group.Wait()
	samples := timing.Snapshot()
	if len(samples) != 1 || samples[0] != (CaptureTimingSample{"source_authorize", 800, 800, 800000, 1000}) {
		t.Fatal("concurrent measurements lost", samples)
	}
}

func BenchmarkCaptureTimingGuardOverhead(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			ctx := context.Background()
			var timing CaptureTimings
			if enabled {
				ctx = WithCaptureTimings(ctx, &timing)
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				finish := BeginCaptureTiming(ctx, CaptureGuard)
				finish.Finish(nil)
			}
		})
	}
}
