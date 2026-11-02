package systembackupkekadapter

import (
	"context"
	"errors"
	"sync"
	"testing"

	"clawreef/internal/systembackup/worker"
	kms "clawreef/internal/systembackupkms"
)

func TestProviderPermitTimingCannotAuthorizeMissingOriginalAuthority(t *testing.T) {
	ctx, observer := WithProviderPermitTiming(context.Background())
	var issue *PreparedProviderPermitIssue
	for _, input := range []context.Context{context.Background(), ctx} {
		if err := issue.Stage(input, nil, worker.KeyUseLease{}, "key-check"); !errors.Is(err, kms.ErrPermission) {
			t.Fatalf("missing authority changed denial: %v", err)
		}
		if err := issue.StageOriginal(input, nil, worker.KeyUseLease{}, "key-check", nil); !errors.Is(err, kms.ErrPermission) {
			t.Fatalf("missing original guard changed denial: %v", err)
		}
	}
	data := observer.Snapshot()
	for _, label := range []string{"Stage", "Stage.Entry"} {
		if data[label].Calls != 1 || data[label].Failures != 1 {
			t.Fatal(label, data)
		}
	}
	if len(data) != 2 {
		t.Fatal("recorded stages not reached", data)
	}
	if data["Stage.Entry"].ElapsedNanos > data["Stage"].ElapsedNanos {
		t.Fatal("child exceeds parent", data)
	}
}

func TestProviderPermitTimingConcurrentDetachedSnapshots(t *testing.T) {
	ctx, observer := WithProviderPermitTiming(context.Background())
	var tasks sync.WaitGroup
	for i := 0; i < 32; i++ {
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			for j := 0; j < 100; j++ {
				timer := startProviderPermitTimer(ctx, "Recheck.Mapping")
				timer.finish(j%2 == 0)
				copy := observer.Snapshot()
				delete(copy, "Recheck.Mapping")
			}
		}()
	}
	tasks.Wait()
	data := observer.Snapshot()["Recheck.Mapping"]
	if data.Calls != 3200 || data.Failures != 1600 || data.ElapsedNanos < data.MaxNanos {
		t.Fatal(data)
	}
	var absent *ProviderPermitTimingObserver
	if len(absent.Snapshot()) != 0 || startProviderPermitTimer(nil, "Stage") != nil || startProviderPermitTimer(context.Background(), "Stage") != nil {
		t.Fatal("disabled diagnostics became active")
	}
}
