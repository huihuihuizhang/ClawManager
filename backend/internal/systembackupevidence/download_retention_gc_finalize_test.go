package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadGCFinalizerClosedBindingAndSingleUse(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_tx", "nil_tx", "wrong_collector", "wrong_operation", "unrelated_context", "canceled_original", "checker_failure", "cancel_during_check"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tx := new(sql.Tx)
			owner := &struct{ id int }{1}
			calls := 0
			f := issueDownloadGCFinalizer(ctx, tx, owner, "PRIVATE_OPERATION", func(got context.Context, actual *sql.Tx) error {
				calls++
				if got != ctx || actual != tx {
					t.Fatal("checker received replacement context/transaction")
				}
				if mode == "cancel_during_check" {
					cancel()
				}
				if mode == "checker_failure" {
					return errors.New("PRIVATE authority facts")
				}
				return nil
			})
			if f == nil {
				t.Fatal("valid capability not issued")
			}
			copy := *f
			useCtx, useTx, useOwner, operation := context.Context(ctx), tx, any(owner), "PRIVATE_OPERATION"
			switch mode {
			case "wrong_tx":
				useTx = new(sql.Tx)
			case "nil_tx":
				useTx = nil
			case "wrong_collector":
				useOwner = &struct{ id int }{1}
			case "wrong_operation":
				operation = "OTHER"
			case "unrelated_context":
				useCtx = context.Background()
			case "canceled_original":
				cancel()
			}
			err := f.finish(useCtx, useTx, useOwner, operation)
			if (err == nil) != (mode == "valid") || err != nil && (err != errDownloadGCFinalizationDenied || strings.Contains(err.Error(), "PRIVATE")) {
				t.Fatal("binding/failure boundary differs", err)
			}
			wantCalls := 0
			if mode == "valid" || mode == "checker_failure" || mode == "cancel_during_check" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatal("invalid binding reached SQL checker", calls)
			}
			if copy.finish(ctx, tx, owner, "PRIVATE_OPERATION") == nil || f.finish(ctx, tx, owner, "PRIVATE_OPERATION") == nil || calls != wantCalls {
				t.Fatal("copy/retry renewed a consumed completion")
			}
		})
	}
}

func TestDownloadGCFinalizerConcurrentCopiesConsumeOnce(t *testing.T) {
	ctx := context.Background()
	tx := new(sql.Tx)
	owner := &struct{ id int }{1}
	var calls, accepted atomic.Int32
	f := issueDownloadGCFinalizer(ctx, tx, owner, "operation", func(context.Context, *sql.Tx) error { calls.Add(1); return nil })
	var group sync.WaitGroup
	for i := 0; i < 24; i++ {
		copy := *f
		group.Add(1)
		go func() {
			defer group.Done()
			if copy.finish(ctx, tx, owner, "operation") == nil {
				accepted.Add(1)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 1 || accepted.Load() != 1 {
		t.Fatal("copied completion finalized more than once", calls.Load(), accepted.Load())
	}
}

type gcFinalizerWrappedContext struct {
	context.Context
	extra any
}

func TestDownloadGCFinalizerRejectsDynamicallyIncomparableContext(t *testing.T) {
	for _, extra := range []any{[]int{1}, map[string]int{"PRIVATE": 1}} {
		t.Run(fmt.Sprintf("%T", extra), func(t *testing.T) {
			ctx := gcFinalizerWrappedContext{Context: context.Background(), extra: extra}
			tx, owner := new(sql.Tx), &struct{ id int }{1}
			calls := 0
			check := func(context.Context, *sql.Tx) error { calls++; return nil }
			if issueDownloadGCFinalizer(ctx, tx, owner, "op", check) != nil {
				t.Fatal("dynamically incomparable original context accepted")
			}
			original := context.Background()
			f := issueDownloadGCFinalizer(original, tx, owner, "op", check)
			copy := *f
			if f.finish(ctx, tx, owner, "op") != errDownloadGCFinalizationDenied || copy.finish(original, tx, owner, "op") != errDownloadGCFinalizationDenied || calls != 0 {
				t.Fatal("incomparable replacement reached checker or renewed completion")
			}
		})
	}
}

func TestDownloadGCFinalizerDeadlineZeroAndOutput(t *testing.T) {
	tx, owner := new(sql.Tx), &struct{ id int }{1}
	check := func(context.Context, *sql.Tx) error { return nil }
	if issueDownloadGCFinalizer(nil, tx, owner, "op", check) != nil || issueDownloadGCFinalizer(context.Background(), nil, owner, "op", check) != nil || issueDownloadGCFinalizer(context.Background(), tx, nil, "op", check) != nil || issueDownloadGCFinalizer(context.Background(), tx, owner, "op", nil) != nil {
		t.Fatal("incomplete issuer inputs accepted")
	}
	var zero downloadGCWorkFinalizer
	var absent *downloadGCWorkFinalizer
	if zero.finish(context.Background(), tx, owner, "op") == nil || absent.finish(context.Background(), tx, owner, "op") == nil {
		t.Fatal("zero/forged completion accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f := issueDownloadGCFinalizer(ctx, tx, owner, "PRIVATE_OPERATION", check)
	if f == nil {
		t.Fatal("initial deadline binding failed")
	}
	<-ctx.Done()
	if f.finish(ctx, tx, owner, "PRIVATE_OPERATION") == nil || f.finish(context.Background(), tx, owner, "PRIVATE_OPERATION") == nil {
		t.Fatal("original deadline renewed")
	}
	for _, value := range []any{f, *f} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(verb, value) != "DownloadGCWorkFinalizer" {
				t.Fatal("captured facts formatted")
			}
		}
		if b, err := json.Marshal(value); err == nil || len(b) != 0 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("captured facts serialized")
		}
	}
}
