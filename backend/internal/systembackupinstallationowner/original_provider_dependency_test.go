package systembackupinstallationowner

import (
	"context"
	"testing"
	"time"
)

func TestOriginalSigningDependencyPublicZeroCannotProduceNativeObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var observation ObservedOriginalSigningDependency
	if observation.Recheck(ctx, Binding{}, time.Now()) == nil {
		t.Fatal("zero metadata observation accepted")
	}
	if _, err := observation.ValidUntil(ctx); err == nil {
		t.Fatal("zero metadata cap accepted")
	}
	observer := &CaptureSigningObserver{}
	if _, err := observer.ObserveOriginalProviderDependency(ctx, nil); err == nil {
		t.Fatal("missing actual authenticated owner record accepted")
	}
}
