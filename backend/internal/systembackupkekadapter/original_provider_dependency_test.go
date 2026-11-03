package systembackupkekadapter

import (
	"context"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

func TestOriginalVaultDependencyPublicZeroCannotProduceNativeObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var observation ObservedOriginalVaultDependency
	if observation.Recheck(ctx, reg.Binding{}, time.Now()) == nil {
		t.Fatal("zero native evidence accepted")
	}
	if _, err := observation.Binding(); err == nil {
		t.Fatal("zero native binding accepted")
	}
	if _, err := observation.ValidUntil(ctx); err == nil {
		t.Fatal("zero native window accepted")
	}
	observer := &VaultPermissionObserver{}
	if _, err := observer.ObserveOriginalProviderDependency(ctx, nil, "installation", reg.ReferencePin{}, nil); err == nil {
		t.Fatal("missing original SQL authority accepted")
	}
}
