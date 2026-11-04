//go:build !linux

package quiesce

import (
	"context"
	"net"
)

type SharedRuntimeNodeHandler struct{}

func NewSharedRuntimeNodeHandler(*NodeObserver, SharedRuntimeNodeOwnerConfig) (*SharedRuntimeNodeHandler, error) {
	return nil, ErrNodeObservation
}
func (*SharedRuntimeNodeHandler) Close() {}
func NewSharedRuntimeFrozenObserver(*NodeObserver, SharedRuntimeFrozenReaderConfig) (*NodeObserver, error) {
	return nil, ErrNodeObservation
}
func (*NodeObserver) stoppedWithSharedScopes(context.Context, nodeObservationAnchor, []SharedRuntimeFrozenScope) (int, int, error) {
	return 0, 0, ErrNodeObservation
}
func ServeSharedRuntimeNodeLifecycle(context.Context, net.Listener, string, string, string, *SharedRuntimeNodeHandler) error {
	return ErrNodeObservation
}
