//go:build !linux

package quiesce

import "context"

func (*NodeObserver) stoppedProNative(context.Context, stoppedProAnchor) (int, int, int, int, string, error) {
	return 0, 0, 0, 0, "", ErrNodeObservation
}
