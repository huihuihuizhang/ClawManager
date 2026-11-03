//go:build !linux

package quiesce

import "context"

func ReadNodeObservationKey(string) ([]byte, error) { return nil, ErrNodeObservation }

func (*NodeObserver) hostIdentity(context.Context) error { return ErrNodeObservation }
func (*NodeObserver) paths(context.Context, []string) ([]observedPath, error) {
	return nil, ErrNodeObservation
}
func (*NodeObserver) running(context.Context, ObservationBinding, []PodIdentity, []observedPath) ([]observedProcess, error) {
	return nil, ErrNodeObservation
}
func (*NodeObserver) originalScopes(context.Context, nodeObservationAnchor) ([]observedProcess, error) {
	return nil, ErrNodeObservation
}
func (*NodeObserver) reconcileOriginalRecovery(context.Context, NodeObservationRequest, nodeObservationAnchor) (originalRecoveryNativeResult, error) {
	return originalRecoveryNativeResult{}, ErrNodeObservation
}
func (*NodeObserver) stopped(context.Context, nodeObservationAnchor) (int, int, error) {
	return 0, 0, ErrNodeObservation
}
func (*NodeObserver) scan(context.Context, nodeObservationAnchor, any) (int, []observedProcess, error) {
	return 0, nil, ErrNodeObservation
}
