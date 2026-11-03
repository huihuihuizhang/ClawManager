//go:build !linux

package quiesce

import "context"

func (*NodeObserver) prepareGateway(context.Context,GatewayNodeObservationRequest) (gatewayObservationAnchor,error) {return gatewayObservationAnchor{},ErrNodeObservation}
func (*NodeObserver) checkGateway(context.Context,GatewayNodeObservationRequest,gatewayObservationAnchor) (int,int,error) {return 0,0,ErrNodeObservation}
