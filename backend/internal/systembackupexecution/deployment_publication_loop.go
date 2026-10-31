package systembackupexecution

import "context"

// A failed task in one queue must not suppress another original task's
// query-only unknown recovery. Cancellation never starts the next pass.
func runCaptureAndPublicationPass(ctx context.Context, capture, publication func(context.Context) error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	captureErr := capture(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	publicationErr := publication(ctx)
	if publicationErr != nil {
		return publicationErr
	}
	return captureErr
}

func (s *DeploymentService) runCaptureAndPublicationPass(ctx context.Context) error {
	return runCaptureAndPublicationPass(ctx, s.Runtime.Loop.RunOnce, s.RunPublicationPass)
}
