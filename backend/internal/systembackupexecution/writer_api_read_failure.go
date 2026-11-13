package systembackupexecution

import (
	"context"
	"errors"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// WriterAPIReadFailure contains fixed diagnostic labels, never API error text.
type WriterAPIReadFailure struct {
	Step, Kind, Reason string
	InstanceID         int
	cause              error
}

// Preserve the rejection/cause and bounded inner graph label. The source row
// identity is diagnostic only; it cannot supply a runtime observation or grant.
func writerNativeReadFailure(err error, ctx context.Context, step, kind string, instance int, observed error) error {
	err = writerAPIReadFailure(err, ctx, step, kind, observed)
	var failure *WriterAPIReadFailure
	if errors.As(err, &failure) && instance > 0 {
		copy := *failure
		copy.InstanceID = instance
		return &copy
	}
	return err
}

func (e *WriterAPIReadFailure) Error() string { return "writer API read refused: " + e.Step }
func (e *WriterAPIReadFailure) Unwrap() error { return e.cause }

func writerAPIReadFailure(err error, ctx context.Context, step, kind string, observed error) error {
	if err == nil {
		return nil
	}
	var inner *WriterAPIReadFailure
	if errors.As(err, &inner) {
		return err
	}
	reason := "validation"
	var timeout net.Error
	switch {
	case errors.Is(observed, context.DeadlineExceeded) || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		reason = "deadline"
	case errors.Is(observed, context.Canceled) || ctx != nil && errors.Is(ctx.Err(), context.Canceled):
		reason = "canceled"
	case apierrors.IsForbidden(observed):
		reason = "forbidden"
	case apierrors.IsUnauthorized(observed):
		reason = "unauthorized"
	case apierrors.IsNotFound(observed):
		reason = "not_found"
	case errors.As(observed, &timeout) && timeout.Timeout():
		reason = "timeout"
	case observed != nil:
		reason = "read_error"
	}
	return &WriterAPIReadFailure{Step: step, Kind: kind, Reason: reason, cause: err}
}
