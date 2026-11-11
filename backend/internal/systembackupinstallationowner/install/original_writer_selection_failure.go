package install

import "errors"

// Selection phase names are fixed source locations, never raw SQL/API errors.
// Retain the original cause privately for errors.Is/errors.As and diagnostics.
type OriginalWriterSelectionFailure struct {
	Stage string
	cause error
}

func (e OriginalWriterSelectionFailure) Error() string { return "original writer selection refused" }
func (e OriginalWriterSelectionFailure) Unwrap() error { return e.cause }

func originalSelectionStageFailure(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	var nested OriginalWriterSelectionFailure
	if errors.As(cause, &nested) {
		stage += "/" + nested.Stage
	}
	return OriginalWriterSelectionFailure{Stage: stage, cause: cause}
}
