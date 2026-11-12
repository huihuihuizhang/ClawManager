package systembackupexecution

// OriginalMountAuthorFailure exposes only a fixed phase label. The wrapped
// cause remains available to errors.As without disclosing credentials or URLs.
type OriginalMountAuthorFailure struct {
	Phase string
	cause error
}

func (e *OriginalMountAuthorFailure) Error() string {
	return "original mount author refused: " + e.Phase
}
func (e *OriginalMountAuthorFailure) Unwrap() error { return e.cause }
