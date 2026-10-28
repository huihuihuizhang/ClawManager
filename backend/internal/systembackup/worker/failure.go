package worker

import (
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/workspace"
	"errors"
)

// Failure reports a closed category only; it deliberately discards source
// filenames, filesystem error text, credentials and archive contents.
type Failure struct{ code string }

func (e *Failure) Error() string { return "backup worker failed: " + e.code }
func (e *Failure) Unwrap() error { return ErrExecution }
func captureFailure(err error) error {
	code := "capture_execution_failed"
	if errors.Is(err, workspace.ErrArchive) {
		code = "workspace_archive_rejected"
	} else if errors.Is(err, staging.ErrFile) {
		code = "staging_publication_failed"
	} else if errors.Is(err, staging.ErrBinding) {
		code = "staging_binding_rejected"
	}
	return &Failure{code: code}
}
func FailureCode(err error) string {
	var f *Failure
	if errors.As(err, &f) {
		return f.code
	}
	return "execution_unavailable"
}

type pendingControlFailure struct{ code string }

func (e pendingControlFailure) Error() string { return e.code }
func (e pendingControlFailure) Unwrap() error { return ErrNotReady }
func PendingControl(code string) error {
	switch code {
	case "job_binding_pending", "worker_mount_identity_pending", "worker_process_pending", "control_metadata_pending", "worker_construction_pending", "worker_job_pending", "worker_pod_pending", "worker_spec_pending", "worker_node_pending", "worker_mount_pending":
		return pendingControlFailure{code}
	default:
		return ErrNotReady
	}
}
