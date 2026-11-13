package systembackupexecution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestOriginalMountFailurePreservesCauseWithoutLeaking(t *testing.T) {
	cause := &InstanceMountInputError{Code: "missing", InstanceID: 7, MountID: "secret-value"}
	err := &OriginalMountAuthorFailure{Phase: "mount_scope", cause: cause}
	var recovered *InstanceMountInputError
	if !errors.As(err, &recovered) || recovered != cause || strings.Contains(err.Error(), "secret-value") {
		t.Fatal("phase error leaked cause or lost typed coverage failure")
	}
}

func TestOriginalMountFailureRejectsInvalidInputsWithPhase(t *testing.T) {
	_, err := ProduceOriginalInstanceMountMaterials(context.Background(), nil, nil, install.EnrollmentPin{}, "", "", "", "", "")
	var failure *OriginalMountAuthorFailure
	if !errors.As(err, &failure) || failure.Phase != "inputs" || !errors.Is(err, install.ErrInstall) {
		t.Fatal("original input rejection lost its stage or cause")
	}
}

func TestOriginalMountFailureExposesBoundedDeadlineReason(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := ProduceOriginalInstanceMountMaterials(ctx, nil, nil, install.EnrollmentPin{}, "", "", "", "", "")
	var failure *WriterAPIReadFailure
	if !errors.As(err, &failure) || failure.Reason != "deadline" || failure.Step != "inputs" || failure.Kind != "MountMaterials" || !errors.Is(err, install.ErrInstall) {
		t.Fatal("deadline lost its bounded diagnostic or original refusal", err)
	}
	inner := &InstanceMountInputError{Code: "missing", InstanceID: 7, MountID: "fixture-private-path"}
	wrapped := writerAPIReadFailure(inner, ctx, "mount_scope", "MountMaterials", inner)
	var recovered *InstanceMountInputError
	if !errors.As(wrapped, &recovered) || recovered != inner || strings.Contains(wrapped.Error(), "fixture-private-path") {
		t.Fatal("deadline diagnostic lost mount details or leaked its cause")
	}
}
