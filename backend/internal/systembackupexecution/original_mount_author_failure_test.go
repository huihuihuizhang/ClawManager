package systembackupexecution

import (
	"context"
	"errors"
	"strings"
	"testing"

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
