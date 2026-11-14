package systembackupexecution

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestSourceFactsFailureKeepsRefusalAndHidesPrivatePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-source-token")
	_, err := ProduceOriginalBootstrapSourceRegistries(context.Background(), nil, nil, install.EnrollmentPin{}, path, "")
	var failure *WriterAPIReadFailure
	if !errors.As(err, &failure) || !errors.Is(err, install.ErrInstall) || failure.Step != "facts_selection" || failure.Kind != "SourceFacts" || strings.Contains(err.Error(), path) {
		t.Fatal("source facts rejection lost bounded diagnostics or exposed private input", err)
	}
}
