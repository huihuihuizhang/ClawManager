package systembackupexecution

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"testing"
)

func TestPublicationRuntimeProducerRefusesMissingActualAuthority(t *testing.T) {
	if r, e := ProducePublicationRuntimeMaterials(context.Background(), nil, nil, nil, nil, install.EnrollmentPin{}, PublicationRuntimeMaterialInputs{}); e == nil || r.Version != "" {
		t.Fatal("missing original sources emitted runtime receipt")
	}
}
