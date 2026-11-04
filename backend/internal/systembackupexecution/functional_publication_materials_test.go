package systembackupexecution

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"testing"
)

func TestFunctionalPublicationProducerNeedsActualInstallationOwner(t *testing.T) {
	for name, ctx := range map[string]context.Context{"nil": nil, "unbounded": context.Background()} {
		t.Run(name, func(t *testing.T) {
			receipt, err := ProduceFunctionalPublicationMaterials(ctx, nil, nil, install.EnrollmentPin{}, FunctionalPublicationMaterialInputs{})
			if err == nil || receipt.PublicationPolicy.File != "" {
				t.Fatal("missing actual owner emitted policy material")
			}
		})
	}
}
