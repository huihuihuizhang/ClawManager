package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestMinIODeliveryCannotCreateOriginalAuthorityOrUseUnpinnedCopy(t *testing.T) {
	if _, e := ProduceFormalMinIOMaterialDelivery(context.Background(), nil, nil, install.EnrollmentPin{}, "", "", "", "", "", "", FormalMinIOMaterialDeliveryOptions{}); e == nil {
		t.Fatal("missing real installer accepted")
	}
	if InstallFormalMinIOFiles(context.Background(), "") == nil {
		t.Fatal("unbound init manifest accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if InstallFormalMinIOFiles(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == nil {
		t.Fatal("cancelled installer context accepted")
	}
}
