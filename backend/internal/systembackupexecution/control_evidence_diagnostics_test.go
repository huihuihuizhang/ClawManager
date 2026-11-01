package systembackupexecution

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func TestControlEvidenceDenyDiagnosticOmitsRequestAndToken(t *testing.T) {
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	secret := "PRIVATE_BODY_TOKEN_AND_QUERY_MUST_NOT_APPEAR"
	request := httptest.NewRequest(http.MethodPost, "https://localhost/control-evidence?token="+secret, strings.NewReader(secret))
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	var service *DeploymentService
	service.serveControlEvidenceSource(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=controller-pull-input-materials-tls sentinel=ce_rejected") {
		t.Fatal("diagnostic changed denial or exposed request material")
	}
}

func TestControlEvidenceBindDiagnosticFormatterOmitsAuthorityAndContext(t *testing.T) {
	var output bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(0)
	defer log.SetOutput(previous)
	defer log.SetFlags(flags)
	secret := "PRIVATE_SQL_ARGS_BODY_GRANT_TOKEN_MUST_NOT_APPEAR"
	type privateKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), privateKey{}, secret))
	cancel()
	guard, err := (c.SQLExecutionAuthority{}).BindObserved(ctx, nil, d.Authority{InstallationID: secret, TaskPublicID: secret, ClaimOwner: secret}, logOriginalExecutionBindDiagnostic)
	if err != c.ErrExecutionAuthority || guard != nil || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "boundary=bind-dependencies class=context_canceled sql_number=0 sql_state=") {
		t.Fatal("formatter leaked private inputs or changed rejection")
	}
}
