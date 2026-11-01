package systembackupexecution

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
