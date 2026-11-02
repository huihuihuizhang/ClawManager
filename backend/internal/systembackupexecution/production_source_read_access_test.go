package systembackupexecution

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSourceMetadataReadAccessCannotSubstituteAuthority(t *testing.T) {
	s, other := &DeploymentService{}, &DeploymentService{}
	o, otherOwner := &PublicJobOwner{}, &PublicJobOwner{}
	capture := &originalSourceMetadataAuthority{service: s, owner: o}
	observation := &sourceSQLObservation{delegation: &sourceMetadataDelegation{service: s, owner: o}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, access := range []sourceMetadataReadAccess{
		{}, captureMetadataReadAccess(nil), (*sourceSQLObservation)(nil).metadataReadAccess(),
		{service: s, owner: o},
		{capture: capture, observation: observation, service: s, owner: o},
		{capture: capture, service: other, owner: o},
		{capture: capture, service: s, owner: otherOwner},
		{observation: observation, service: other, owner: o},
		{observation: observation, service: s, owner: otherOwner},
	} {
		if access.Recheck(ctx) == nil {
			t.Fatal("invalid/canceled metadata origin accepted")
		}
		if _, err := access.openClients(ctx); err == nil {
			t.Fatal("metadata client opened without a real live origin")
		}
		if _, _, err := access.resourceMetadata(ctx, nil); err == nil {
			t.Fatal("resource read accepted without real metadata clients")
		}
		if _, err := access.skillObjectMetadata(ctx, nil, nil); err == nil {
			t.Fatal("object read accepted without actual SQL skills/source client")
		}
	}
}

type countingMetadataReadTransport struct{ calls int }

func (c *countingMetadataReadTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	c.calls++
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("successful in-memory source response")), Request: request}, nil
}

func TestSourceMetadataTransportRejectsMissingOriginBeforeNetwork(t *testing.T) {
	for _, authority := range []sourceMetadataReadAuthority{nil, (*originalSourceMetadataAuthority)(nil), sourceMetadataReadAccess{}} {
		base := &countingMetadataReadTransport{}
		request, err := http.NewRequestWithContext(context.Background(), "GET", "https://source.invalid/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if response, err := (sourceMetadataTransport{authority: authority, host: "source.invalid", base: base}).RoundTrip(request); err == nil || response != nil || base.calls != 0 {
			t.Fatal("request without actual original authority reached network")
		}
	}
	request, err := http.NewRequestWithContext(context.Background(), "GET", "https://source.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := (sourceMetadataTransport{authority: sourceMetadataReadAccess{}, host: "source.invalid", base: nil}).RoundTrip(request); err == nil || response != nil {
		t.Fatal("nil base transport did not fail closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := (*DeploymentService)(nil).ObserveSourceMetadata(ctx); err == nil {
		t.Fatal("nil service produced a taskless source observation")
	}
	if (SourceMetadataObservation{}).SHA256() != "" || !(SourceMetadataObservation{}).ValidUntil().IsZero() {
		t.Fatal("empty observation manufactured facts")
	}
}
