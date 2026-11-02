package systembackupkekadapter

import (
	"context"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

func TestPublisherSourceRecoveryBridgeRejectsMissingOriginalFactoryAndScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		factory *PublisherVerifierFactory
		ctx     context.Context
		part    string
	}{
		{"nil_factory", nil, context.Background(), ce.Part},
		{"nil_context", new(PublisherVerifierFactory), nil, ce.Part},
		{"canceled", new(PublisherVerifierFactory), ctx, ce.Part},
		{"no_part", new(PublisherVerifierFactory), context.Background(), ""},
		{"business_part", new(PublisherVerifierFactory), context.Background(), "workspace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, access, err := tc.factory.OpenSourceRecovery(tc.ctx, security.PublisherCaptureScope{Part: tc.part})
			if err == nil || source != nil || access != nil {
				t.Fatal("missing real original scope manufactured source recovery")
			}
		})
	}
}
