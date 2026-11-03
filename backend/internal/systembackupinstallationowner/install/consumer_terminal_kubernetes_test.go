package install

import (
	"context"
	"os"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTerminalKubernetesUsesSamePinnedConsumerWithoutPreparingOwners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newCaptureConsumerFixture(t, ctx)
	beforeAPI, beforeSQL, beforeSigns := f.apiCalls.Load(), f.f.s.auth.queries, f.f.signs.Load()
	client, err := f.source.OpenTerminalKubernetes(ctx)
	if err != nil || client == nil || f.apiCalls.Load() != beforeAPI || f.f.s.auth.queries != beforeSQL || f.f.signs.Load() != beforeSigns {
		t.Fatal("local client construction prepared an owner or performed API/SQL/signing", err)
	}
	actual, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || actual.Status.UserInfo.Username != f.f.i.plan.OwnerUsername || f.f.s.auth.queries != beforeSQL {
		t.Fatal("client did not reach the same actual pinned original TLS peer", err)
	}
	if err := os.WriteFile(f.source.sourcePinFile, []byte("invalid-independent-pin"), 0600); err != nil {
		t.Fatal(err)
	}
	beforeAPI = f.apiCalls.Load()
	if client, err := f.source.OpenTerminalKubernetes(ctx); err == nil || client != nil || f.apiCalls.Load() != beforeAPI || f.f.s.auth.queries != beforeSQL {
		t.Fatal("changed original pin performed owner I/O or constructed a client")
	}
}
