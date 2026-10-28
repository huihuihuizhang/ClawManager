package systembackupevidence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestRecoveryManagerPeerIsSeparateAndRequestBound(t *testing.T) {
	workload, fixture, c := systemPeerFixture(t)
	mapping := RecoveryManagerPeerConfig{
		Scope: c.Scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256,
		CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt,
	}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, endRequest := context.WithCancel(fixture.request.Context())
	defer endRequest()
	fixture.request = fixture.request.WithContext(requestCtx)
	peer, err := auth.AuthenticateRequest(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := auth.Check(context.Background(), peer, c.Scope, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil || facts.Scope != c.Scope || facts.IdentityHash == workload.workload ||
		!digestPattern.MatchString(facts.IdentityHash) || !digestPattern.MatchString(facts.CredentialBindingHash) ||
		facts.IssuerIdentityHash != mapping.IssuerIdentityHash {
		t.Fatal("independent management identity rejected", err)
	}
	if _, err := json.Marshal(peer); !errors.Is(err, ErrAuth) {
		t.Fatal("management peer serialized", err)
	}
	if err := json.Unmarshal([]byte(`{}`), peer); !errors.Is(err, ErrAuth) {
		t.Fatal("management peer minted from JSON", err)
	}
	other := c.Scope
	other.Database = pd.Database("other")
	if _, err := auth.Check(context.Background(), peer, other, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("cross-scope management identity accepted", err)
	}
	if _, err := auth.Check(context.Background(), &RecoveryManagerPeer{}, c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("unbound management peer accepted", err)
	}
	endRequest()
	if _, err := auth.Check(context.Background(), peer, c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("completed management request reused", err)
	}
	auth.Close()
}

func TestRecoveryManagerPeerRejectsInvalidMappingAndClosure(t *testing.T) {
	_, fixture, c := systemPeerFixture(t)
	mapping := RecoveryManagerPeerConfig{
		Scope: c.Scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256,
		CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt,
	}
	bad := mapping
	bad.ClientCASHA256 = strings.Repeat("0", 64)
	if _, err := NewRecoveryManagerPeerAuthenticator(bad); err != ErrInvalid {
		t.Fatal("wrong management CA pin accepted", err)
	}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := auth.AuthenticateRequest(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	auth.Close()
	if _, err := auth.Check(context.Background(), peer, c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("closed management mapping accepted", err)
	}
}
