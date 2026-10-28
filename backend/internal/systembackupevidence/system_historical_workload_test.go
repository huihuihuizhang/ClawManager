package systembackupevidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestSystemHistoricalWorkloadIntentExactEvidenceAndScope(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	peer, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	const evidenceID = "sev_11111111-2222-4333-8444-555555555555"
	intent, err := newSystemHistoricalWorkloadIntent(context.Background(), a, peer, evidenceID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts, binding, err := intent.check(context.Background(), c.Scope, evidenceID, now)
	if err != nil || facts.Scope != c.Scope || facts.ActorIdentityHash != a.actor || !digestPattern.MatchString(binding) {
		t.Fatal("valid workload intent rejected", err)
	}
	for _, change := range []func(*SystemPeerFacts){
		func(f *SystemPeerFacts) { f.SubjectHash = hash([]byte("different-subject")) },
		func(f *SystemPeerFacts) { f.ClientCASHA256 = hash([]byte("different-ca")) },
		func(f *SystemPeerFacts) { f.CertificateSHA256 = hash([]byte("different-certificate")) },
	} {
		modified := facts
		change(&modified)
		if systemHistoricalWorkloadBinding(modified, evidenceID) == binding {
			t.Fatal("historical binding ignored current identity pin")
		}
	}
	if _, _, err := intent.check(context.Background(), c.Scope, "sev_aaaaaaaa-2222-4333-8444-555555555555", now); err != ErrAuth {
		t.Fatal("intent reused for another evidence", err)
	}
	otherScope := pd.Scope{ServerUUID: c.Scope.ServerUUID, Database: "other", Installation: c.Scope.Installation}
	if _, _, err := intent.check(context.Background(), otherScope, evidenceID, now); err != ErrAuth {
		t.Fatal("intent reused across scope", err)
	}
	other, err := newSystemHistoricalWorkloadIntent(context.Background(), a, peer, "sev_aaaaaaaa-2222-4333-8444-555555555555")
	if err != nil || other.binding == binding {
		t.Fatal("different evidence did not change binding", err)
	}
	if f.db.begins != 0 {
		t.Fatal("workload intent unexpectedly performed SQL")
	}
}

func TestSystemHistoricalWorkloadIntentCannotBeMintedOrOutlivePeer(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	peer, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	const evidenceID = "sev_11111111-2222-4333-8444-555555555555"
	for _, tc := range []struct {
		name  string
		auth  *SystemPeerAuthenticator
		proof *SystemPeer
		id    string
	}{
		{"nil_auth", nil, peer, evidenceID},
		{"nil_peer", a, nil, evidenceID},
		{"invalid_evidence", a, peer, "invalid"},
		{"zero_peer", a, &SystemPeer{}, evidenceID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if intent, err := newSystemHistoricalWorkloadIntent(context.Background(), tc.auth, tc.proof, tc.id); err != ErrAuth || intent != nil {
				t.Fatal("invalid workload intent minted", err)
			}
		})
	}
	intent, err := newSystemHistoricalWorkloadIntent(context.Background(), a, peer, evidenceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(intent); err == nil {
		t.Fatal("intent serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), intent); err != ErrAuth {
		t.Fatal("JSON minted intent", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := intent.check(ctx, c.Scope, evidenceID, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("canceled operation accepted", err)
	}
	if _, _, err := intent.check(context.Background(), c.Scope, evidenceID, time.Time{}); err != ErrAuth {
		t.Fatal("invalid DB time accepted", err)
	}
	requestCtx, endRequest := context.WithCancel(f.request.Context())
	peer.request = requestCtx
	endRequest()
	if _, _, err := intent.check(context.Background(), c.Scope, evidenceID, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("finished request proof reused", err)
	}
}

func TestSystemHistoricalWorkloadIntentVerifierClosure(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	peer, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	const evidenceID = "sev_11111111-2222-4333-8444-555555555555"
	intent, err := newSystemHistoricalWorkloadIntent(context.Background(), a, peer, evidenceID)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if _, _, err := intent.check(context.Background(), c.Scope, evidenceID, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("closed verifier accepted workload intent", err)
	}
}
