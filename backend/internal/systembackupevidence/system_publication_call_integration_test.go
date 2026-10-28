package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func newDSystemPublicationFixture(t *testing.T, configure func(*dIntegrationFixture, *systemSTSTestFixture)) (*dIntegrationFixture, *systemSTSTestFixture, *pd.Execution, *pd.PublicationClaim) {
	t.Helper()
	f := newDIntegrationFixture(t)
	f.advance("pending")
	x := newSystemSTSTestFixture(t, "")
	x.c.History, x.c.Channel = f.history, f.channel
	x.c.SubjectIdentityHash = string(f.command.ActorIdentityHash)
	var domain pd.DomainRecord
	f.load("system_backup_producer_domains", &domain)
	x.c.IssuerIdentityHash = string(domain.IssuerIdentityHash)
	x.c.STS.Store.Root = f.channel.Root
	x.c.STS.Store.Installation = string(f.command.Scope.Installation)
	x.c.STS.Store.Identity = f.channel.Store.Identity
	x.c.STS.Store.Version = f.channel.Store.Version
	if configure != nil {
		configure(f, x)
	}
	f.policy = pd.Hash(SystemSTSPolicyHash(x.c))
	f.claimRequest.PolicyHash = f.policy
	f.claimRequest.RefsVersionHash = f.policy
	callEnv, err := NewSystemPublicationCallEnvironment(&dIntegrationExecution{f}, f.prepared, f.channel, f.history)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := pd.NewExecution(f.lifecycle, callEnv)
	if err != nil {
		t.Fatal(err)
	}
	claimEnv, err := NewSystemClaimEnvironment(&dIntegrationClaim{f: f}, f.prepared, f.channel, f.history)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := pd.NewPublication(execution, claimEnv)
	if err != nil {
		t.Fatal(err)
	}
	// TLS/STS fixture construction above can outlive a capacity sample. The
	// in-memory SQL clock otherwise stays at fixture creation while D's real
	// post-commit clock advances. Sample actual time before this NEW admission;
	// keep every original claim/budget/owner deadline unchanged. This mirrors
	// the existing fresh SQL sample before FinishPublication, not a lease refresh.
	f.d.now = time.Now().UTC().Truncate(time.Microsecond)
	claim, err := publication.ClaimPublication(context.Background(), f.handle, f.claimRequest)
	if err != nil || claim == nil {
		t.Fatal("D claim", err)
	}
	return f, x, execution, claim
}

func TestSystemPublicationClaimAfterSlowLocalSetup(t *testing.T) {
	var originalClaim, originalBudget, originalOwner pd.Timestamp
	f, _, _, claim := newDSystemPublicationFixture(t, func(f *dIntegrationFixture, _ *systemSTSTestFixture) {
		originalClaim, originalBudget, originalOwner = f.claimRequest.ExpiresAt, f.claimRequest.BudgetUntil, f.history.OwnerWriteExpiresAt
		// Reproduce setup longer than the existing five-second sample freshness.
		// No provider call or claim transaction has begun during this delay.
		time.Sleep(6 * time.Second)
	})
	if claim == nil || f.claimRequest.ExpiresAt != originalClaim || f.claimRequest.BudgetUntil != originalBudget || f.history.OwnerWriteExpiresAt != originalOwner {
		t.Fatal("setup refresh changed original execution deadlines")
	}
}

type publicationCountingAuthority struct {
	delegate pd.ExecutionEnvironment
	calls    int
}

func (a *publicationCountingAuthority) PrepareExecution(ctx context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	a.calls++
	return a.delegate.PrepareExecution(ctx, b)
}

func TestSystemPublicationCallPreflightBeforeAuthority(t *testing.T) {
	f := newDIntegrationFixture(t)
	f.advance("pending")
	a := &publicationCountingAuthority{delegate: &dIntegrationExecution{f}}
	env, err := NewSystemPublicationCallEnvironment(a, f.prepared, f.channel, f.history)
	if err != nil {
		t.Fatal(err)
	}
	b := pd.ExecutionBinding{
		Kind: "call", Scope: f.history.Scope, Subject: f.command.ActorIdentityHash,
		GrantID: f.history.GrantID, GrantGeneration: f.history.GrantGeneration, GrantVersion: "1", RunID: f.history.RunID,
		Call: pd.CallRequest{Purpose: "sts", EvidenceID: f.history.Evidence.EvidenceID,
			RefIdentityHash: f.history.Evidence.WriteIdentityHash, RefVersion: pd.ProviderVersion(f.history.Evidence.WriteRefVersion),
			PolicyHash: f.policy, BudgetUntil: f.claimRequest.BudgetUntil},
		Claim: &pd.ClaimBinding{EvidenceID: f.history.Evidence.EvidenceID, EvidenceVersion: "1",
			ManifestHash: f.history.Evidence.ManifestHash, Owner: f.claimRequest.Nonce,
			ExpiresAt: f.claimRequest.ExpiresAt, PolicyHash: f.policy, RefsVersionHash: f.policy},
	}
	if got, err := env.PrepareExecution(context.Background(), b); err != nil || got.Session == nil || a.calls != 1 {
		t.Fatal("exact STS call did not reach authority", err)
	}
	b.Call.Purpose = "publish"
	b.Call.RefIdentityHash = f.history.Evidence.StoreIdentityHash
	b.Call.RefVersion = pd.ProviderVersion(f.history.Evidence.StoreRefVersion)
	if got, err := env.PrepareExecution(context.Background(), b); err != nil || got.Session == nil || a.calls != 2 {
		t.Fatal("exact publish call did not reach authority", err)
	}
	wrong := []struct {
		name   string
		change func(*pd.ExecutionBinding)
	}{
		{"kind", func(x *pd.ExecutionBinding) { x.Kind = "observation" }},
		{"grant", func(x *pd.ExecutionBinding) { x.GrantID = "other-grant" }},
		{"generation", func(x *pd.ExecutionBinding) { x.GrantGeneration = "2" }},
		{"ref_identity", func(x *pd.ExecutionBinding) { x.Call.RefIdentityHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"ref_version", func(x *pd.ExecutionBinding) { x.Call.RefVersion = "other" }},
		{"policy", func(x *pd.ExecutionBinding) { x.Call.PolicyHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"claim_evidence", func(x *pd.ExecutionBinding) { x.Claim.EvidenceID = "other-evidence" }},
		{"claim_manifest", func(x *pd.ExecutionBinding) { x.Claim.ManifestHash = pd.Hash(strings.Repeat("f", 64)) }},
		{"observation", func(x *pd.ExecutionBinding) { x.Observation = &pd.ObservationRequest{} }},
		{"probe_hash", func(x *pd.ExecutionBinding) { v := pd.Hash(strings.Repeat("f", 64)); x.ProbeSnapshotHash = &v }},
	}
	for _, tc := range wrong {
		t.Run(tc.name, func(t *testing.T) {
			x := b
			claim := *b.Claim
			x.Claim = &claim
			tc.change(&x)
			if got, err := env.PrepareExecution(context.Background(), x); err == nil || got.Session != nil || a.calls != 2 {
				t.Fatal("invalid publication binding reached authority", err)
			}
		})
	}
}

// D mints the claim and both call snapshots. A's adapter reads actual SQL
// registry/chunks on each call and again during D's final guard.
func TestSystemPublicationCallActualDClaimAndSnapshots(t *testing.T) {
	f, x, execution, claim := newDSystemPublicationFixture(t, nil)
	sts, err := NewSystemExecutionSTSCredentials(context.Background(), execution, f.handle, claim, f.prepared, x.c, x.verifier)
	if err != nil {
		t.Fatal("D sts/publish snapshots", err)
	}
	defer sts.Close()
	if sts.views[0].Binding.Call.Purpose != "sts" || sts.views[1].Binding.Call.Purpose != "publish" || len(sts.views) != 2 {
		t.Fatal("missing original D snapshots")
	}
	if _, err := sts.Resolve(context.Background(), S3Scope{Ref: sts.original.record.Ref, Operation: S3Stat}); err != nil {
		t.Fatal("STS exchange under D snapshots", err)
	}
	f.d.chunks[0]["gcm_nonce"] = []byte(strings.Repeat("x", 12))
	if err := sts.recheck(context.Background()); err == nil {
		t.Fatal("changed A chunk must revoke the original D snapshots")
	}
}

func TestSystemPublisherActualDClaimToReceipt(t *testing.T) {
	var present, puts bool
	f, x, execution, claim := newDSystemPublicationFixture(t, func(f *dIntegrationFixture, x *systemSTSTestFixture) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !verifyS3Wire(r) || r.URL.Path != "/test-bucket/"+string(f.history.RelativeKey) {
				t.Error("unexpected signed object request")
				w.WriteHeader(http.StatusForbidden)
				return
			}
			switch r.Method {
			case http.MethodHead:
				if !present {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				digest, _ := hex.DecodeString(string(f.history.Evidence.ObjectHash))
				w.Header().Set("X-Amz-Version-Id", "Exact.Version/1")
				w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
				w.Header().Set("Content-Length", string(f.history.Evidence.ObjectBytes))
			case http.MethodPut:
				puts = true
				body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(f.ciphertext)+1)))
				if err != nil || !bytes.Equal(body, f.ciphertext) || r.Header.Get("If-None-Match") != "*" || present {
					t.Error("unexpected conditional PUT")
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				present = true
			default:
				t.Error("unexpected object method", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		t.Cleanup(server.Close)
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		x.c.STS.Store.Endpoint, x.c.STS.Store.CAPEM, x.c.STS.Store.CASHA256 = server.URL, ca, hash(ca)
	})
	f.acceptPublishedFinish = true
	publisher, err := NewSystemPublisher(context.Background(), execution, f.handle, claim, f.prepared, x.c, x.verifier, &systemPublishFixture{}, &systemPublishTestProof{}, &dIntegrationFinish{f: f})
	if err != nil {
		t.Fatal("publisher", err)
	}
	defer publisher.Close()
	finish, err := publisher.Publish(context.Background(), source(f.ciphertext))
	if err != nil || finish.State != "ready" || !present || !puts {
		t.Fatal("D claim through actual signed PUT and FinishPublication", finish, err)
	}
	if err := f.step("result"); err != nil {
		t.Fatal("CommitResult", err)
	}
	var run pd.RunRecord
	f.load("system_backup_producer_runs", &run)
	if run.State != "committed" || f.d.row["storage_state"] != "ready" || f.d.row["storage_immutable_version"] != "Exact.Version/1" {
		t.Fatal("publication and receipt did not commit")
	}
}
