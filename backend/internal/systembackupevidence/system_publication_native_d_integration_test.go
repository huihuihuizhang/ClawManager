package systembackupevidence

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Models only the remaining independent deployment authority. The concrete C
// wrapper authenticates the fresh original native readback, not this fixture.
type nativeReadbackDTestAuthority struct{ dIntegrationFinish }

func (a *nativeReadbackDTestAuthority) PrepareFinishAuthority(ctx context.Context, b pd.FinishBinding, r Record) (SystemFinishAuthoritySession, *time.Time, error) {
	if b.Scope != a.f.history.Scope || b.RunID != a.f.history.RunID || b.Request.ObjectHash != a.f.history.Evidence.ObjectHash || b.Request.ObjectBytes != a.f.history.Evidence.ObjectBytes {
		return nil, nil, pd.ErrGuardRequired
	}
	a.f.finishRequest = b.Request
	a.f.d.now = time.Now().UTC().Truncate(time.Microsecond)
	return a.dIntegrationFinish.PrepareFinishAuthority(ctx, b, r)
}

func TestVerifiedSystemPublisherOriginalDClaimReadbackAndFinishTransactionModel(t *testing.T) {
	heads := 0
	f, x, execution, claim := newDSystemPublicationFixture(t, func(f *dIntegrationFixture, x *systemSTSTestFixture) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !verifyS3Wire(r) || r.Method != http.MethodHead || r.URL.Path != "/test-bucket/"+string(f.history.RelativeKey) {
				t.Error("verifier used non-original or mutating native request")
				w.WriteHeader(403)
				return
			}
			heads++
			digest, _ := hex.DecodeString(string(f.history.Evidence.ObjectHash))
			w.Header().Set("X-Amz-Version-Id", "Exact.Version/1")
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
			w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
			w.Header().Set("Content-Length", string(f.history.Evidence.ObjectBytes))
		}))
		t.Cleanup(server.Close)
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		x.c.STS.Store.Endpoint, x.c.STS.Store.CAPEM, x.c.STS.Store.CASHA256 = server.URL, ca, hash(ca)
	})
	publisher, e := NewVerifiedSystemPublisher(context.Background(), execution, f.handle, claim, f.prepared, x.c, x.verifier, &systemPublishFixture{}, &nativeReadbackDTestAuthority{dIntegrationFinish{f: f}})
	if e != nil {
		t.Fatal("original opaque D claim constructor", e)
	}
	defer publisher.Close()
	result, e := publisher.Publish(context.Background(), source(f.ciphertext))
	if e != nil || result.State != "ready" || result.ImmutableVersion == nil || *result.ImmutableVersion != "Exact.Version/1" || heads != 2 {
		t.Fatal("publisher HEAD plus independent C HEAD and original Finish transaction", e, result, heads)
	}
	if e := f.step("result"); e != nil {
		t.Fatal("separate original CommitResult", e)
	}
	var run pd.RunRecord
	f.load("system_backup_producer_runs", &run)
	if run.State != "committed" || f.d.row["storage_state"] != "ready" {
		t.Fatal("real original model result/registry not committed")
	}
}
