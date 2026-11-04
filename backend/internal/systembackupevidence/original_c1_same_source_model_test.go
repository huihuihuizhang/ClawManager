package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	"clawreef/internal/systembackupsecurity"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// SQL/Kubernetes/provider responses are MODELS, not deployment evidence. The
// concrete public SDK, real TLS Transit/channel, native publication verifier,
// tracked source, immutable ciphertext and original handle are the SAME chain.
// No source/proof struct is constructed or decoded by the test.
func prepareSameOriginalC1(t *testing.T, ctx context.Context, f *dIntegrationFixture) {
	x, simulated := systemExecutionFixture(t, "")
	c := simulated.c
	c.Scope, c.RunID, c.InputHash = f.history.Scope, f.history.RunID, string(f.history.InputHash)
	c.SubjectIdentityHash = string(f.command.ActorIdentityHash)
	var domain pd.DomainRecord
	f.load("system_backup_producer_domains", &domain)
	c.IssuerIdentityHash = string(domain.IssuerIdentityHash)
	c.Identity = f.prepared.Manifest().Identity
	c.Content.Installation, c.Content.EvidenceID, c.Content.Classification = c.Identity.Installation, c.Identity.ID, c.Identity.Classification
	c.Content.Role, c.Content.ProviderIdentity = string(f.command.Target.Role), string(f.command.Target.IdentityHash)
	c.Content.ProviderVersion, c.Content.ScopeHash = string(f.command.Target.RefVersion), string(f.command.Target.ProbeScopeHash)
	c.EvaluatorProfileHash = string(f.command.Target.EvaluatorProfileHash)
	c.Content.ValidUntil, _ = f.history.ObservationExpiresAt.Time()
	c.Wrap.Transit.Installation = c.Identity.Installation
	var document systembackupsecurity.CapabilityEvidence
	if err := json.Unmarshal(x.body, &document); err != nil {
		t.Fatal(err)
	}
	document.Role, document.IdentityHash, document.RefVersion, document.ScopeHash = c.Content.Role, c.Content.ProviderIdentity, c.Content.ProviderVersion, c.Content.ScopeHash
	for n := range document.Capabilities {
		if n == 0 {
			document.Capabilities[n].Code = "conditional_create"
		} else {
			document.Capabilities[n].Code = "checksum_bound_request"
		}
		document.Capabilities[n].RequestScopeHash = c.Content.ScopeHash
		document.Capabilities[n].ExpiresAt = c.Content.ValidUntil.Add(-10 * time.Second).UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	c.Identity.ContentHash, c.Identity.ContentSize = hash(body), int64(len(body))
	f.policy = pd.Hash(SystemExecutionPreparationPolicyHash(c))
	env, err := NewSystemPreparationCallEnvironment(&dIntegrationExecution{f}, c)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := pd.NewExecution(f.lifecycle, env)
	if err != nil {
		t.Fatal(err)
	}
	preparer, err := NewSystemExecutionPreparer(ctx, execution, f.handle, c)
	if err != nil {
		t.Fatal("original SDK preparation", err)
	}
	t.Cleanup(preparer.Close)
	var ciphertext bytes.Buffer
	f.prepared, err = preparer.Prepare(ctx, c.Identity, source(body), &ciphertext)
	if err != nil {
		t.Fatal("original native Wrap", err)
	}
	f.ciphertext = bytes.Clone(ciphertext.Bytes())
	if x.encrypts.Load() != 1 || bytes.Contains(f.ciphertext, body) {
		t.Fatal("no real native encryption")
	}
	binding, err := f.prepared.PendingProducerBinding(f.channel)
	if err != nil {
		t.Fatal(err)
	}
	// Native preparation changed the capability body checksum. The object key
	// includes that checksum, so derive the exact native key from this SAME
	// Prepared rather than retaining the old generic fixture's relative key.
	relativeKey, err := keyFor(f.channel.Root, f.prepared.Manifest().Identity)
	if err != nil {
		t.Fatal("original native derived object key", err)
	}
	f.history.RelativeKey = pd.RelativeKey(relativeKey)
	f.history.Evidence = binding
	f.pendingRequest.History, f.pendingRequest.PolicyHash = f.history, f.policy
	f.resultRequest.Evidence = binding
	version := pd.Text("Exact.Version/1")
	f.resultRequest.Evidence.ImmutableVersion = &version
	f.finishRequest.ObjectHash, f.finishRequest.ObjectBytes = binding.ObjectHash, binding.ObjectBytes
	var checkedHistory pd.HistoricalBindingRecord
	decodeErr := pd.DecodeRecord(canonical(f.history), &checkedHistory)
	_, historyHashErr := pd.PendingHistoryHash(f.history)
	if decodeErr != nil || historyHashErr != nil || f.history.Evidence.ImmutableVersion != nil {
		t.Fatalf("native historical binding prerequisites decode=%v hash=%v immutable-nil=%t original-public-record=%s", decodeErr, historyHashErr, f.history.Evidence.ImmutableVersion == nil, canonical(f.history))
	}
	created, createdErr := checkedHistory.CreatedAt.Time()
	expires, expiresErr := checkedHistory.RetentionExpiresAt.Time()
	owner, ownerErr := checkedHistory.OwnerWriteExpiresAt.Time()
	observation, observationErr := checkedHistory.ObservationExpiresAt.Time()
	if createdErr != nil || expiresErr != nil || ownerErr != nil || observationErr != nil || expires.Before(observation) || string(checkedHistory.Scope.Installation) != f.prepared.Manifest().Identity.Installation {
		t.Fatalf("native historical time/install prerequisites errors=%v/%v/%v/%v created=%s expires=%s owner=%s observation=%s same-installation=%t", createdErr, expiresErr, ownerErr, observationErr, created, expires, owner, observation, string(checkedHistory.Scope.Installation) == f.prepared.Manifest().Identity.Installation)
	}
	pe, err := NewSystemPendingEnvironment(&dIntegrationPending{f: f}, f.prepared, f.channel, f.history)
	if err != nil {
		t.Fatal("original native pending environment", err)
	}
	f.pending, err = pd.NewPending(execution, pe)
	if err != nil {
		t.Fatal(err)
	}
	f.d.now = time.Now().UTC().Truncate(time.Microsecond)
	if _, err = f.pending.AdmitPending(ctx, f.handle, f.pendingRequest); err != nil {
		t.Fatal("original pending", err)
	}
}

func sameOriginalC1Gateway(t *testing.T, ctx context.Context, f *dIntegrationFixture) (*OriginalC1OwnerChannel, SystemSTSPolicy, *int) {
	t.Helper()
	var mu sync.Mutex
	present, puts := false, 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(403)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/test-bucket" {
			if _, ok := r.URL.Query()["versioning"]; ok {
				io.WriteString(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
				return
			}
			if _, ok := r.URL.Query()["versions"]; ok && !present {
				io.WriteString(w, `<ListVersionsResult><Name>test-bucket</Name><Prefix>`)
				_ = xml.EscapeText(w, []byte(r.URL.Query().Get("prefix")))
				io.WriteString(w, `</Prefix><IsTruncated>false</IsTruncated></ListVersionsResult>`)
				return
			}
		}
		if r.URL.Path != "/test-bucket/"+string(f.history.RelativeKey) {
			w.WriteHeader(403)
			return
		}
		if r.Method == http.MethodPut {
			body, err := io.ReadAll(r.Body)
			if err != nil || present || r.Header.Get("If-None-Match") != "*" || !bytes.Equal(body, f.ciphertext) {
				w.WriteHeader(403)
				return
			}
			present = true
			puts++
		} else if r.Method != http.MethodHead {
			w.WriteHeader(403)
			return
		}
		if !present {
			w.WriteHeader(404)
			return
		}
		digest, _ := hex.DecodeString(string(f.history.Evidence.ObjectHash))
		w.Header().Set("X-Amz-Version-Id", "Exact.Version/1")
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
		w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(f.ciphertext)))
		}
	}))
	t.Cleanup(upstream.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	const ns, sa, pod = "c1-model", "producer", "producer-pod"
	kube := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: types.UID("namespace-uid")}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa, Namespace: ns, UID: types.UID("sa-uid")}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: ns, UID: types.UID("pod-uid")}, Spec: corev1.PodSpec{ServiceAccountName: sa, NodeName: "model-node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	)
	subject, audience := "system:serviceaccount:"+ns+":"+sa, "original-c1"
	raw, _ := json.Marshal(map[string]any{"iss": "https://c1.example", "sub": subject, "aud": audience, "exp": time.Now().Add(5 * time.Minute).Unix()})
	token := "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	kube.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		r := action.(ktesting.CreateAction).GetObject().(*authv1.TokenReview)
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{Authenticated: r.Spec.Token == token, Audiences: []string{audience}, User: authv1.UserInfo{Username: subject, UID: "sa-uid", Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-uid": {"pod-uid"}, "authentication.kubernetes.io/pod-name": {pod}}}}}, nil
	})
	store := S3Config{Endpoint: upstream.URL, Region: "us-east-1", Bucket: "test-bucket", Root: f.channel.Root, Installation: string(f.history.Scope.Installation), Identity: f.channel.Store.Identity, Version: f.channel.Store.Version, CAPEM: ca, CASHA256: hash(ca)}
	gateway, err := NewOriginalC1OwnerChannel(ctx, OriginalC1ChannelOwner{Upstream: store, AccessKey: []byte("owner-access"), SecretKey: []byte("owner-secret-with-32-model-bytes"), Kubernetes: kube, Namespace: ns, NamespaceUID: "namespace-uid", PodName: pod, PodUID: "pod-uid", ServiceAccount: sa, ServiceAccountUID: "sa-uid", Issuer: "https://c1.example", Audience: audience, RoleARN: "arn:aws:iam::123456789012:role/system-evidence"})
	if err != nil {
		t.Fatal("concrete native owner channel", err)
	}
	t.Cleanup(gateway.Close)
	config, profile := gateway.Config()
	var domain pd.DomainRecord
	f.load("system_backup_producer_domains", &domain)
	file := filepath.Join(t.TempDir(), "original-c1.jwt")
	if err := os.WriteFile(file, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(filepath.Dir(file), "authentication.jwt")
	authRaw, _ := json.Marshal(map[string]any{"iss": "https://c1.example", "sub": subject, "aud": "system-auth", "exp": time.Now().Add(5 * time.Minute).Unix()})
	if err := os.WriteFile(authFile, []byte("header."+base64.RawURLEncoding.EncodeToString(authRaw)+".signature"), 0600); err != nil {
		t.Fatal(err)
	}
	return gateway, SystemSTSPolicy{History: f.history, Channel: f.channel, SubjectIdentityHash: string(f.command.ActorIdentityHash), IssuerIdentityHash: string(domain.IssuerIdentityHash), Subject: subject, TokenFile: file, AuthenticationAudience: "system-auth", AuthenticationTokenFile: authFile, ProviderProfileHash: profile, STS: config}, &puts
}

// This bridge interprets SHARE reads in the existing SQL MODEL, without
// changing production SQL, lock order or transaction constructors.
type originalC1ReadModel struct{ *dIntegrationDB }

func (c originalC1ReadModel) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c originalC1ReadModel) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)" {
		return &systemPendingTestRows{cols: []string{"uuid", "db", "now"}, rows: [][]driver.Value{{string(c.scope.ServerUUID), string(c.scope.Database), c.now}}}, nil
	}
	return c.dIntegrationDB.QueryContext(ctx, strings.TrimSuffix(q, " FOR SHARE")+map[bool]string{true: " FOR UPDATE", false: ""}[strings.HasSuffix(q, " FOR SHARE")], args)
}

func TestOriginalC1SameHandleNativePublicationAndCommittedSourceModel(t *testing.T) {
	for _, failResult := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[failResult], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			f := newDIntegrationFixtureInContext(t, ctx, nil)
			originalHandle := f.handle
			prepareSameOriginalC1(t, ctx, f)
			gateway, policy, puts := sameOriginalC1Gateway(t, ctx, f)
			f.policy = pd.Hash(SystemSTSPolicyHash(policy))
			f.claimRequest.PolicyHash, f.claimRequest.RefsVersionHash = f.policy, f.policy
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
			f.d.now = time.Now().UTC().Truncate(time.Microsecond)
			claim, err := publication.ClaimPublication(ctx, f.handle, f.claimRequest)
			if err != nil {
				t.Fatal("original claim", err)
			}
			profile, absence, err := gateway.NewProfileVerifier(ctx, execution, f.handle, claim, f.prepared, policy)
			if err != nil {
				t.Fatal("production profile constructor", err)
			}
			publisher, err := NewVerifiedSystemPublisher(ctx, execution, f.handle, claim, f.prepared, policy, profile, absence, &nativeReadbackDTestAuthority{dIntegrationFinish{f: f}})
			if err != nil {
				t.Fatal("production native publisher", err)
			}
			defer publisher.Close()
			if env, source, err := NewTrackedSystemResultEnvironment(&dIntegrationResult{f: f}, f.prepared, f.channel, f.history, publisher); err == nil || env != nil || source != nil {
				t.Fatal("loopback accepted without original backing source")
			}
			env, original, err := NewTrackedSystemResultEnvironmentWithBacking(ctx, &dIntegrationResult{f: f}, f.prepared, f.channel, f.history, publisher, gateway.BackingStoreSource())
			if err != nil {
				t.Fatal("original tracked result", err)
			}
			publisher.store = &originalC1TraceStore{systemPublicationStore: publisher.store, t: t}
			result, err := publisher.Publish(ctx, source(f.ciphertext))
			if err != nil || result.State != "ready" || *puts != 1 {
				logOriginalC1PublicationFailure(t, gateway, profile, publisher)
				t.Fatal("one native PUT/readback/finish", result, err, *puts)
			}
			service, err := pd.NewResults(execution, env)
			if err != nil {
				t.Fatal(err)
			}
			if failResult {
				f.fail = "result_guard"
			}
			f.d.now = time.Now().UTC().Truncate(time.Microsecond)
			committed, err := service.CommitResult(ctx, f.handle, f.resultRequest)
			if failResult && err == nil || !failResult && (err != nil || committed.Replayed) {
				t.Fatal("original result transaction", committed, err)
			}
			readDB := sql.OpenDB(originalC1ReadModel{f.d})
			defer readDB.Close()
			tx, err := readDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			facts, readErr := original.ReadCommitted(ctx, tx)
			if failResult {
				if readErr == nil {
					t.Fatal("rolled-back result authenticated")
				}
				return
			}
			store, _, err := gateway.BackingStoreSource().OriginalStore()
			store.CAPEM = nil
			if readErr != nil || err != nil || f.handle != originalHandle || facts.Record.Ref.ImmutableVersion != "Exact.Version/1" || !reflect.DeepEqual(facts.NativeStore, store) || facts.NativeStore.Endpoint == policy.STS.Store.Endpoint || len(facts.KeySource.EnvelopeHeader) == 0 || len(facts.Commands) == 0 || len(facts.References) != 3 {
				t.Fatal("committed original durable source", readErr, err)
			}
			for _, table := range []string{"domains", "grants", "runs", "targets", "evidence_bindings", "evidence_refs", "command_receipts", "result_receipts"} {
				if len(f.d.records["system_backup_producer_"+table]) == 0 {
					t.Fatal("missing actual SDK rows", table)
				}
			}
			if _, err := json.Marshal(original); err == nil {
				t.Fatal("opaque source serialized")
			}
		})
	}
}
