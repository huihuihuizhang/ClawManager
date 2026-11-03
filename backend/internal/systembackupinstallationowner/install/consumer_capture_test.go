package install

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Real local TLS API/Vault protocols, signatures and the explicit SQL model.
// The account value switch is synthetic; actual account/GRANT/InnoDB proof
// remains the separate frozen native SQL suite. No other owner is supplied.
type captureConsumerFixture struct {
	f               *authorityFixture
	source          *CaptureSigningConsumer
	document        CaptureConsumerFiles
	api             *httptest.Server
	apiCalls        atomic.Int32
	enrollmentDrift atomic.Bool
}

func newCaptureConsumerFixture(t *testing.T, ctx context.Context) *captureConsumerFixture {
	t.Helper()
	f := newAuthorityFixture(t)
	c := &captureConsumerFixture{f: f}
	kube, plan := f.i.kube, f.i.plan
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.apiCalls.Add(1)
		requireNoOpenAuthorityTx(t, f.s)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer consumer-static-token" {
			w.WriteHeader(403)
			return
		}
		send := func(value any) {
			if json.NewEncoder(w).Encode(value) != nil {
				t.Error("controlled API response")
			}
		}
		base := "/api/v1/namespaces/" + plan.Target.Namespace
		switch r.Method + " " + r.URL.Path {
		case "POST /apis/authentication.k8s.io/v1/selfsubjectreviews":
			var input authenticationv1.SelfSubjectReview
			if decodeEnrollmentAPIRequest(r, &input, "authentication.k8s.io", "SelfSubjectReview") != nil {
				w.WriteHeader(400)
				return
			}
			v, e := kube.AuthenticationV1().SelfSubjectReviews().Create(r.Context(), &input, metav1.CreateOptions{})
			if e != nil {
				w.WriteHeader(403)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}
			send(v)
		case "GET /api/v1/namespaces/kube-system", "GET /api/v1/namespaces/" + plan.Target.Namespace:
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/")
			v, e := kube.CoreV1().Namespaces().Get(r.Context(), name, metav1.GetOptions{})
			if e != nil {
				w.WriteHeader(404)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}
			send(v)
		case "GET " + base + "/configmaps/" + plan.EnrollmentName:
			v, e := kube.CoreV1().ConfigMaps(plan.Target.Namespace).Get(r.Context(), plan.EnrollmentName, metav1.GetOptions{})
			if e != nil {
				w.WriteHeader(404)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}
			if c.enrollmentDrift.Load() {
				v.UID = "foreign-original-registration"
			}
			send(v)
		case "GET " + base + "/pods/" + f.record.Binding.PodName:
			v, e := kube.CoreV1().Pods(plan.Target.Namespace).Get(r.Context(), f.record.Binding.PodName, metav1.GetOptions{})
			if e != nil {
				w.WriteHeader(404)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}
			send(v)
		case "GET " + base + "/serviceaccounts/" + f.record.Binding.ServiceAccountName:
			v, e := kube.CoreV1().ServiceAccounts(plan.Target.Namespace).Get(r.Context(), f.record.Binding.ServiceAccountName, metav1.GetOptions{})
			if e != nil {
				w.WriteHeader(404)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}
			send(v)
		case "POST /apis/authentication.k8s.io/v1/tokenreviews":
			var input authenticationv1.TokenReview
			if decodeEnrollmentAPIRequest(r, &input, "authentication.k8s.io", "TokenReview") != nil {
				w.WriteHeader(400)
				return
			}
			v, e := kube.AuthenticationV1().TokenReviews().Create(r.Context(), &input, metav1.CreateOptions{})
			if e != nil {
				w.WriteHeader(403)
				return
			}
			v.TypeMeta = metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
			send(v)
		default:
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(api.Close)
	c.api = api
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	plan.KubernetesAPI, plan.KubernetesCASHA256 = api.URL, hash(ca)
	planRaw, e := canonical(plan)
	if e != nil {
		t.Fatal(e)
	}
	i, e := New(f.i.db, kube, planRaw, hash(planRaw), f.i.public, hash(f.i.public))
	if e != nil {
		t.Fatal(e)
	}
	if kube.CoreV1().ConfigMaps(plan.Target.Namespace).Delete(ctx, plan.EnrollmentName, metav1.DeleteOptions{}) != nil {
		t.Fatal("controlled previous API enrollment")
	}
	receipt, e := i.Enroll(ctx, f.password)
	if e != nil {
		t.Fatal("controlled original new API plan enrollment", e)
	}
	f.i, f.enrollment = i, receipt.Pin
	pack := issueFixture(t, f, ctx)
	if _, e := i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal("private consumer fixture output directory", e)
	}
	if _, e := i.ExportCommitted(ctx, f.password, f.enrollment, pack, hash(pack), directory); e != nil {
		t.Fatal(e)
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(directory, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("controlled consumer input")
		}
		return path
	}
	public := i.public
	kubeRaw, e := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "consumer", "clusters": []any{map[string]any{"name": "consumer", "cluster": map[string]any{"server": api.URL, "certificate-authority-data": base64.StdEncoding.EncodeToString(ca)}}}, "users": []any{map[string]any{"name": "consumer", "user": map[string]string{"token": "consumer-static-token"}}}, "contexts": []any{map[string]any{"name": "consumer", "context": map[string]string{"cluster": "consumer", "user": "consumer"}}}})
	if e != nil {
		t.Fatal(e)
	}
	pinPath, enrollmentPath := filepath.Join(directory, "owner.pin.json"), filepath.Join(directory, "owner.enrollment-pin.json")
	pin, e := os.ReadFile(pinPath)
	if e != nil {
		t.Fatal(e)
	}
	enrollment, e := os.ReadFile(enrollmentPath)
	if e != nil {
		t.Fatal(e)
	}
	c.document = CaptureConsumerFiles{SchemaVersion: CaptureConsumerVersion, PlanFile: write("plan.json", planRaw), PlanSHA256: hash(planRaw), IssuerPublicFile: write("issuer.public", public), IssuerPublicSHA256: hash(public), TrustPinFile: pinPath, TrustPinSHA256: hash(pin), EnrollmentPinFile: enrollmentPath, EnrollmentPinSHA256: hash(enrollment), KubeconfigFile: write("kubeconfig", kubeRaw), KubeconfigSHA256: hash(kubeRaw), RecordFile: filepath.Join(directory, "owner.record"), SignatureFile: filepath.Join(directory, "owner.signature"), Request: f.files}
	sourceRaw, e := canonical(c.document)
	if e != nil {
		t.Fatal(e)
	}
	c.source = NewCaptureSigningConsumer(write("capture-consumer.json", sourceRaw), write("capture-consumer.sha256", []byte(hash(sourceRaw))))
	return c
}

func TestCaptureConsumerLoadsIndependentPinsAndOriginalL2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := newCaptureConsumerFixture(t, ctx)
	queries, signs := c.f.s.auth.queries, c.f.signs.Load()
	check, e := c.source.Prepare(ctx, c.f.grant, c.f.config)
	if e != nil || c.f.signs.Load() != signs+1 || c.f.s.auth.queries != queries {
		t.Fatal("consumer required installer SQL/private key or skipped concrete TLS probe", e)
	}
	authority, ok := check.(sec.BootstrapOriginalResourceAuthority)
	if !ok {
		t.Fatal("legacy current-source L2 hook missing")
	}
	apiCalls := c.apiCalls.Load()
	c.api.Close()
	// Explicit protocol-model account only; not actual MySQL privilege evidence.
	c.f.s.auth.account = c.f.i.plan.Target.DatabaseAccount
	tx, e := c.f.i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if e := authority.AuthorizeBootstrapOriginal(ctx, tx, c.f.grant, c.f.config, now); e != nil {
		t.Fatal("actual signed owner SQL model L2", e)
	}
	if e := check.Recheck(ctx, tx, time.Now().UTC().Truncate(time.Microsecond)); e != nil || c.apiCalls.Load() != apiCalls || c.f.signs.Load() != signs+1 {
		t.Fatal("consumer renewed or did network under SQL locks", e)
	}
	c.f.s.auth.active = false
	if e := authority.AuthorizeBootstrapOriginal(ctx, tx, c.f.grant, c.f.config, now); e == nil {
		t.Fatal("changed original source authorized historical retry")
	}
}
func TestCaptureConsumerRejectsForeignEnrollmentAndInputDrift(t *testing.T) {
	for _, mode := range []string{"foreign_enrollment", "changed_public", "source_pin_removed", "unknown_private_input"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c := newCaptureConsumerFixture(t, ctx)
			before := c.f.signs.Load()
			switch mode {
			case "foreign_enrollment":
				c.enrollmentDrift.Store(true)
			case "changed_public":
				if os.WriteFile(c.document.IssuerPublicFile, make([]byte, 32), 0600) != nil {
					t.Fatal("input mutation")
				}
			case "source_pin_removed":
				if os.Remove(c.source.sourcePinFile) != nil {
					t.Fatal("pin removal")
				}
			case "unknown_private_input":
				raw, e := canonical(c.document)
				if e != nil {
					t.Fatal(e)
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) != nil {
					t.Fatal("doc")
				}
				fields["IssuerPrivateFile"] = json.RawMessage(`"must-not-open"`)
				raw, e = canonical(fields)
				if e != nil || os.WriteFile(c.source.sourceFile, raw, 0600) != nil || os.WriteFile(c.source.sourcePinFile, []byte(hash(raw)), 0600) != nil {
					t.Fatal("closed input mutation")
				}
			}
			if _, e := c.source.Prepare(ctx, c.f.grant, c.f.config); e == nil || c.f.signs.Load() != before {
				t.Fatal("foreign/unpinned input reached provider", e)
			}
		})
	}
}
func TestCaptureConsumerLatePinRevocationLatchesBeforeL2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := newCaptureConsumerFixture(t, ctx)
	check, e := c.source.Prepare(ctx, c.f.grant, c.f.config)
	if e != nil {
		t.Fatal(e)
	}
	original, e := os.ReadFile(c.source.sourcePinFile)
	if e != nil || os.Remove(c.source.sourcePinFile) != nil {
		t.Fatal("controlled pin removal")
	}
	current := check.(sec.BootstrapOriginalResourceAuthority)
	c.f.s.auth.account = c.f.i.plan.Target.DatabaseAccount
	tx, e := c.f.i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	queries := c.f.s.auth.queries
	if current.AuthorizeBootstrapOriginal(ctx, tx, c.f.grant, c.f.config, time.Now().UTC()) == nil {
		t.Fatal("removed pin allowed current identity")
	}
	if os.WriteFile(c.source.sourcePinFile, original, 0600) != nil {
		t.Fatal("controlled pin restore")
	}
	if current.AuthorizeBootstrapOriginal(ctx, tx, c.f.grant, c.f.config, time.Now().UTC()) == nil || c.f.s.auth.queries != queries {
		t.Fatal("failed preparation revived after pin restore or reached SQL")
	}
	if _, e := c.source.CandidateAuthority(nil); e == nil {
		t.Fatal("missing Original authority replaced")
	}
	var _ sec.BootstrapResourceValidator = c.source
}

func TestCaptureConsumerMissingProviderCAKeepsOnlyCurrentHistoryIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := newCaptureConsumerFixture(t, ctx)
	observerRaw, e := os.ReadFile(c.f.files.ObserverFile)
	var observer observerDocument
	if e != nil || decodeExact(observerRaw, &observer) != nil || os.Remove(observer.CAFile) != nil {
		t.Fatal("controlled physical CA removal")
	}
	signs := c.f.signs.Load()
	check, e := c.source.Prepare(ctx, c.f.grant, c.f.config)
	if e != nil || c.f.signs.Load() != signs {
		t.Fatal("missing physical provider CA preempted current identity or signed", e)
	}
	c.f.s.auth.account = c.f.i.plan.Target.DatabaseAccount
	tx, e := c.f.i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	current := check.(sec.BootstrapOriginalResourceAuthority)
	for range 2 {
		if current.AuthorizeBootstrapOriginal(ctx, tx, c.f.grant, c.f.config, time.Now().UTC().Truncate(time.Microsecond)) != nil {
			t.Fatal("original current history required missing provider CA")
		}
	}
	if check.Recheck(ctx, tx, time.Now().UTC().Truncate(time.Microsecond)) == nil || c.f.signs.Load() != signs {
		t.Fatal("identity-only source granted new use or renewed provider permission")
	}
}
