package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func bootstrapSourceRegistryFixtureSelection(t *testing.T, f *authorityFixture) pd.BootstrapConsumptionRequest {
	t.Helper()
	raw, err := os.ReadFile("../../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ID    string
			Value json.RawMessage
		}
		Records []struct {
			Definition string
			Value      json.RawMessage
		}
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("strict original producer vectors")
	}
	var result pd.ResultRequest
	var domain pd.DomainRecord
	var grant pd.GrantRecord
	for _, vector := range vectors.Positive {
		if vector.ID == "unconfigured_artifact" && pd.DecodeRecord(vector.Value, &result) != nil {
			t.Fatal("result vector")
		}
	}
	for _, vector := range vectors.Records {
		switch vector.Definition {
		case "DomainRecord":
			if pd.DecodeRecord(vector.Value, &domain) != nil {
				t.Fatal("domain vector")
			}
		case "GrantRecord":
			if pd.DecodeRecord(vector.Value, &grant) != nil {
				t.Fatal("grant vector")
			}
		}
	}
	if result.Admission.Unconfigured == nil || grant.Host.Service == nil {
		t.Fatal("service/unconfigured original source fixture")
	}
	result.Scope = pd.Scope{ServerUUID: pd.ServerUUID(f.record.Target.ServerUUID), Database: pd.Database(f.record.Target.Database), Installation: pd.Installation(f.record.Target.InstallationID)}
	result.Evidence.OwnerID = result.Scope.Installation
	result.Admission.Unconfigured.CandidateHash = pd.Hash(f.record.ConfigSHA256)
	result.Admission.Unconfigured.RegistrySetHash = pd.Hash(f.record.RegistrySetSHA256)
	result.Admission.Unconfigured.RefSetHash = pd.Hash(f.record.ReferenceSetSHA256)
	domain.Scope, domain.Admission = result.Scope, result.Admission
	grant.Scope, grant.Admission, grant.GrantID, grant.Generation, grant.State, grant.IssuerIdentityHash = result.Scope, result.Admission, result.GrantID, result.GrantGeneration, "active", domain.IssuerIdentityHash
	request := pd.BootstrapConsumptionRequest{Scope: result.Scope, OfflineGrantHash: pd.Hash(f.record.GrantSHA256), ConfigHash: pd.Hash(f.record.ConfigSHA256), RegistrySetHash: pd.Hash(f.record.RegistrySetSHA256), RefSetHash: pd.Hash(f.record.ReferenceSetSHA256), ActorID: pd.Counter(strconv.FormatInt(f.record.Actor.UserID, 10)), Username: f.record.Actor.Username, MatrixKey: f.record.MatrixKey, Endpoint: f.record.Endpoint, IdempotencyKey: f.record.IdempotencyKey, Candidates: []pd.BootstrapCandidateSelection{{Purpose: "artifact", ReferenceIdentityHash: pd.Hash(strings.Repeat("b", 64)), ReferenceVersion: "1", MappingHash: pd.Hash(strings.Repeat("c", 64)), Request: result, ResultVersion: "1"}}}
	selection, err := pd.BootstrapConsumptionHash(request)
	if err != nil {
		t.Fatal(err)
	}
	f.record.SelectionSHA256 = string(selection)
	f.draft, err = canonical(f.record)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// Independent copy of the existing real local TLS/enrollment consumer fixture,
// with the original finite window and COMPLETE selection chosen BEFORE the
// actual IssueCapture/ImportCapture/ExportCommitted actions. Old fixtures are
// unchanged; no authenticated private object or clock result is fabricated.
func newBootstrapSourceAuthenticatedConsumer(t *testing.T, ctx context.Context, window time.Duration) (*captureConsumerFixture, pd.BootstrapConsumptionRequest, []byte) {
	t.Helper()
	f := newAuthorityFixture(t)
	f.record.Until = time.Now().UTC().Add(window).Truncate(time.Microsecond)
	f.record.Probe.Until = f.record.Until
	selection := bootstrapSourceRegistryFixtureSelection(t, f)
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
	return c, selection, pack
}

