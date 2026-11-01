package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	c "clawreef/internal/systembackupcontroller"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	kt "k8s.io/client-go/testing"
)

type aPublicationMaterialFixture struct {
	x                                        *aPublisherVerifierFixture
	store                                    *nativePublicationS3
	provider                                 *aNativePublicationServer
	request                                  PublicationUploadRequest
	inputs                                   DeploymentStartupInputs
	controlDSN                               string
	client                                   *fake.Clientset
	secretCreates, secretUpdates, jobCreates int
	omitSecretCreate, omitSecretUpdate       bool
	secretCreateError, secretUpdateError     error
}

func newAPublicationMaterialFixture(t *testing.T) *aPublicationMaterialFixture {
	t.Helper()
	f := &aPublicationMaterialFixture{}
	f.store, f.provider = newANativePublicationStore(t, time.Minute)
	t.Cleanup(f.store.Close)
	f.store.config.RemoteStagingRoot = "remote-staging/installation_test/"
	var issuer control.IdentityIssuer
	originalMTLSControlServer(t, http.NotFoundHandler(), func(value control.IdentityIssuer) { issuer = value })
	f.x = newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &f.store.config, AttemptNo: 1, PublicationWorker: &PublicationWorkerReference{Protocol: publicationPresignedUploadVersion, ServiceAccountName: "publish-upload", ServiceAccountUID: "publish-upload-sa"}, WorkerIssuer: &issuer, ObserveControlDSN: func(dsn string) { f.controlDSN = dsn }})
	f.inputs = aStartPublisherVerifierSamePod(t, f.x)
	aUseActualPublicationDDL(t, f.x, f.store.config)
	aUseActualPublicationJobDDL(t, f.x)
	h, ctx := f.x.history, context.Background()
	h.service.Runtime = &PublicCapture{Owner: h.owner}
	h.service.staging = h.owner.Staging
	h.owner.Issuer = issuer
	f.client = h.owner.Client.(*fake.Clientset)
	cfg := h.service.Config
	for _, object := range []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: cfg.PublicationWorker.ServiceAccountName, UID: types.UID(cfg.PublicationWorker.ServiceAccountUID)}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: cfg.StagingClaim, UID: "staging-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "staging-pv"}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "staging-pv", UID: "staging-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: cfg.Namespace, Name: cfg.StagingClaim, UID: "staging-uid"}}},
	} {
		if err := f.client.Tracker().Add(object); err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := h.service.PublisherVerifierForPart(ctx, h.token, 1, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	record, err := verifier.CapturedRecord(ctx)
	verifier.Close()
	if err != nil {
		t.Fatal(err)
	}
	var original FormalCandidateRecord
	if json.Unmarshal(record.CandidateJSON, &original) != nil {
		t.Fatal("original candidate")
	}
	invSHA, _ := record.Invocation.Hash()
	cipher, envelope := publicationPartPaths("workspace", record.Invocation.Request.Binding.PartIndex, invSHA)
	index := []byte("durable publication transport index DATA")
	f.request = PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: 1, Endpoint: f.store.config.Endpoint, Region: f.store.config.Region, Bucket: f.store.config.Bucket, ArtifactRoot: f.store.config.Root, RemoteStagingRoot: f.store.config.RemoteStagingRoot, CAHash: f.store.config.CASHA256, Deadline: h.original.DeadlineAt.Add(-time.Second), IndexBytes: index, Objects: []PublicationUploadInput{{Path: cipher, SHA256: original.Candidate.Ciphertext.SHA256, Bytes: original.Candidate.Ciphertext.Size}, {Path: envelope, SHA256: original.Candidate.Envelope.SHA256, Bytes: original.Candidate.Envelope.Size}, {Path: "artifact-index.json", SHA256: hash(index), Bytes: int64(len(index))}}}
	f.request.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"` + f.request.Installation + `","backup_public_id":"` + f.request.Backup + `","attempt_no":1,"artifact_index":{"path":"artifact-index.json","checksum":"` + hash(index) + `"}}`)
	f.client.PrependReactor("create", "secrets", func(action kt.Action) (bool, runtime.Object, error) {
		secret := action.(kt.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
		if !strings.HasPrefix(secret.Name, "sbp-") {
			return false, nil, nil
		}
		f.secretCreates++
		secret.UID = types.UID(uuid.NewString())
		secret.ResourceVersion = "1"
		if !f.omitSecretCreate {
			if err := f.client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
				t.Fatal(err)
			}
		}
		if f.secretCreateError != nil {
			return true, nil, f.secretCreateError
		}
		return true, secret, nil
	})
	f.client.PrependReactor("update", "secrets", func(action kt.Action) (bool, runtime.Object, error) {
		secret := action.(kt.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		if !strings.HasPrefix(secret.Name, "sbp-") {
			return false, nil, nil
		}
		f.secretUpdates++
		current, err := f.client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), secret.Namespace, secret.Name)
		if err != nil {
			t.Fatal(err)
		}
		old := current.(*corev1.Secret)
		if old.UID != secret.UID || old.ResourceVersion != secret.ResourceVersion {
			t.Fatal("native conditional Secret update lost its UID/RV")
		}
		before, _ := publicationMaterialBody(old)
		after, _ := publicationMaterialBody(secret)
		if hash(before) != hash(after) {
			t.Fatal("owner binding changed private material bytes")
		}
		clear(before)
		clear(after)
		secret.ResourceVersion = "2"
		if !f.omitSecretUpdate {
			if err = f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
				t.Fatal(err)
			}
		}
		if f.secretUpdateError != nil {
			return true, nil, f.secretUpdateError
		}
		return true, secret, nil
	})
	aRefreshPublicationPayloadCapacity(t, f.x)
	return f
}

// This native TLS bridge persists only the named local fake control-plane
// objects while the actual controller runs in another OS process. It supports
// GET only, so a reopen cannot recreate a Job/Secret or mint native authority.
func aPublicationReadOnlyKubernetesBridge(t *testing.T, client *fake.Clientset) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	writes := &atomic.Int64{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		group, version, start := "", "", 0
		if len(parts) >= 2 && parts[0] == "api" {
			version, start = parts[1], 2
		} else if len(parts) >= 3 && parts[0] == "apis" {
			group, version, start = parts[1], parts[2], 3
		} else {
			w.WriteHeader(404)
			return
		}
		tail := parts[start:]
		namespace, resource, name := "", "", ""
		if len(tail) == 4 && tail[0] == "namespaces" {
			namespace, resource, name = tail[1], tail[2], tail[3]
		} else if len(tail) == 2 {
			resource, name = tail[0], tail[1]
		} else {
			w.WriteHeader(404)
			return
		}
		object, err := client.Tracker().Get(schema.GroupVersionResource{Group: group, Version: version, Resource: resource}, namespace, name)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: 404, Message: "named local read resource absent"})
			return
		}
		kinds, _, err := kscheme.Scheme.ObjectKinds(object)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		for _, kind := range kinds {
			if kind.Group == group && kind.Version == version {
				object.GetObjectKind().SetGroupVersionKind(kind)
				break
			}
		}
		json.NewEncoder(w).Encode(object)
	}))
	t.Cleanup(server.Close)
	return server, writes
}

type aPublicationReopenContext struct {
	ConfigPath, ConfigSHA256, ForwardSHA256, RecoverySHA256, ControlDSN, StagingPath string
	KubernetesURL                                                                    string
	KubernetesCA                                                                     []byte
	Inputs                                                                           DeploymentStartupInputs
	Claim                                                                            c.ClaimToken
	Target                                                                           PublicationTargetMaterials
	ProofFile                                                                        string
}
type aPublicationReopenProof struct {
	RequestSHA256, CredentialSHA256, MaterialBodySHA256, SecretUID, JobUID string
	Deadline                                                               time.Time
	JobOwner                                                               bool
}

func TestPublicationMaterialReopenProcessChild(t *testing.T) {
	path := os.Getenv("A_PUBLICATION_REOPEN_CONTEXT")
	if path == "" {
		t.Skip("isolated child process only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("child context unavailable")
	}
	var input aPublicationReopenContext
	if decodeProviderDeploymentJSON(raw, &input) != nil {
		t.Fatal("child context invalid")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	database, err := sql.Open("mysql", input.ControlDSN)
	input.ControlDSN = ""
	if err != nil {
		t.Fatal("child scoped DB unavailable")
	}
	defer database.Close()
	cfg, err := LoadDeploymentConfig(input.ConfigPath, input.ConfigSHA256)
	if err != nil {
		t.Fatal("child original core", err)
	}
	forward, err := deploymentIdentity(cfg.ForwardGrant, input.ForwardSHA256, cfg.KeyDirectory)
	if err != nil {
		t.Fatal("child original forward", err)
	}
	recovery, err := deploymentIdentity(cfg.RecoveryGrant, input.RecoverySHA256, cfg.KeyDirectory)
	if err != nil {
		t.Fatal("child original recovery", err)
	}
	// Match cmd/system-backup-v2-controller/public_capture.go's existing real
	// controller transport settings; permission/time checks remain fresh.
	client, err := kubernetes.NewForConfig(&rest.Config{Host: input.KubernetesURL, TLSClientConfig: rest.TLSClientConfig{CAData: input.KubernetesCA}, QPS: 50, Burst: 100, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal("child native client")
	}
	service := &DeploymentService{ConfigPath: input.ConfigPath, ConfigDigest: input.ConfigSHA256, Config: cfg, Forward: forward, Recovery: recovery, ForwardEnabled: true}
	if err = service.bindDeploymentStartupInputs(input.Inputs); err != nil {
		t.Fatal("child exact original startup pins", err)
	}
	if err = service.attachPublicationSigners(ctx, database, client, input.Inputs.ControllerPodName); err != nil {
		t.Fatal("child current original Pod", err)
	}
	stage, err := os.OpenRoot(input.StagingPath)
	if err != nil {
		t.Fatal("child original owner custody")
	}
	defer stage.Close()
	service.staging = stage
	issuerRaw, err := os.ReadFile(cfg.IssuerCertificate)
	if err != nil {
		t.Fatal("child public issuer")
	}
	block, _ := pem.Decode(issuerRaw)
	if block == nil {
		t.Fatal("child issuer PEM")
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("child issuer certificate")
	}
	// No CA private signer is opened in the child. A regeneration path cannot
	// produce another worker identity, even if it accidentally gets selected.
	owner := &PublicJobOwner{Client: client, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Security: cfg.Security, TrustDomain: cfg.TrustDomain, Identity: forward, Staging: stage, Issuer: control.IdentityIssuer{Certificate: issuer, TrustDomain: cfg.TrustDomain, ServerRoots: issuerRaw}}
	service.Runtime = &PublicCapture{Owner: owner}
	owner.Gate = service.captureGate(database)
	if err = service.attachPublisherVerifier(ctx, database, client, owner.Gate.Records); err != nil {
		t.Fatal("child fresh publisher factory", err)
	}
	job, materials, err := service.ensureDurableSuspendedPublicationJob(ctx, input.Claim, 1, input.Target, PublicationUploadRequest{})
	if err != nil {
		t.Fatal("child query-only original Job recovery", err)
	}
	defer materials.Close()
	proof, _ := json.Marshal(aPublicationReopenProof{RequestSHA256: materials.intent.RequestSHA256, CredentialSHA256: materials.intent.CredentialSHA256, MaterialBodySHA256: materials.intent.BodySHA256, SecretUID: string(materials.secret.UID), JobUID: string(job.UID), Deadline: materials.intent.Deadline, JobOwner: len(materials.secret.OwnerReferences) == 1})
	if os.WriteFile(input.ProofFile, proof, 0600) != nil {
		t.Fatal("child proof write")
	}
}

func TestPublicationMaterialsDurableBefore121AndActualProcessReopenMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"sending-before-107", "job-owner-bound"} {
		t.Run(mode, func(t *testing.T) {
			f := newAPublicationMaterialFixture(t)
			h, ctx := f.x.history, context.Background()
			materials, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, f.request)
			if err != nil {
				t.Fatal("durable original Secret before Job", err)
			}
			expected := aPublicationReopenProof{RequestSHA256: materials.intent.RequestSHA256, CredentialSHA256: materials.intent.CredentialSHA256, MaterialBodySHA256: materials.intent.BodySHA256, SecretUID: string(materials.secret.UID), Deadline: materials.intent.Deadline, JobOwner: mode == "job-owner-bound"}
			var sends int
			if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE phase='publish'`).Scan(&sends) != nil || sends != 0 {
				t.Fatal("121 preceded durable original Secret")
			}
			f.client.PrependReactor("create", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
				f.jobCreates++
				job := action.(kt.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
				job.UID = types.UID(uuid.NewString())
				job.Generation = 1
				job.ResourceVersion = "1"
				expected.JobUID = string(job.UID)
				var observed []byte
				if h.admin.QueryRow(`SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, publicationMaterialID(h.original.InstallationID, h.original.TaskPublicID, 1)+"_observed").Scan(&observed) != nil {
					t.Fatal("native Secret UID was not acknowledged before original 121/native Create")
				}
				if err := f.client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
					t.Fatal(err)
				}
				if mode == "sending-before-107" {
					return true, nil, errors.New("actual original native Job ACK lost")
				}
				return true, job, nil
			})
			_, err = h.service.ensureSuspendedPublicationJob(ctx, h.token, 1, f.store.config, materials.request)
			if mode == "sending-before-107" {
				if !errors.Is(err, ErrJobUncertain) {
					t.Fatal("original 121 sending crash point", err)
				}
			} else if err != nil {
				t.Fatal("original Job bind", err)
			}
			materials.Close()
			materials = nil
			if mode == "job-owner-bound" {
				owned, err := h.service.bindPublicationMaterialJobOwner(ctx, h.token, 1, f.store.config)
				if err != nil {
					t.Fatal("native original UID owner binding", err)
				}
				owned.Close()
			}
			bridge, writes := aPublicationReadOnlyKubernetesBridge(t, f.client)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bridge.Certificate().Raw})
			privateDir := t.TempDir()
			proofPath := filepath.Join(privateDir, "reopen-proof.json")
			input := aPublicationReopenContext{ConfigPath: h.service.ConfigPath, ConfigSHA256: h.service.ConfigDigest, ForwardSHA256: h.service.Forward.GrantSHA256(), RecoverySHA256: h.service.Recovery.GrantSHA256(), ControlDSN: f.controlDSN, StagingPath: h.owner.Staging.Name(), KubernetesURL: bridge.URL, KubernetesCA: ca, Inputs: f.inputs, Claim: h.token, Target: f.store.config, ProofFile: proofPath}
			serialized, _ := json.Marshal(input)
			contextPath := filepath.Join(privateDir, "private-reopen-context.json")
			if os.WriteFile(contextPath, serialized, 0600) != nil {
				t.Fatal("private reopen context")
			}
			clear(serialized)
			input.ControlDSN = ""
			f.controlDSN = ""
			// Destroy the parent's request and current service/factory references.
			// Only the native Secret, immutable original evidence and actual files/SQL
			// cross the OS-process boundary; no caller p or private material is passed.
			clear(f.request.ManifestInput)
			clear(f.request.IndexBytes)
			f.request = PublicationUploadRequest{}
			h.service.publisherVerifierFactory = nil
			h.service.Runtime = nil
			h.service = nil
			process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPublicationMaterialReopenProcessChild$", "-test.v")
			process.Env = append(os.Environ(), "A_PUBLICATION_REOPEN_CONTEXT="+contextPath)
			if output, err := process.CombinedOutput(); err != nil {
				t.Fatalf("separate controller process failed: %v\n%s", err, output)
			}
			proofRaw, err := os.ReadFile(proofPath)
			if err != nil {
				t.Fatal("reopen proof unavailable")
			}
			var proof aPublicationReopenProof
			if json.Unmarshal(proofRaw, &proof) != nil || proof != expected {
				t.Fatal("reopen did not use original bytes/UID/deadline")
			}
			if writes.Load() != 0 || f.secretCreates != 1 || f.jobCreates != 1 || f.provider.puts != 0 || f.provider.gets != 0 || f.provider.heads != 0 || f.x.logins.Load() != 0 || f.x.decrypts.Load() != 0 {
				t.Fatal("reopen regenerated/sent private authority or source/provider IO")
			}
			if (mode == "job-owner-bound" && f.secretUpdates != 1) || (mode != "job-owner-bound" && f.secretUpdates != 0) {
				t.Fatal("native owner update count", f.secretUpdates)
			}
		})
	}
}

func TestPublicationMaterialsUnknownAndOwnershipFailClosedMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"secret-create-ack-lost", "secret-absent-after-intent", "secret-uid-replaced", "secret-bytes-changed", "foreign-owner", "extra-owner-after-bind", "owner-update-ack-lost", "owner-update-absent", "owner-update-forbidden", "released-after-material", "121-without-material-intent", "expired-material-new-claim"} {
		t.Run(mode, func(t *testing.T) {
			f := newAPublicationMaterialFixture(t)
			h, ctx := f.x.history, context.Background()
			if mode == "secret-create-ack-lost" || mode == "secret-absent-after-intent" {
				f.secretCreateError = errors.New("actual native Secret create ACK lost")
				f.omitSecretCreate = mode == "secret-absent-after-intent"
			}
			m, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, f.request)
			if mode == "secret-create-ack-lost" || mode == "secret-absent-after-intent" {
				if !errors.Is(err, ErrJobUncertain) || m != nil || f.secretCreates != 1 {
					t.Fatal("Secret native unknown did not reach actual create", err)
				}
			} else if err != nil {
				t.Fatal("original durable material", err)
			}
			if m != nil {
				m.Close()
			}
			intent, err := h.service.loadPublicationMaterialIntent(ctx, h.token, 1)
			if err != nil {
				t.Fatal("original material intent", err)
			}
			if mode == "secret-uid-replaced" || mode == "secret-bytes-changed" || mode == "foreign-owner" {
				object, err := f.client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), intent.Namespace, intent.Name)
				if err != nil {
					t.Fatal(err)
				}
				secret := object.(*corev1.Secret)
				if mode == "secret-uid-replaced" {
					secret.UID = types.UID(uuid.NewString())
				}
				if mode == "secret-bytes-changed" {
					secret.Data["credential.json"][0] ^= 1
				}
				if mode == "foreign-owner" {
					secret.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "foreign", UID: types.UID(uuid.NewString())}}
				}
				// Deliberate independent control-plane corruption/replacement actor,
				// not the production client's immutable Secret update path.
				if err = f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "extra-owner-after-bind" || mode == "owner-update-ack-lost" || mode == "owner-update-absent" || mode == "owner-update-forbidden" || mode == "121-without-material-intent" {
				stored, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, PublicationUploadRequest{})
				if err != nil {
					t.Fatal(err)
				}
				f.client.PrependReactor("create", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
					f.jobCreates++
					job := action.(kt.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
					job.UID = types.UID(uuid.NewString())
					job.Generation = 1
					job.ResourceVersion = "1"
					if err := f.client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
						t.Fatal(err)
					}
					return true, job, nil
				})
				if _, err = h.service.ensureSuspendedPublicationJob(ctx, h.token, 1, f.store.config, stored.request); err != nil {
					t.Fatal("actual original Job bind", err)
				}
				stored.Close()
				if mode == "121-without-material-intent" {
					result, err := h.admin.Exec(`DELETE FROM system_backup_v2_evidence WHERE public_id=?`, publicationMaterialID(intent.Installation, intent.Backup, 1))
					if err != nil {
						t.Fatal(err)
					}
					if count, err := result.RowsAffected(); err != nil || count != 1 {
						t.Fatal("independent original material intent loss absent")
					}
				} else {
					if mode == "owner-update-ack-lost" || mode == "owner-update-absent" {
						f.secretUpdateError = errors.New("actual native owner update ACK lost")
						f.omitSecretUpdate = mode == "owner-update-absent"
					}
					if mode == "owner-update-forbidden" {
						f.secretUpdateError = apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, intent.Name, errors.New("actual named owner update denied"))
						f.omitSecretUpdate = true
					}
					owned, err := h.service.bindPublicationMaterialJobOwner(ctx, h.token, 1, f.store.config)
					if mode == "extra-owner-after-bind" {
						if err != nil {
							t.Fatal("actual original owner binding", err)
						}
						owned.Close()
						object, err := f.client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), intent.Namespace, intent.Name)
						if err != nil {
							t.Fatal(err)
						}
						secret := object.(*corev1.Secret)
						secret.OwnerReferences = append(secret.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "foreign", UID: types.UID(uuid.NewString())})
						if err = f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
							t.Fatal(err)
						}
					} else if !errors.Is(err, ErrJobUncertain) || owned != nil || f.secretUpdates != 1 {
						t.Fatal("actual owner update unknown not reached", err)
					}
				}
			}
			if mode == "released-after-material" {
				if _, err := (c.ClaimCoordinator{Executor: h.admin, InstallationID: intent.Installation}).Release(ctx, h.token, time.Second); err != nil {
					t.Fatal(err)
				}
				var owner sql.NullString
				var version uint64
				if h.admin.QueryRow(`SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, intent.Backup).Scan(&owner, &version) != nil || owner.Valid || version <= h.token.RowVersion {
					t.Fatal("actual release effect absent")
				}
			}
			if mode == "expired-material-new-claim" {
				var lease time.Time
				if h.admin.QueryRow(`SELECT controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=?`, intent.Backup).Scan(&lease) != nil {
					t.Fatal("original SQL lease")
				}
				until := intent.Deadline
				if lease.After(until) {
					until = lease
				}
				if wait := time.Until(until) + 50*time.Millisecond; wait > 0 {
					time.Sleep(wait)
				}
				aRefreshPublicationPayloadCapacity(t, f.x)
				var version uint64
				if h.admin.QueryRow(`SELECT row_version FROM system_backup_v2_backups WHERE public_id=?`, intent.Backup).Scan(&version) != nil {
					t.Fatal("expired original row version")
				}
				fresh, err := (c.SQLTaskClaimStore{DB: h.db, InstallationID: intent.Installation}).AcquireWithReceipt(ctx, h.token.Target, h.token.Owner, version, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
				if err != nil || fresh.RowVersion <= h.token.RowVersion {
					t.Fatal("actual new claim receipt after old window", err)
				}
				h.token = fresh
			}
			// A successful recovery must work without the original in-memory p and
			// without a CA signer; a failure cannot fall back to fresh material.
			h.owner.Issuer.Signer = nil
			clear(f.request.ManifestInput)
			clear(f.request.IndexBytes)
			f.request = PublicationUploadRequest{}
			recovered, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, PublicationUploadRequest{})
			positive := mode == "secret-create-ack-lost" || mode == "owner-update-ack-lost"
			if positive {
				if err != nil || recovered == nil || recovered.intent != intent {
					t.Fatal("native query-only original material recovery", err)
				}
				recovered.Close()
			} else if err == nil || recovered != nil {
				t.Fatal("unknown/replaced/foreign/released material accepted", mode, err)
			}
			if f.secretCreates != 1 || f.provider.puts != 0 || f.provider.gets != 0 || f.provider.heads != 0 || f.x.logins.Load() != 0 || f.x.decrypts.Load() != 0 {
				t.Fatal("material failure regenerated or reached provider/source")
			}
			if mode == "owner-update-ack-lost" || mode == "owner-update-absent" || mode == "owner-update-forbidden" {
				if f.secretUpdates != 1 {
					t.Fatal("owner update resent", f.secretUpdates)
				}
			}
			rows, err := h.admin.Query(`SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id LIKE 'sev_pub_material_%'`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var body []byte
				if rows.Scan(&body) != nil {
					t.Fatal("material metadata read")
				}
				for _, needle := range []string{"X-Amz-Signature", "PRIVATE KEY", "credential.json", "tls.key"} {
					if bytes.Contains(body, []byte(needle)) {
						t.Fatal("private material entered SQL evidence")
					}
				}
			}
			if rows.Err() != nil {
				t.Fatal("material metadata cursor")
			}
		})
	}
}

func TestPublicationMaterialsRefusePostCommitCreationMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	f := newAPublicationMaterialFixture(t)
	h, ctx := f.x.history, context.Background()
	if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET status='publishing',can_cancel=FALSE,commit_started_at=UTC_TIMESTAMP(6) WHERE public_id=?`, h.original.TaskPublicID); err != nil {
		t.Fatal("actual original post-commit state", err)
	}
	var committed bool
	if h.admin.QueryRow(`SELECT status='publishing' AND can_cancel=FALSE AND commit_started_at IS NOT NULL FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&committed) != nil || !committed {
		t.Fatal("commit point effect absent")
	}
	if job, materials, err := h.service.ensureDurableSuspendedPublicationJob(ctx, h.token, 1, f.store.config, f.request); err == nil || job != nil || materials != nil {
		t.Fatal("post-commit generated/dispatched another private Job", err)
	}
	var staging, sends int
	if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE phase='publish'`).Scan(&staging) != nil || staging != 0 {
		t.Fatal("post-commit reached new candidate/key creation")
	}
	if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE phase='publish'`).Scan(&sends) != nil || sends != 0 || f.secretCreates != 0 || f.jobCreates != 0 {
		t.Fatal("post-commit reached original 121/native creation")
	}
	if f.provider.puts != 0 || f.provider.gets != 0 || f.provider.heads != 0 || f.x.logins.Load() != 0 || f.x.decrypts.Load() != 0 {
		t.Fatal("post-commit preparation reached provider/source")
	}
}
