package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
	authnv1 "k8s.io/api/authentication/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

type aOriginalForwardFixture struct {
	store   *nativePublicationS3
	native  *aNativePublicationServer
	domains []byte
}

func (x *aOriginalForwardFixture) options(o *dOriginalSixPartFixtureOptions) {
	o.CaptureDescription = true
	o.PublicationForward = true
	o.BeforeOriginalConfig = func(_ context.Context, t *testing.T, f *dOriginalSixPartTask, values map[string]any) error {
		p := &x.store.config
		p.InstallationID = f.profile.InstallationID
		p.Root = p.InstallationID + "/"
		p.RemoteStagingRoot = "remote-staging/" + p.InstallationID + "/"
		registry := publicationFailureDomainRegistry{Version: "system-backup-original-failure-domains.v1", Installation: p.InstallationID, Revision: "local-native-forward-r1", History: []publicationFailureDomainEvent{{Sequence: 1, Domain: "local-original-source", IdentitySHA256: hash([]byte("named local source failure-domain observation")), State: "active"}, {Sequence: 2, Domain: f.profile.FailureDomain, IdentitySHA256: hash([]byte("named local target failure-domain observation")), State: "active"}}}
		previous, _ := ce.Canonical(registry.History[0])
		registry.History[1].PreviousSHA256 = hash(previous)
		x.domains, _ = ce.Canonical(registry)
		for _, entry := range values["registries"].([]any) {
			r := entry.(map[string]any)
			if r["registry_kind"] == "failure_domains" {
				r["version"], r["sha256"] = registry.Revision, hash(x.domains)
			}
		}
		for _, entry := range values["references"].([]any) {
			r := entry.(map[string]any)
			switch r["purpose"] {
			case "artifact_read":
				r["identity_hash"], r["version"] = p.ReadIdentityHash, p.ReadRefVersion
			case "artifact_write":
				r["identity_hash"], r["version"] = p.WriteIdentityHash, p.WriteRefVersion
			case "artifact_ca":
				r["identity_hash"], r["version"] = p.CAIdentityHash, p.CARefVersion
			}
		}
		return nil
	}
	before := o.BeforeCoreSeal
	o.BeforeCoreSeal = func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, core *DeploymentConfig) error {
		if before != nil {
			if err := before(ctx, t, f, core); err != nil {
				return err
			}
		}
		file := filepath.Join(f.directory, "original-native-publication-target.json")
		raw, _ := json.Marshal(x.store.config)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			return err
		}
		core.PublicationTarget = &PublicationTargetReference{Protocol: publicationTargetVersion, Path: file}
		core.PublicationWorker = &PublicationWorkerReference{Protocol: publicationPresignedUploadVersion, ServiceAccountName: "a-original-upload", ServiceAccountUID: "a-original-upload-sa"}
		return nil
	}
}

// Explicit local administrator and permission-observer fixtures, independently
// signed before Prepare. These authenticate test evidence only; the named local
// domains do not certify production physical isolation or recovery readiness.
func (x *aOriginalForwardFixture) publisher(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, p *PublisherVerifierMaterials) error {
	owner, sig, err := (a.SQLOriginalReader{DB: f.db}).ReadOriginal(ctx, p.Binding.InstallationID, p.Binding.ConfigRef)
	if err != nil {
		return err
	}
	var record a.OriginalRecord
	if json.Unmarshal(owner, &record) != nil {
		return fmt.Errorf("original owner unavailable")
	}
	now := time.Now().UTC()
	until := f.input.Authority.DeadlineAt
	if a.InspectOriginalKEKMaterial(owner, sig, p.InstallationIssuer, hash(owner), p.Binding.InstallationID, record.Revision, p.Binding.ConfigRef, now) != nil {
		return fmt.Errorf("original owner verification")
	}
	capPublic, capKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(capKey)
	attPublic, attKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(attKey)
	capRecord := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: p.Binding, Operation: kms.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/" + p.Binding.Provider.KeyName, ProviderVersion: p.Binding.Key.ProviderVersion, AuthMount: "local-recovery-jwt", Role: "local-independent-recovery", Policy: "local-independent-recovery", PolicySHA256: hash([]byte("local observer original recovery policy")), RoleSHA256: hash([]byte("local observer original recovery role")), JWTTrustSHA256: hash([]byte("local observer original recovery JWT trust")), Reference: p.Binding.UnwrapRef}}, Source: reg.SourceRecord{SourceID: "explicit-local-independent-recovery-observer", RecordID: "sev_a_original_recovery_capability", RecordVersion: "local-r1"}, Revision: "local-r1", NotBefore: now.Add(-time.Minute), Until: until}
	capFacts, _ := json.Marshal(capRecord.Facts)
	capRecord.Source.ContentSHA256 = hash(capFacts)
	capPayload, _ := json.Marshal(capRecord)
	capRaw, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capPayload, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capPayload...))})
	pin, err := originalFailureDomainsPin(f.config)
	if err != nil {
		return err
	}
	config, err := security.DecodeConfigValues(f.config)
	if err != nil {
		return err
	}
	statement := publicationFailureDomainAttestation{Version: "system-backup-original-failure-domain-attestation.v1", ID: "sev_a_original_failure_domain_attestation", Installation: p.Binding.InstallationID, ConfigSHA256: hash(f.config), Registry: pin, TargetDomain: f.profile.FailureDomain, TargetSHA256: publicationRecoveryTargetSHA(x.store.config), SourceDomains: []string{"local-original-source"}, Dependencies: []publicationRecoveryDependency{}, CapabilitySHA256: hash(capRaw), OwnerRecordSHA256: hash(owner), Actor: "explicit-local-administrator", AuditID: "explicit-local-original-forward-audit", Issued: now, Expires: until}
	for _, ref := range config.References() {
		statement.Dependencies = append(statement.Dependencies, publicationRecoveryDependency{Purpose: ref.Purpose, IdentitySHA256: ref.IdentityHash, Version: ref.Version, Domain: f.profile.FailureDomain})
	}
	statementRaw, _ := ce.Canonical(statement)
	attRaw, _ := ce.Canonical(publicationSignedAttestation{Payload: statementRaw, Signature: ed25519.Sign(attKey, append([]byte(publicationAttestationDomain), statementRaw...))})
	selection := publicationRecoverySelection{Attestation: publicationEvidencePin{ID: statement.ID, SHA256: hash(attRaw)}, Capability: publicationEvidencePin{ID: capRecord.Source.RecordID, SHA256: hash(capRaw)}, OwnerRecordSHA256: hash(owner), OwnerRevision: record.Revision}
	p.RecoveryTrust = &PublicationRecoveryTrust{Selection: selection, AttestationIssuer: attPublic, Capability: a.ProviderCapabilityPin{Source: capRecord.Source, Issuer: capPublic}, FailureDomainRegistry: x.domains, SourceDomains: []string{"local-original-source"}}
	for _, item := range []struct {
		id, kind string
		raw      []byte
	}{{selection.Attestation.ID, "failure_domain_attestation", attRaw}, {selection.Capability.ID, "capability_snapshot", capRaw}} {
		if len(item.raw) > 8192 {
			return fmt.Errorf("local original evidence exceeds unchanged inline limit")
		}
		if _, err = f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,media_type,inline_payload,content_checksum,content_size_bytes,expires_at) VALUES(?,'system',?,?,'inline','healthy','none','application/json',?,?,?,?)`, item.id, p.Binding.InstallationID, item.kind, item.raw, hash(item.raw), len(item.raw), until); err != nil {
			return err
		}
	}
	id, sha := selection.Attestation.ID, selection.Attestation.SHA256
	policy := originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: p.Binding.InstallationID, ConfigSHA256: hash(f.config), FailureDomains: pin, Target: publicationManifestTarget{Class: f.profile.TargetClass, Domain: f.profile.FailureDomain, Risks: append([]string{}, f.profile.TargetRisks...), AttestationID: &id, AttestationSHA256: &sha}, RecoveryEvidenceStatus: "provided", RecoveryEvidence: &selection}
	raw, _ := ce.Canonical(policy)
	file := filepath.Join(f.directory, "original-positive-publication-policy.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		return err
	}
	f.service.captureMaterials.Discovery.PublicationPolicy = &originalPublicationPolicyReference{Protocol: originalPublicationPolicyVersion, Path: file, SHA256: hash(raw)}
	f.repinOriginalMetadataSource(t)
	targetRaw, _ := json.Marshal(x.store.config)
	if err = f.service.loadPublicationTargetInput([]PublicationTargetInput{{File: f.service.Config.PublicationTarget.Path, SHA256: hash(targetRaw)}}); err != nil {
		return err
	}
	return f.owner.Client.(*kubefake.Clientset).Tracker().Add(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: f.service.Config.Namespace, Name: f.service.Config.PublicationWorker.ServiceAccountName, UID: types.UID(f.service.Config.PublicationWorker.ServiceAccountUID)}})
}

func aInstallOriginalUploadNativeAPI(t *testing.T, f *dOriginalSixPartTask) (*int, *int) {
	t.Helper()
	client := f.owner.Client.(*kubefake.Clientset)
	creates, patches := new(int), new(int)
	// client-go's tracker does not assign API-server metadata. Model those
	// native facts explicitly; never weaken production UID/RV/body checks.
	client.PrependReactor("create", "secrets", func(action kt.Action) (bool, runtime.Object, error) {
		secret := action.(kt.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
		if !strings.HasPrefix(secret.Name, "sbp-") {
			return false, nil, nil
		}
		body, err := publicationMaterialBody(secret)
		clear(body)
		if err != nil || secret.UID != "" || secret.ResourceVersion != "" {
			return true, nil, fmt.Errorf("original native Secret creation shape")
		}
		secret.UID, secret.ResourceVersion = types.UID(uuid.NewString()), "1"
		if err = client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
			return true, nil, err
		}
		return true, secret, nil
	})
	client.PrependReactor("update", "secrets", func(action kt.Action) (bool, runtime.Object, error) {
		secret := action.(kt.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		if !strings.HasPrefix(secret.Name, "sbp-") {
			return false, nil, nil
		}
		current, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), secret.Namespace, secret.Name)
		if err != nil {
			return true, nil, err
		}
		old := current.(*corev1.Secret)
		before, beforeErr := publicationMaterialBody(old)
		after, afterErr := publicationMaterialBody(secret)
		defer clear(before)
		defer clear(after)
		version, versionErr := strconv.ParseUint(old.ResourceVersion, 10, 64)
		if beforeErr != nil || afterErr != nil || versionErr != nil || version == ^uint64(0) || old.UID != secret.UID || old.ResourceVersion != secret.ResourceVersion || !bytes.Equal(before, after) {
			return true, nil, fmt.Errorf("original native immutable Secret UID/RV/body changed")
		}
		secret.ResourceVersion = strconv.FormatUint(version+1, 10)
		if err = client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
			return true, nil, err
		}
		return true, secret, nil
	})
	client.PrependReactor("create", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
		job := action.(kt.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		if !strings.HasPrefix(job.Name, "sbp-") {
			return false, nil, nil
		}
		*creates++
		if job.Spec.Suspend == nil || !*job.Spec.Suspend {
			return true, nil, fmt.Errorf("original upload Create must remain suspended")
		}
		job.UID, job.Generation, job.ResourceVersion = types.UID(uuid.NewString()), 1, "1"
		if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
			return true, nil, err
		}
		return true, job, nil
	})
	client.PrependReactor("patch", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
		patch := action.(kt.PatchAction)
		if !strings.HasPrefix(patch.GetName(), "sbp-") {
			return false, nil, nil
		}
		*patches++
		if patch.GetPatchType() != types.JSONPatchType {
			return true, nil, fmt.Errorf("original upload patch type")
		}
		object, err := client.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), patch.GetNamespace(), patch.GetName())
		if err != nil {
			return true, nil, err
		}
		job := object.(*batchv1.Job).DeepCopy()
		var ops []struct {
			Op, Path string
			Value    json.RawMessage
		}
		if json.Unmarshal(patch.GetPatch(), &ops) != nil || len(ops) != 5 {
			return true, nil, fmt.Errorf("original upload patch shape")
		}
		paths := []string{"/metadata/uid", "/metadata/resourceVersion", "/metadata/generation", "/spec/suspend", "/spec/suspend"}
		for i, value := range []any{string(job.UID), job.ResourceVersion, job.Generation, true, false} {
			raw, _ := json.Marshal(value)
			op := "test"
			if i == 4 {
				op = "replace"
			}
			if ops[i].Op != op || ops[i].Path != paths[i] || !bytes.Equal(ops[i].Value, raw) {
				return true, nil, fmt.Errorf("original upload conditional patch")
			}
		}
		no := false
		job.Spec.Suspend = &no
		job.Generation++
		job.ResourceVersion = "2"
		if err = client.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
			return true, nil, err
		}
		return true, job, nil
	})
	return creates, patches
}

func TestAOriginalSixPartManifestUploadJobMySQL(t *testing.T) {
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires exclusively handed-over original SAN/TLS MySQL")
	}
	previous := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(previous)
	store, native := newANativePublicationStore(t, 20*time.Minute)
	x := &aOriginalForwardFixture{store: store, native: native}
	fixture := &aSameTaskCertificateMaterials{configureOptions: x.options, configurePublisher: x.publisher}
	runAOriginalSixPartCertificatePublicationFixture(t, "capture-description", fixture, func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		creates, patches := aInstallOriginalUploadNativeAPI(t, f)
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		request, err := f.service.prepareOriginalForwardRequest(ctx, claim, capture.Input.CaptureAttemptNo, policy, capture, store.config)
		if err != nil {
			t.Fatal("original complete manifest request", err)
		}
		m, err := decodePublicationManifestV12(request.ManifestInput)
		if err != nil || m.Purpose != "acceptance" || len(m.Eligibility.Disqualifiers) != 0 || len(request.Objects) != 15 {
			t.Fatal("original complete acceptance MF facts", err)
		}
		job, err := f.service.ensureStartedPublicationJob(ctx, *claim, capture.Input.CaptureAttemptNo, store.config, request)
		if err != nil || job == nil || job.Spec.Suspend == nil || *job.Spec.Suspend || *creates != 1 || *patches != 1 {
			t.Fatal("original native upload Job create/activation", err, *creates, *patches)
		}
		material, err := f.service.preparePublicationJobMaterials(ctx, *claim, capture.Input.CaptureAttemptNo, store.config, PublicationUploadRequest{})
		if err != nil {
			t.Fatal(err)
		}
		defer material.Close()
		initial, err := f.service.readOriginalPublicationUploadCompletion(ctx, *claim, material, job)
		if err != nil {
			t.Fatal("original SQL NULL upload cursor before first result", err)
		}
		if data, err := originalPublicationUploadedData(initial); !errors.Is(err, ErrJobUncertain) || data != nil {
			t.Fatal("original empty upload was treated as complete", err)
		}
		input, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		output, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer output.Close()
		inputs, err := f.service.publicationJobInputs(ctx, *claim, capture.Input.CaptureAttemptNo, material.request)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range inputs {
			if err = input.MkdirAll(filepath.Dir(file.Path), 0700); err != nil {
				t.Fatal(err)
			}
			source, err := f.owner.Staging.Open(file.SubPath)
			if err != nil {
				t.Fatal(err)
			}
			dest, err := input.OpenFile(file.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				source.Close()
				t.Fatal(err)
			}
			_, copyErr := io.Copy(dest, source)
			close1, close2 := dest.Close(), source.Close()
			if copyErr != nil || close1 != nil || close2 != nil {
				t.Fatal("native read-only input projection", copyErr, close1, close2)
			}
		}
		directory := t.TempDir()
		grantFile := filepath.Join(directory, "put-grants.json")
		caFile := filepath.Join(directory, "artifact-ca.crt")
		if os.WriteFile(grantFile, material.secret.Data["credential.json"], 0600) != nil || os.WriteFile(caFile, material.secret.Data["artifact-ca.crt"], 0600) != nil {
			t.Fatal("original private upload projections")
		}
		result, err := RunPublicationUploadOnly(ctx, material.secret.Data["request.json"], caFile, grantFile, input, output)
		if err != nil || len(result.Objects) != 15 {
			t.Fatal("actual upload-only worker", err)
		}
		objects := aOriginalUploadReadObjectsData(material.request.Objects, result.Objects)
		limits, err := artifactLimitsFromConfigSnapshot(capture.Input.ConfigSnapshot, capture.Input.ConfigSHA256)
		if err != nil {
			t.Fatal(err)
		}
		set, err := selectPublicationRemoteCaptureSet(capture.Input.InstallationID, capture.Input.TaskPublicID, capture.Input.CaptureAttemptNo, store.config.Root, capture.CaptureContextSHA256, material.request.IndexBytes, hash(material.request.IndexBytes), objects, limits)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), limits)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if err = reader.inspectPublicationRemoteCaptureSetBytes(ctx, set, material.intent.Deadline); err != nil {
			t.Fatal("independent fifteen fixed native body reads", err)
		}
		// Result hints still enter the original mTLS + Pod TokenReview receiver.
		aSendOriginalForwardResults(ctx, t, f, job, material, result, directory)
		// The actual local upload-only worker and result sender have returned.
		// Model that native exit fact; it cannot replace SQL result validation.
		finished := job.DeepCopy()
		finished.Status = batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}
		if err = f.owner.Client.(*kubefake.Clientset).Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), finished, finished.Namespace); err != nil {
			t.Fatal(err)
		}
		if err = f.service.awaitOriginalPublicationUpload(ctx, *claim, capture.Input.CaptureAttemptNo, store.config, time.Second, nil); err != nil {
			t.Fatal("original SQL/native upload completion wait", err)
		}
		uploaded, err := f.service.readOriginalPublicationUploadedData(ctx, *claim, capture.Input.CaptureAttemptNo, store.config)
		if err != nil || uploaded == nil || len(uploaded.Objects) != 15 || !bytes.Equal(uploaded.Manifest, request.ManifestInput) || uploaded.Candidate.Version != result.Candidate.Version || *creates != 1 || *patches != 1 {
			t.Fatal("original public upload DATA for independent C", err, *creates, *patches)
		}
		t.Log("same original task complete MF / actual one-send upload Job / fifteen fixed native bytes", f.publicID, "job", string(job.UID), "objects", len(result.Objects), "candidate-version", result.Candidate.Version, "signs", fixture.signs.Load())
		t.Log("No complete remote-C, marker, acceptance/catalog or terminal-success claim is made by byte readback alone")
	})
}

func aOriginalUploadReadObjectsData(expected []PublicationUploadInput, observations []PublicationUploadObservation) map[string]ArtifactReadObject {
	if len(expected) != len(observations) {
		return nil
	}
	objects := make(map[string]ArtifactReadObject, len(expected))
	for i, observed := range observations {
		objects[expected[i].Path] = ArtifactReadObject{Key: observed.Key, Version: observed.Version, SHA256: observed.SHA256, Size: observed.Bytes}
	}
	return objects
}

func TestOriginalForwardUploadReadSetRequiresRelativePathMapData(t *testing.T) {
	observed := originalUploadPollFixtureData(t)
	request := observed.Request
	manifest, err := decodePublicationManifestV12(request.ManifestInput)
	if err != nil {
		t.Fatal(err)
	}
	var uploaded []PublicationUploadObservation
	for _, message := range observed.Messages[:len(request.Objects)] {
		uploaded = append(uploaded, message.Object)
	}
	objects := aOriginalUploadReadObjectsData(request.Objects, uploaded)
	limits := ArtifactReadLimits{MaxArtifactBytes: 64 << 20, MaxIndexBytes: 1 << 20}
	set, err := selectPublicationRemoteCaptureSet(request.Installation, request.Backup, request.Attempt, request.ArtifactRoot, manifest.CaptureContext, request.IndexBytes, hash(request.IndexBytes), objects, limits)
	if err != nil || set == nil {
		t.Fatal("native upload observations were not projected as relative-path DATA", err)
	}
	for i, input := range request.Objects {
		object, exists := objects[input.Path]
		if !exists || object.Key != uploaded[i].Key || object.Version != uploaded[i].Version {
			t.Fatal("relative-path projection changed original fixed key/version")
		}
	}
}

func aSendOriginalForwardResults(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, job *batchv1.Job, m *publicationJobMaterials, result PublicationUploadResult, directory string) {
	t.Helper()
	client := f.owner.Client.(*kubefake.Clientset)
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: job.Namespace, Name: job.Name + "-pod", UID: types.UID(uuid.NewString()), Labels: map[string]string{"backup.clawmanager.io/v2-task": f.publicID}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
	if err := client.Tracker().Add(pod); err != nil {
		t.Fatal(err)
	}
	token := "local-original-upload-token-" + string(pod.UID)
	client.PrependReactor("create", "tokenreviews", func(action kt.Action) (bool, runtime.Object, error) {
		review := action.(kt.CreateAction).GetObject().(*authnv1.TokenReview).DeepCopy()
		if review.Spec.Token != token {
			return false, nil, nil
		}
		review.Status = authnv1.TokenReviewStatus{Authenticated: true, Audiences: append([]string{}, review.Spec.Audiences...), User: authnv1.UserInfo{Username: "system:serviceaccount:" + pod.Namespace + ":" + pod.Spec.ServiceAccountName, UID: f.service.Config.PublicationWorker.ServiceAccountUID, Extra: map[string]authnv1.ExtraValue{"authentication.kubernetes.io/pod-name": {pod.Name}, "authentication.kubernetes.io/pod-uid": {string(pod.UID)}}}}
		return true, review, nil
	})
	identity := filepath.Join(directory, "identity")
	if os.Mkdir(identity, 0700) != nil {
		t.Fatal("local private identity directory")
	}
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		if os.WriteFile(filepath.Join(identity, name), m.secret.Data[name], 0600) != nil {
			t.Fatal("original upload identity projection")
		}
	}
	tokenFile := filepath.Join(directory, "token")
	if os.WriteFile(tokenFile, []byte(token), 0600) != nil {
		t.Fatal("original bound token projection")
	}
	endpoint, err := url.Parse(f.service.Config.ControlURL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Path = PublicationResultPath
	if err = SendPublicationUploadResult(ctx, endpoint.String(), identity, tokenFile, m.secret.Data["request.json"], result); err != nil {
		t.Fatal("original upload mTLS/TokenReview result receiver", err)
	}
}

func TestOriginalForwardNativeAPISecretIdentityData(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	f := &dOriginalSixPartTask{owner: &PublicJobOwner{Client: client}}
	creates, patches := aInstallOriginalUploadNativeAPI(t, f)
	yes := true
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "local-data", Name: "sbp-data-upload"}, Immutable: &yes, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
	for _, key := range []string{"request.json", "credential.json", "artifact-ca.crt", "ca.crt", "tls.crt", "tls.key"} {
		secret.Data[key] = []byte("inert-local-model-data-" + key)
	}
	before, err := publicationMaterialBody(secret)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CoreV1().Secrets(secret.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil || created.UID == "" || created.ResourceVersion == "" {
		t.Fatal("native model omitted Secret UID/resourceVersion", err)
	}
	created.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "sbp-data-job", UID: "local-data-job", Controller: &yes}}
	updated, err := client.CoreV1().Secrets(secret.Namespace).Update(context.Background(), created, metav1.UpdateOptions{})
	if err != nil || updated.UID != created.UID || updated.ResourceVersion == created.ResourceVersion {
		t.Fatal("native model failed original UID/resourceVersion update", err)
	}
	after, err := publicationMaterialBody(updated)
	if err != nil || !bytes.Equal(before, after) || *creates != 0 || *patches != 0 {
		t.Fatal("native Secret metadata update changed immutable bytes or sent a Job", err)
	}
}
