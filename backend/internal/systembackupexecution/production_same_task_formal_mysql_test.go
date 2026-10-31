package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Original constructors consume separate local installation-owner, provider,
// verifier-owner and Generate-owner signatures on this SAME task/control pool.
// No replacement key callback is granted by the local TLS protocol model.
func (f *dOriginalSixPartTask) installOriginalFormalMaterials(ctx context.Context, t *testing.T) {
	t.Helper()
	s, owner := f.service, f.owner
	f.provider = newDOriginalProvider(s.Config.Namespace, s.controllerActor.PodUID, s.captureMaterials.Discovery.ControllerServiceAccountUID)
	provider := httptest.NewUnstartedServer(f.provider)
	provider.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: append([]tls.Certificate{}, s.tlsConfig.Certificates...)}
	provider.StartTLS()
	t.Cleanup(provider.Close)
	write := func(name string, raw []byte) string {
		t.Helper()
		file := filepath.Join(f.directory, name)
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("original private formal input")
		}
		return file
	}
	// Config uses snake_case wire names for reference identity.
	var config map[string]any
	if json.Unmarshal(f.config, &config) != nil {
		t.Fatal("original config")
	}
	key := w.KeyBinding{Provider: "external-kms", ProviderKeyID: "original-key", ProviderVersion: "1"}
	for _, entry := range config["references"].([]any) {
		ref := entry.(map[string]any)
		if ref["purpose"] == "kek" {
			key.IdentityHash, key.RegistryVersion = ref["identity_hash"].(string), ref["version"].(string)
		}
	}
	ca := append([]byte{}, owner.Issuer.ServerRoots...)
	providerIdentity, scopeSHA := hash(ca), hash([]byte("explicit local original-key single-provider scope"))
	reference := func(purpose, capability, identity string) reg.TypedReference {
		raw, _ := json.Marshal(map[string]string{"ref_kind": "external_kms_key", "purpose": purpose, "identity_hash": identity, "identity_version": "explicit-local-original-r1", "description_redacted": "explicit local original provider owner input", "kms_capability": capability, "provider_identity_hash": providerIdentity, "scope_hash": scopeSHA})
		return reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}
	}
	binding := reg.Binding{InstallationID: s.Config.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: key.IdentityHash, Version: key.RegistryVersion}, Key: key, Provider: reg.ProviderBinding{Endpoint: provider.URL, KeyName: key.ProviderKeyID, ProviderIdentityHash: providerIdentity, ScopeHash: scopeSHA, CAPEMSHA256: hash(ca), CASource: reg.SourceRecord{SourceID: "explicit-local-original-provider-ca", RecordID: "original-ca", RecordVersion: "v1", ContentSHA256: hash(ca)}}, GenerateRef: reference("data_key_generation", "generate_data_key", hash([]byte("original local Generate reference"))), UnwrapRef: reference("kek_unwrap", "unwrap_data_key", hash([]byte("original local Unwrap reference")))}
	databaseID := reg.DatabaseIdentity{ServerUUID: f.server, Database: f.database}
	var account string
	if f.control.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil {
		t.Fatal("original control identity")
	}
	now := time.Now().UTC()
	installationIssuer, installationKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(installationKey)
	bindingRaw, _ := json.Marshal(binding)
	original := a.OriginalRecord{Binding: binding, Source: reg.SourceRecord{SourceID: "explicit-local-installation-owner", RecordID: "original-key", RecordVersion: "v1", ContentSHA256: hash(bindingRaw)}, Revision: "explicit-local-owner-r1", NotBefore: now.Add(-time.Minute), Until: f.input.Authority.DeadlineAt}
	installationWriter, err := a.NewInstallationAuthorityWriter(f.db, s.Config.InstallationID, databaseID, installationIssuer)
	if err != nil {
		t.Fatal(err)
	}
	originalRaw, _ := json.Marshal(original)
	if _, err := installationWriter.Put(ctx, originalRaw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), originalRaw...)), 0); err != nil {
		t.Fatal("same-task original local installation authority", err)
	}
	baseWorkload := a.ControllerVerifierWorkload{Namespace: s.Config.Namespace, PodName: s.controllerActor.PodName, PodUID: s.controllerActor.PodUID, ServiceAccountName: s.controllerActor.ServiceAccountName, ServiceAccountUID: s.captureMaterials.Discovery.ControllerServiceAccountUID, OwnerKind: "Deployment", OwnerUID: s.captureMaterials.Discovery.ControllerDeploymentUID, ControllerOwner: s.Config.ControllerOwner, ConfigVersion: f.input.Authority.ConfigVersion, ConfigSHA256: f.input.Authority.ConfigSHA256}
	verifierIssuer, verifierKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(verifierKey)
	verifierGrant := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: s.Config.InstallationID, Database: databaseID, DatabaseAccount: account, Workload: baseWorkload, CaptureGrantSHA256: s.Forward.GrantSHA256(), NotBefore: now.Add(-time.Minute), Until: f.input.Authority.DeadlineAt}
	raw, _ := json.Marshal(verifierGrant)
	verifierEnvelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: raw, Signature: ed25519.Sign(verifierKey, append([]byte(a.ControllerVerifierGrantDomain), raw...))})
	verifierWorkload := baseWorkload
	verifierWorkload.GrantSHA256 = hash(verifierEnvelope)
	permission := func(generate bool) a.ProviderCapabilityPermission {
		p := a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "controller-jwt", Role: "controller-unwrap-role", Policy: "controller-unwrap-policy", PolicySHA256: hash([]byte("explicit local unwrap policy")), RoleSHA256: hash([]byte("explicit local unwrap role")), JWTTrustSHA256: hash([]byte("explicit local verifier JWT trust")), Reference: binding.UnwrapRef, ControllerVerifier: &verifierWorkload}
		if generate {
			p.Path, p.AuthMount, p.Role, p.Policy, p.Reference, p.ControllerVerifier = "transit/datakey/plaintext/original-key", "capture-jwt", "capture-generate-role", "capture-generate-policy", binding.GenerateRef, nil
		}
		return p
	}
	capability := func(generate bool) a.ProviderCapabilityPin {
		t.Helper()
		operation, id := k.Generate, "sev_explicit_local_original_generate"
		if !generate {
			operation, id = k.Unwrap, "sev_explicit_local_original_unwrap"
		}
		record := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: operation, Permission: permission(generate)}, Source: reg.SourceRecord{SourceID: "explicit-local-provider-permission-owner", RecordID: id, RecordVersion: "v1"}, Revision: "explicit-local-r1", NotBefore: now.Add(-time.Minute), Until: f.input.Authority.DeadlineAt}
		facts, _ := json.Marshal(record.Facts)
		record.Source.ContentSHA256 = hash(facts)
		issuer, signing, _ := ed25519.GenerateKey(rand.Reader)
		defer clear(signing)
		raw, _ := json.Marshal(record)
		envelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: raw, Signature: ed25519.Sign(signing, append([]byte(a.ProviderCapabilityDomain), raw...))})
		if _, err := f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)`, id, s.Config.InstallationID, envelope, hash(envelope), len(envelope), record.Until); err != nil {
			t.Fatal("original local provider capability", err)
		}
		return a.ProviderCapabilityPin{Source: record.Source, Issuer: issuer}
	}
	generatePin, unwrapPin := capability(true), capability(false)
	permitRoot, permitRootKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(permitRootKey)
	permitPublic, permitSigning, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(permitSigning)
	workerJWT := filepath.Join(f.directory, "workers", "{pod_uid}", "provider-token")
	f.provider.workerJWTFile = workerJWT
	permitGrant := a.ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: binding, Database: databaseID, DatabaseAccount: account, Workload: baseWorkload, SigningPublicKey: permitPublic, GeneratePermission: permission(true), WorkerNamespace: s.Config.Namespace, WorkerServiceAccountName: s.Config.Security.ServiceAccountName, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, WorkerJWTIdentityFile: workerJWT, NotBefore: now.Add(-time.Minute), Until: f.input.Authority.DeadlineAt}
	raw, _ = json.Marshal(permitGrant)
	permitEnvelope, _ := json.Marshal(a.SignedProviderPermitIssuerGrant{Record: raw, Signature: ed25519.Sign(permitRootKey, append([]byte(a.ProviderPermitIssuerGrantDomain), raw...))})
	permitWorkload := baseWorkload
	permitWorkload.GrantSHA256 = hash(permitEnvelope)
	delivery := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: permitPublic, IssuerGrantSHA256: hash(permitEnvelope)}
	materials := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: databaseID, Binding: binding, GenerateCapability: generatePin, UnwrapCapability: unwrapPin, InstallationIssuer: installationIssuer, CAFile: write("original-provider-ca.pem", ca), JWTFile: write("original-verifier-provider.jwt", []byte("explicit-local-original-verifier-projected-jwt")), Workload: verifierWorkload, Grant: a.ControllerVerifierGrantMount{File: write("original-verifier-grant.json", verifierEnvelope), SHA256: hash(verifierEnvelope), Issuer: verifierIssuer}, ProviderPermits: &ProviderPermitDeploymentConfig{Workload: permitWorkload, Grant: a.ProviderPermitIssuerGrantMount{File: write("original-provider-issuer-grant.json", permitEnvelope), SHA256: hash(permitEnvelope), Issuer: permitRoot}, SigningKeyFile: write("original-provider-issuer-signing.key", permitSigning), DeliveryPin: delivery}}
	materials.KubernetesReads = &a.VerifierKubernetesReads{Version: a.VerifierKubernetesReadsVersion, Namespace: baseWorkload.Namespace, NamespaceUID: s.Config.NamespaceUID, PodName: baseWorkload.PodName, PodUID: baseWorkload.PodUID, ServiceAccountName: baseWorkload.ServiceAccountName, ServiceAccountUID: baseWorkload.ServiceAccountUID, OwnerKind: baseWorkload.OwnerKind, OwnerName: s.captureMaterials.Discovery.ControllerDeployment, OwnerUID: baseWorkload.OwnerUID, ReplicaSetName: "d-source-rs", ReplicaSetUID: "d-source-rs-uid"}
	semantic := binding
	for _, ref := range []*reg.TypedReference{&semantic.GenerateRef, &semantic.UnwrapRef} {
		var value map[string]json.RawMessage
		json.Unmarshal(ref.RawJSON, &value)
		delete(value, "description_redacted")
		ref.RawJSON, _ = json.Marshal(value)
		ref.SHA256 = ""
	}
	semanticRaw, _ := json.Marshal(semantic)
	fingerprint, err := reg.BindingFingerprint(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES(?,?,?,?,?,?)`, s.Config.InstallationID, key.IdentityHash, key.RegistryVersion, fingerprint, hash(semanticRaw), bindingRaw); err != nil {
		t.Fatal("original local binding index", err)
	}
	materialRaw, _ := json.Marshal(materials)
	if os.WriteFile(s.Config.FormalVerifier.Path, materialRaw, 0600) != nil {
		t.Fatal("original independent formal material file")
	}
	if err := s.loadFormalVerifier([]FormalVerifierInput{{File: s.Config.FormalVerifier.Path, SHA256: hash(materialRaw)}}); err != nil {
		t.Fatal("original formal material loader", err)
	}
	if err := s.attachFormalVerifier(owner); err != nil {
		t.Fatal("same-task actual original verifier/permit constructors", err)
	}
	if owner.FormalKeys == nil || owner.providerPermits == nil {
		t.Fatal("original independent key constructors not retained")
	}
	kmsConfig := k.Config{Endpoint: provider.URL, InstallationID: s.Config.InstallationID, KeyName: key.ProviderKeyID, Key: key, CAPEM: ca, CASHA256: hash(ca), NotBefore: now.Add(-time.Minute), NotAfter: f.input.Authority.DeadlineAt}
	f.sourceMount.Issuer = f.metadataSigner.Public().(ed25519.PublicKey)
	databaseScope, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-database", Database: &f.sourceSpec}}, f.sourceMount)
	if err != nil {
		t.Fatal("original SQL worker delegation scope", err)
	}
	sourceRecord, _ := json.Marshal(worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: s.Config.InstallationID, ConfigSHA256: f.input.Authority.ConfigSHA256, WorkerNamespace: s.Config.Namespace, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, Operation: "capture-database", ScopeSHA256: databaseScope, CredentialSHA256: f.sourceMount.CredentialSHA256, NotBefore: now.Add(-time.Minute), Until: f.input.Authority.DeadlineAt})
	sourceEnvelope, _ := json.Marshal(worker.SignedFormalSourceGrant{Record: sourceRecord, Signature: ed25519.Sign(f.metadataSigner, append([]byte(worker.FormalSourceGrantDomain), sourceRecord...))})
	f.sourceMount.GrantFile, f.sourceMount.GrantSHA256 = write("original-sql-worker-grant.json", sourceEnvelope), hash(sourceEnvelope)
	for name, operation := range s.captureMaterials.Operations {
		operation.Provider = k.Access{Operation: k.Generate, Endpoint: provider.URL, KeyName: key.ProviderKeyID, Request: w.KeyRequest{Key: key}}
		operation.Formal.PermitDelivery = &delivery
		mapping := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: kmsConfig, PermitDelivery: &delivery}
		if name == ce.Operation {
			mapping.ControlEvidence = s.captureMaterials.ControlEvidenceSource
		}
		if name == "capture-source-redis" {
			mapping.Sources = &s.captureMaterials.Redis
		}
		if name == "capture-skill-objects" {
			mapping.Sources = &s.captureMaterials.Objects
		}
		if name == "capture-database" {
			mapping.Sources = &f.sourceMount
		}
		if strings.HasSuffix(name, "deployment-resources") || strings.HasSuffix(name, "secret-bundle") {
			part := "deployment_resources"
			if strings.HasSuffix(name, "secret-bundle") {
				part = "secret_bundle"
			}
			source := f.resourceSources[part]
			mapping.Resources = &source
		}
		raw, _ := json.Marshal(mapping)
		operation.Formal.ConfigSHA256 = hash(raw)
		immutable := true
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: operation.Workload.FormalMaterials.ConfigMap, Namespace: s.Config.Namespace, UID: types.UID(name + "-mapping-uid")}, Immutable: &immutable, Data: map[string]string{"materials.json": string(raw)}}
		if _, err := owner.Client.CoreV1().ConfigMaps(s.Config.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal("original formal mapping ConfigMap fixture", err)
		}
		operation.MountIdentities[0].UID, operation.MountIdentities[0].SHA256 = string(cm.UID), kube.ContentHash([]any{cm.Data, cm.BinaryData})
		s.captureMaterials.Operations[name] = operation
	}
	f.repinOriginalMetadataSource(t)
}

func (f *dOriginalSixPartTask) composeOriginalPublicRuntime(ctx context.Context, t *testing.T) {
	t.Helper()
	s := f.service
	access, err := RequiredDeploymentCaptureAccess(s.Config, s.controllerActor.ServiceAccountName, s.formalVerifier)
	if err != nil {
		t.Fatal("original complete named runtime access inventory", err)
	}
	allowed := map[authzv1.ResourceAttributes]bool{}
	for _, item := range access {
		names := item.Rule.ResourceNames
		if len(names) == 0 {
			names = []string{""}
		}
		for _, verb := range item.Rule.Verbs {
			for _, name := range names {
				allowed[authzv1.ResourceAttributes{Namespace: item.Namespace, Verb: verb, Group: item.Rule.APIGroups[0], Resource: item.Rule.Resources[0], Name: name}] = true
			}
		}
	}
	f.owner.Client.(*kubefake.Clientset).PrependReactor("create", "selfsubjectaccessreviews", func(action ktest.Action) (bool, runtime.Object, error) {
		review := action.(ktest.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).DeepCopy()
		if review.Spec.ResourceAttributes != nil {
			review.Status.Allowed = allowed[*review.Spec.ResourceAttributes]
		}
		review.Status.Denied = !review.Status.Allowed
		return true, review, nil
	})
	stage, err := s.composeCaptureRuntime(f.control, f.owner)
	if err != nil {
		t.Fatal("same-task actual original NewPublicCapture composition", stage, err)
	}
	if err := s.Runtime.Loop.Guard.Check(ctx); err != nil {
		t.Fatal("original runtime guard", err)
	}
	f.installOriginalKubeLifecycle(ctx, t)
}
