package install

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Real signatures and original installer entry, with the existing SQL model,
// fake Kubernetes graph and local TLS Vault protocol. Not native integration.
func firstCaptureDraftSources(t *testing.T, ctx context.Context, mutate func(*OriginalPublicationSigningFiles, *sec.InstallationSigningRecord)) (*authorityFixture, OriginalFirstCaptureDraftInputs) {
	t.Helper()
	f := newAuthorityFixture(t)
	b := f.record.Binding
	b.KeyVersion = "1"
	identity, e := owner.ReferenceIdentity(b)
	if e != nil {
		t.Fatal(e)
	}
	f.config = authorityConfig(t, sec.BootstrapSecretRef{Purpose: "capture_signing", IdentityHash: identity, Version: "1"})
	f.grant.ConfigSHA256 = f.config.SHA256()
	f.record.ConfigSHA256 = f.config.SHA256()
	grantJSON, _ := json.Marshal(f.grant)
	f.record.GrantSHA256 = hash(grantJSON)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(f.config.CanonicalJSON(), &fields)
	f.record.RegistrySetSHA256 = hash(fields["registries"])
	f.record.ReferenceSetSHA256 = hash(fields["references"])
	write := func(path string, raw []byte) BootstrapSourceFilePin {
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return BootstrapSourceFilePin{File: path, SHA256: hash(raw)}
	}
	write(f.files.ConfigFile, f.config.CanonicalJSON())
	f.files.ConfigFileSHA256 = f.config.SHA256()
	grantDoc, e := canonical(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: f.record.NotBefore.Add(-time.Minute), ExpiresAt: f.record.Until.Add(time.Minute), Grant: f.grant})
	if e != nil {
		t.Fatal(e)
	}
	f.files.GrantFileSHA256 = write(f.files.GrantFile, grantDoc).SHA256
	controller := true
	refs := []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "controller-deployment", UID: "deployment-original", Controller: &controller}}
	if _, e := f.i.kube.AppsV1().Deployments(b.Namespace).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller-deployment", Namespace: b.Namespace, UID: "deployment-original"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: b.ServiceAccountName}}}}, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.i.kube.AppsV1().ReplicaSets(b.Namespace).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-replicaset", Namespace: b.Namespace, UID: "replicaset-original", OwnerReferences: refs}}, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	pod, e := f.i.kube.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller-replicaset", UID: "replicaset-original", Controller: &controller}}
	if _, e := f.i.kube.CoreV1().Pods(b.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	docRaw, e := os.ReadFile(f.files.ObserverFile)
	var doc observerDocument
	if e != nil || decodeExact(docRaw, &doc) != nil {
		t.Fatal("original observer")
	}
	jwt, e := os.ReadFile(doc.RuntimeJWTFile)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(jwt)
	m := OriginalPublicationSigningFiles{Version: "original-publication-signing-material.v1", PlanSHA256: f.i.planHash, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, CaptureObserver: BootstrapSourceFilePin{File: f.files.ObserverFile, SHA256: f.files.ObserverFileSHA256}, CA: BootstrapSourceFilePin{File: doc.CAFile, SHA256: doc.CASHA256}, Trust: doc.Trust, JWTFiles: map[string]BootstrapSourceFilePin{}, Histories: f.record.Histories}
	signed := sec.InstallationSigningRecord{InstallationID: b.InstallationID, Revision: 1, NotBefore: f.record.NotBefore, Until: f.record.Until}
	for n := range m.Histories {
		m.Histories[n].Keys = append([]owner.PublicKey(nil), m.Histories[n].Keys...)
		m.Histories[n].Keys[0].ProtectedUntil = signed.Until
	}
	for _, h := range m.Histories {
		binding := b
		binding.Purpose, binding.KeyID, binding.KeyName = h.Purpose, h.KeyName, h.KeyName
		m.Bindings = append(m.Bindings, binding)
		m.JWTFiles[h.Purpose] = BootstrapSourceFilePin{File: doc.RuntimeJWTFile, SHA256: hash(jwt)}
		pub, e := base64.StdEncoding.DecodeString(h.Keys[0].PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		signed.Keys = append(signed.Keys, sec.ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: h.Purpose, KeyID: h.KeyName, KeyVersion: "1", PublicKey: pub, NotBefore: signed.NotBefore, NotAfter: signed.Until})
		signed.Permissions = append(signed.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: h.Purpose, KeyID: h.KeyName, KeyVersion: "1", Endpoint: b.Endpoint, KeyName: h.KeyName, ProviderVersion: b.ProviderVersion}, AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, CASHA256: b.CASHA256})
	}
	if mutate != nil {
		mutate(&m, &signed)
	}
	recordRaw, e := canonical(signed)
	if e != nil {
		t.Fatal(e)
	}
	m.Record = sec.FileSigningRecordReader{RecordFile: filepath.Join(dir, "installation-signing.record.json"), SignatureFile: filepath.Join(dir, "installation-signing.signature")}
	write(m.Record.RecordFile, recordRaw)
	write(m.Record.SignatureFile, ed25519.Sign(f.key, append([]byte(sec.InstallationSigningDomain), recordRaw...)))
	m.Pin = sec.InstallationSigningPin{InstallationID: f.i.plan.Target.InstallationID, Revision: 1, RecordSHA256: hash(recordRaw), Issuer: f.i.public}
	materialRaw, e := canonical(m)
	if e != nil {
		t.Fatal(e)
	}
	material := write(filepath.Join(dir, "original-publication-signing.material.json"), materialRaw)
	write(filepath.Join(dir, "original-publication-signing.material.signature"), ed25519.Sign(f.key, append([]byte(originalPublicationSigningMaterialDomain), materialRaw...)))
	_, selected := firstCaptureSelectionFor(t, f)
	selectionRaw, e := canonical(selected)
	if e != nil {
		t.Fatal(e)
	}
	selection := write(filepath.Join(dir, "original-selection.json"), selectionRaw)
	out := t.TempDir()
	if e := os.Chmod(out, 0700); e != nil {
		t.Fatal(e)
	}
	return f, OriginalFirstCaptureDraftInputs{Request: f.files, SigningMaterial: material, Selection: selection, ControllerDeployment: "controller-deployment", ControllerPodName: b.PodName, OutputDirectory: out, Until: f.record.Until}
}

func TestOriginalFirstCaptureDraftOriginalIssueAndImportModel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, in := firstCaptureDraftSources(t, ctx, nil)
	result, e := f.i.PrepareOriginalFirstCaptureDraft(ctx, f.password, f.enrollment, in)
	if e != nil {
		t.Fatal("prepare original draft", e)
	}
	draft, e := readBootstrapSourcePin(result.Draft, 262144)
	if e != nil || result.State != "unsigned_draft_requires_original_issue_and_import" {
		t.Fatal("draft result", e)
	}
	if _, e := f.i.PrepareOriginalFirstCaptureDraft(ctx, f.password, f.enrollment, in); e == nil {
		t.Fatal("replaced create-only output")
	}
	pack, e := f.i.IssueCapture(ctx, f.password, f.enrollment, draft, result.Draft.SHA256, f.key, in.Request)
	if e != nil {
		t.Fatal("original native-protocol capture issue", e)
	}
	if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), in.Request); e != nil {
		t.Fatal("original import model", e)
	}
	next := t.TempDir()
	if e := os.Chmod(next, 0700); e != nil {
		t.Fatal(e)
	}
	in.OutputDirectory = next
	if _, e := f.i.PrepareOriginalFirstCaptureDraft(ctx, f.password, f.enrollment, in); e == nil {
		t.Fatal("nonzero head accepted")
	}
}

func TestOriginalFirstCaptureDraftRejectsContradictorySignedSourcesModel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*OriginalPublicationSigningFiles, *sec.InstallationSigningRecord)
	}{
		{"wrong_installation", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			s.InstallationID = "installation_other"
		}},
		{"revoked", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) { s.Keys[0].Revoked = true }},
		{"missing_history", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			m.Histories = m.Histories[:2]
		}},
		{"wrong_pod", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			m.Bindings[1].PodUID = "other-original-pod"
		}},
		{"missing_jwt", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			delete(m.JWTFiles, "capture_certificate")
		}},
		{"wrong_enrollment", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			m.EnrollmentDocumentSHA256 = hash([]byte("other-enrollment"))
		}},
		{"expired_original_authorization", func(m *OriginalPublicationSigningFiles, s *sec.InstallationSigningRecord) {
			s.NotBefore, s.Until = time.Now().Add(-2*time.Hour).UTC().Truncate(time.Microsecond), time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
			for n := range s.Keys {
				s.Keys[n].NotBefore, s.Keys[n].NotAfter = s.NotBefore, s.Until
				m.Histories[n].Keys[0].ProtectedUntil = s.Until
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f, in := firstCaptureDraftSources(t, ctx, tc.mutate)
			if _, e := f.i.PrepareOriginalFirstCaptureDraft(ctx, f.password, f.enrollment, in); e == nil {
				t.Fatal("contradictory signed source accepted")
			}
			entries, e := os.ReadDir(in.OutputDirectory)
			if e != nil || len(entries) != 0 {
				t.Fatal("failed before write must leave no draft", e)
			}
		})
	}
	t.Run("expired_original_request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		f, in := firstCaptureDraftSources(t, ctx, nil)
		in.Until = time.Now().Add(-time.Minute)
		if _, e := f.i.PrepareOriginalFirstCaptureDraft(ctx, f.password, f.enrollment, in); e == nil {
			t.Fatal("expired accepted")
		}
	})
}
