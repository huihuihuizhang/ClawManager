package systembackupexecution

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestOriginalCaptureMappingCreateAndIndependentGetRejectExistingDrift(t *testing.T) {
	for _, kind := range []string{"ConfigMap", "Secret"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			s := &OriginalCaptureSequence{core: DeploymentConfig{Namespace: "original-source", NamespaceUID: "original-namespace-uid"}}
			client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: s.core.Namespace, UID: types.UID(s.core.NamespaceUID)}})
			creates := 0
			client.PrependReactor("create", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				creates++
				object := action.(ktesting.CreateAction).GetObject().DeepCopyObject()
				var meta *metav1.ObjectMeta
				switch v := object.(type) {
				case *corev1.ConfigMap:
					meta = &v.ObjectMeta
				case *corev1.Secret:
					meta = &v.ObjectMeta
				default:
					t.Fatal("unexpected create")
				}
				meta.UID, meta.ResourceVersion = "independently-read-object-uid", "1"
				if err := client.Tracker().Create(action.GetResource(), object, s.core.Namespace); err != nil {
					return true, nil, err
				}
				// An untrusted create response must never supply the accepted UID.
				response := object.DeepCopyObject()
				switch v := response.(type) {
				case *corev1.ConfigMap:
					v.UID = "forged-create-response"
				case *corev1.Secret:
					v.UID = "forged-create-response"
				}
				return true, response, nil
			})
			expected := &originalMappingObject{kind: kind, name: "original-input", data: map[string][]byte{"grant.json": []byte("component-original-fixed-bytes")}}
			first, err := s.createOriginalMappingObject(ctx, client, expected)
			if err != nil || first.UID != "independently-read-object-uid" || creates != 1 {
				t.Fatal("independent immutable readback", err)
			}
			second, err := s.createOriginalMappingObject(ctx, client, expected)
			if err != nil || second != first || creates != 1 {
				t.Fatal("exact retry changed existing original object", err)
			}
			expected.data["grant.json"] = []byte("drifted-original-input")
			if _, err := s.createOriginalMappingObject(ctx, client, expected); err == nil || creates != 1 {
				t.Fatal("existing source drift overwritten/accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "create" {
					t.Fatal("mutable/delete API used")
				}
			}
		})
	}
}

func TestOriginalCaptureMappingCannotBorrowAnotherOperationFiles(t *testing.T) {
	grantSHA, credentialSHA := hash([]byte("original-grant")), hash([]byte("original-credential"))
	mapping := worker.FormalCaptureMaterials{Sources: &worker.FormalSourceMount{GrantFile: "/run/backup/materials/source/grant.json", GrantSHA256: grantSHA, CredentialFile: "/run/backup/materials/source/credential.json", CredentialSHA256: credentialSHA}}
	files := map[string]OriginalCaptureMappingFile{mapping.Sources.GrantFile: {File: "original-grant", SHA256: grantSHA}}
	if checkOriginalMappingDependencies(mapping, files, "") == nil {
		t.Fatal("missing operation credential projection accepted")
	}
	files[mapping.Sources.CredentialFile] = OriginalCaptureMappingFile{File: "original-credential", SHA256: credentialSHA}
	if err := checkOriginalMappingDependencies(mapping, files, ""); err != nil {
		t.Fatal("complete exact dependencies rejected", err)
	}
	files[mapping.Sources.CredentialFile] = OriginalCaptureMappingFile{File: "foreign-credential", SHA256: grantSHA}
	if checkOriginalMappingDependencies(mapping, files, "") == nil {
		t.Fatal("foreign original credential bytes accepted")
	}
	objects := map[string]*originalMappingObject{}
	if mergeOriginalMappingObject(objects, "Secret", "original-input", "key", []byte("one"), false) != nil || mergeOriginalMappingObject(objects, "Secret", "original-input", "key", []byte("two"), false) == nil {
		t.Fatal("conflicting shared original key accepted")
	}
}

func TestOriginalCaptureMappingFailureLatchesRealOwnerSequenceComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	sequence, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(sequence.materials.Redis.GrantFile)
	if err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset()
	if _, err := sequence.MaterializeMappings(ctx, client, filepath.Join(filepath.Dir(f.definitionFile), "missing-components.json"), hash([]byte("missing")), filepath.Join(filepath.Dir(f.definitionFile), "intermediate.json")); err == nil {
		t.Fatal("missing original components accepted")
	}
	queries := f.model.queries.Load()
	if _, _, err := sequence.WorkerSourceMounts(ctx); err == nil || f.model.queries.Load() != queries {
		t.Fatal("failed sequence resumed original signing")
	}
	after, err := os.ReadFile(sequence.materials.Redis.GrantFile)
	if err != nil || !bytes.Equal(before, after) || len(client.Actions()) != 0 || f.model.executions.Load() != 0 {
		t.Fatal("failed materialization changed original source/SQL", err)
	}
}
