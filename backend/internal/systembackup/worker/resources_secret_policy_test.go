package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	c "clawreef/internal/systembackup"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// Fake source objects exercise the real archive producer and independent
// reader. They do not mint a source credential or formal capture receipt.
func TestResourceSecretPolicyActualArchiveData(t *testing.T) {
	for _, mode := range []string{"current", "wrong-source-type", "wrong-readback-type", "missing-required", "missing-end"} {
		t.Run(mode, func(t *testing.T) {
			i, _, _ := resourceInvocationFixture(t, true)
			policy := c.SecretCapturePolicy{SchemaVersion: c.SecretCapturePolicyVersion, RegistryVersion: "owner-policy-data-r1", RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []c.SecretCapturePolicyEntry{{ID: "credential", SecretName: "credential", Required: true, ExpectedType: "Opaque", Purpose: "application_secret"}}}
			raw, _ := json.Marshal(policy)
			raw, err := jsoncanonicalizer.Transform(raw)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			frozen, err := c.DecodeSecretCapturePolicy(raw, policy.RegistryVersion, hex.EncodeToString(sum[:]))
			if err != nil {
				t.Fatal(err)
			}
			i.Request.Resources.SecretPolicy = &frozen
			object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": map[string]any{"namespace": "source", "name": "credential", "uid": "credential-original-uid"}, "data": map[string]any{"private": "cHJpdmF0ZQ=="}}}
			if mode == "wrong-source-type" || mode == "wrong-readback-type" {
				object.Object["type"] = "kubernetes.io/tls"
			}
			client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
			env := &ResourceCaptureSources{Client: client, Authorize: func(context.Context, Invocation) error { return nil }}
			if mode == "missing-required" {
				i.Request.Resources.Selections = []c.KubernetesSelection{}
			}
			var archive bytes.Buffer
			if mode == "wrong-readback-type" {
				// Produce a structurally sound archive whose historical object violates
				// policy, bypassing ONLY the producer policy inspector in this DATA case.
				header, _ := json.Marshal(struct {
					Version string              `json:"schema_version"`
					Scope   ResourceCaptureSpec `json:"scope"`
				}{"resource-capture-history.v1", *i.Request.Resources})
				archive.Write(append(header, '\n'))
				err = c.CaptureKubernetesResourcesGuarded(context.Background(), client, &archive, "source", i.Request.Resources.NamespaceUID, "secret_bundle", i.Request.Resources.Selections, c.ObjectBudget{MaxItems: 10, MaxBytes: i.Request.MaxArchiveBytes}, func(context.Context) error { return nil })
			} else {
				err = captureResourceSource(context.Background(), env, i, &archive, func() error { return nil })
			}
			if mode == "wrong-source-type" || mode == "missing-required" {
				if err == nil {
					t.Fatal("policy violation emitted complete source history")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body := archive.Bytes()
			if mode == "missing-end" {
				end := bytes.LastIndex(body[:len(body)-1], []byte{'\n'})
				body = body[:end+1]
			}
			seen := 0
			err = ReadResourceCaptureArchive(context.Background(), bytes.NewReader(body), *i.Request.Resources, i.Request.MaxArchiveBytes, func(c.KubernetesSelection, json.RawMessage) error { seen++; return nil })
			if mode != "current" {
				if err == nil {
					t.Fatal("invalid policy history accepted")
				}
				if mode == "wrong-readback-type" && seen != 0 {
					t.Fatal("invalid object reached coverage callback")
				}
				return
			}
			if err != nil || seen != 1 {
				t.Fatal("independent actual-object reader failed", err, seen)
			}
		})
	}
}
