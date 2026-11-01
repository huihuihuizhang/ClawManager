package systembackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Explicit policy DATA; no source API, SQL, claim or capture authority.
func secretPolicyData(t *testing.T) (SecretCapturePolicy, []byte, string) {
	t.Helper()
	p := SecretCapturePolicy{SchemaVersion: SecretCapturePolicyVersion, RegistryVersion: "owner-r1", RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []SecretCapturePolicyEntry{{ID: "application", SecretName: "application", Required: true, ExpectedType: "Opaque", Purpose: "application_secret"}, {ID: "optional", SecretName: "optional", ExpectedType: "kubernetes.io/tls", Purpose: "tls_credentials"}}}
	raw, err := p.canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return p, raw, hex.EncodeToString(sum[:])
}

func TestSecretCapturePolicyExactIndependentDocument(t *testing.T) {
	for _, mode := range []string{"current", "hash", "version", "whitespace", "unknown", "duplicate", "alias", "tail", "null-entries", "service-account-token", "duplicate-name", "unsorted", "wrong-namespace-scope", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			p, raw, sha := secretPolicyData(t)
			version := p.RegistryVersion
			switch mode {
			case "hash":
				sha = strings.Repeat("0", 64)
			case "version":
				version = "other"
			case "whitespace":
				raw = append([]byte(" "), raw...)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"capture_mode":`), []byte(`"unapproved":true,"capture_mode":`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"registry_kind":"secret_allowlist"`), []byte(`"registry_kind":"secret_allowlist","registry_kind":"secret_allowlist"`), 1)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"entry_id"`), []byte(`"\u0065ntry_id"`), 1)
			case "tail":
				raw = append(raw, []byte(`{}`)...)
			case "null-entries":
				p.Entries = nil
			case "service-account-token":
				p.Entries[0].ExpectedType = "kubernetes.io/service-account-token"
			case "duplicate-name":
				p.Entries[1].SecretName = p.Entries[0].SecretName
			case "unsorted":
				p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0]
			case "wrong-namespace-scope":
				p.NamespaceScope = "all_namespaces"
			case "too-many":
				p.Entries = make([]SecretCapturePolicyEntry, 10001)
			}
			if mode == "null-entries" || mode == "service-account-token" || mode == "duplicate-name" || mode == "unsorted" || mode == "wrong-namespace-scope" || mode == "too-many" {
				raw, _ = json.Marshal(p)
			}
			if mode != "hash" {
				sum := sha256.Sum256(raw)
				sha = hex.EncodeToString(sum[:])
			}
			got, err := DecodeSecretCapturePolicy(raw, version, sha)
			if mode == "current" {
				if err != nil || got.RequiredEntries() != 1 || got.SHA256 != sha {
					t.Fatal("fixed policy rejected", err)
				}
				return
			}
			if err == nil || got.SHA256 != "" {
				t.Fatal("invalid fixed policy accepted", mode)
			}
		})
	}
}

func TestSecretCapturePolicyRequiredEntriesAndActualObject(t *testing.T) {
	for _, mode := range []string{"required-only", "optional-present", "missing-required", "extra-name", "duplicate-selection", "wrong-version", "missing-uid", "wrong-namespace", "wrong-uid", "wrong-kind", "wrong-type", "default-opaque"} {
		t.Run(mode, func(t *testing.T) {
			p, raw, sha := secretPolicyData(t)
			f, err := DecodeSecretCapturePolicy(raw, p.RegistryVersion, sha)
			if err != nil {
				t.Fatal(err)
			}
			refs := []KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "application", UID: "actual-original-uid"}}
			switch mode {
			case "optional-present":
				refs = append(refs, KubernetesSelection{Version: "v1", Resource: "secrets", Name: "optional", UID: "optional-uid"})
			case "missing-required":
				refs = []KubernetesSelection{}
			case "extra-name":
				refs[0].Name = "other"
			case "duplicate-selection":
				refs = append(refs, refs[0])
			case "wrong-version":
				refs[0].Version = "v2"
			case "missing-uid":
				refs[0].UID = ""
			}
			err = f.ValidateSelections("installation", refs)
			invalidPlan := mode == "missing-required" || mode == "extra-name" || mode == "duplicate-selection" || mode == "wrong-version" || mode == "missing-uid"
			if invalidPlan {
				if err == nil {
					t.Fatal("invalid entry coverage admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			obj := map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": map[string]any{"name": "application", "namespace": "installation", "uid": "actual-original-uid"}, "data": map[string]any{"never_reported": "cHJpdmF0ZQ=="}}
			meta := obj["metadata"].(map[string]any)
			switch mode {
			case "wrong-namespace":
				meta["namespace"] = "other"
			case "wrong-uid":
				meta["uid"] = "replacement"
			case "wrong-kind":
				obj["kind"] = "ConfigMap"
			case "wrong-type":
				obj["type"] = "kubernetes.io/tls"
			case "default-opaque":
				delete(obj, "type")
			}
			raw, _ = json.Marshal(obj)
			id, err := f.CheckCaptured("installation", refs[0], raw)
			invalidObject := strings.HasPrefix(mode, "wrong-")
			if invalidObject {
				if err == nil || id != "" {
					t.Fatal("changed object accepted")
				}
				return
			}
			if err != nil || id != "application" {
				t.Fatal("original full object rejected", err)
			}
		})
	}
}
