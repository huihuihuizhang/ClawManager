package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestEnrolledCompositionRequiresExplicitOriginalNativeHostPins(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "original-composition.json")
	for _, fault := range []string{"current", "legacy-version", "previous-v3", "previous-v4", "previous-v5", "previous-v6", "previous-v7", "previous-v8", "missing-redis-source-pin", "relative-secret-policy-path", "missing-native-pin", "relative-native-path", "missing-signer-pin", "relative-signer-source", "missing-source-registry-pin", "relative-source-registry-signature", "missing-kek-window-pin", "relative-kek-window-signature", "missing-status-relay-pin", "relative-status-relay-signature"} {
		d := enrolledComposition{Version: enrolledCompositionVersion, NativeHost: install.BootstrapNativeHostFiles{RecordFile: filepath.Join(directory, "original-native-host.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(directory, "original-native-host.sig")}}
		d.Classification = install.FunctionalClassificationFiles{RecordFile: filepath.Join(directory, "classification.json"), RecordSHA256: strings.Repeat("b", 64), SignatureFile: filepath.Join(directory, "classification.sig"), RegistryDirectory: directory}
		d.SourceRegistries = install.BootstrapSourceRegistryFiles{RecordFile: filepath.Join(directory, "source-registries.json"), RecordSHA256: strings.Repeat("f", 64), SignatureFile: filepath.Join(directory, "source-registries.sig")}
		d.KEKFile, d.KEKSHA256 = filepath.Join(directory, "original-kek.json"), strings.Repeat("c", 64)
		d.KEKWindow = install.BootstrapKEKWindowFiles{RecordFile: filepath.Join(directory, "kek-window.json"), RecordSHA256: strings.Repeat("c", 64), SignatureFile: filepath.Join(directory, "kek-window.sig")}
		d.StatusRelay = install.StatusRelayReferenceFiles{RecordFile: filepath.Join(directory, "status-relay-reference.record.json"), RecordSHA256: strings.Repeat("f", 64), SignatureFile: filepath.Join(directory, "status-relay-reference.signature")}
		d.SigningConsumerFile, d.SigningConsumerPinFile, d.SigningConsumerSHA256 = filepath.Join(directory, "signing-consumer.json"), filepath.Join(directory, "signing-consumer.sha256"), strings.Repeat("e", 64)
		d.MinIO = execution.MinIOBootstrapTerminalInput{BundleFile: filepath.Join(directory, "minio-bundle.json"), BundleSHA256: strings.Repeat("d", 64), GrantFile: filepath.Join(directory, "minio-grant.json"), GrantSHA256: strings.Repeat("d", 64), DefinitionFile: filepath.Join(directory, "minio-definition.json"), DefinitionSHA256: strings.Repeat("d", 64), CapabilityIntentFile: filepath.Join(directory, "minio-intent.json"), CapabilityIntentSHA256: strings.Repeat("d", 64), ProvenanceFile: filepath.Join(directory, "minio-provenance.json")}
		d.MinIO.PermissionSource.File, d.MinIO.PermissionSource.SHA256 = filepath.Join(directory, "minio-permission.json"), strings.Repeat("d", 64)
		d.SourceNativeRegistries = execution.BootstrapSourceNativeRegistryFiles{RedisSources: install.BootstrapSourceFilePin{File: filepath.Join(directory, "redis-sources.json"), SHA256: strings.Repeat("b", 64)}, SecretAllowlist: install.BootstrapSourceFilePin{File: filepath.Join(directory, "secret-policy.json"), SHA256: strings.Repeat("c", 64)}}
		for index := 0; index < 5; index++ {
			d.MinIO.ReferenceFiles = append(d.MinIO.ReferenceFiles, execution.MinIOBootstrapReferenceFile{File: filepath.Join(directory, "minio-reference.json")})
		}
		switch fault {
		case "previous-v7":
			d.Version = "enrolled-bootstrap-production-composition.v7"
		case "previous-v8":
			d.Version = "enrolled-bootstrap-production-composition.v8"
		case "missing-redis-source-pin":
			d.SourceNativeRegistries.RedisSources.SHA256 = ""
		case "relative-secret-policy-path":
			d.SourceNativeRegistries.SecretAllowlist.File = "relative-policy.json"
		case "legacy-version":
			d.Version = "enrolled-bootstrap-production-composition.v1"
		case "previous-v3":
			d.Version = "enrolled-bootstrap-production-composition.v3"
		case "previous-v4":
			d.Version = "enrolled-bootstrap-production-composition.v4"
		case "previous-v5":
			d.Version = "enrolled-bootstrap-production-composition.v5"
		case "previous-v6":
			d.Version = "enrolled-bootstrap-production-composition.v6"
		case "missing-status-relay-pin":
			d.StatusRelay.RecordSHA256 = ""
		case "relative-status-relay-signature":
			d.StatusRelay.SignatureFile = "untrusted-relative-relay-signature"
		case "missing-kek-window-pin":
			d.KEKWindow.RecordSHA256 = ""
		case "relative-kek-window-signature":
			d.KEKWindow.SignatureFile = "untrusted-relative-kek-window-signature"
		case "missing-source-registry-pin":
			d.SourceRegistries.RecordSHA256 = ""
		case "relative-source-registry-signature":
			d.SourceRegistries.SignatureFile = "untrusted-relative-source-signature"
		case "missing-signer-pin":
			d.SigningConsumerSHA256 = ""
		case "relative-signer-source":
			d.SigningConsumerFile = "untrusted-relative-signer-source"
		case "missing-native-pin":
			d.NativeHost.RecordSHA256 = ""
		case "relative-native-path":
			d.NativeHost.RecordFile = "untrusted-relative-source"
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		_, err = loadEnrolledComposition(file, hex.EncodeToString(h[:]))
		if (fault == "current") != (err == nil) {
			t.Fatal("legacy/missing native host source silently selected", fault, err)
		}
	}
}
