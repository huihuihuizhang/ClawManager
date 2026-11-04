package install

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/runtimecustody"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
)

func TestOriginalWriterSelectionConsumesActualCLIReceiptEncoding(t *testing.T) {
	receipt := GeneratedOriginalObserverPKI{Version: "original-observer-pki-materials.v1", Status: "materialized_uninstalled_not_task_authority", PlanSHA256: strings.Repeat("a", 64)}
	var output bytes.Buffer
	if e := json.NewEncoder(&output).Encode(receipt); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"actual_encoder", "unknown_field", "duplicate_field"} {
		t.Run(fault, func(t *testing.T) {
			raw := bytes.Clone(output.Bytes())
			if fault == "unknown_field" {
				raw = append([]byte(`{"Passed":true,`), raw[1:]...)
			}
			if fault == "duplicate_field" {
				raw = append([]byte(`{"Version":"forged",`), raw[1:]...)
			}
			var read GeneratedOriginalObserverPKI
			e := decodeOriginalWriterMaterialData(raw, &read)
			if (e == nil) != (fault == "actual_encoder") {
				t.Fatal("actual ordinary material/closed-schema boundary", fault, e)
			}
			if e == nil && read.PlanSHA256 != receipt.PlanSHA256 {
				t.Fatal("receipt changed")
			}
		})
	}
}

func TestOriginalWriterSelectionRealCustodySelectsAllocatedOriginal(t *testing.T) {
	for _, fault := range []string{"none", "wrong_key", "wrong_generation", "wrong_pod", "different_port", "ambiguous_original", "truncated_cipher"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			if e := os.Chmod(directory, 0700); e != nil {
				t.Fatal(e)
			}
			key := bytes.Repeat([]byte{37}, 32)
			keyFile := filepath.Join(directory, "custody.key")
			if e := os.WriteFile(keyFile, key, 0600); e != nil {
				t.Fatal(e)
			}
			source := domain.SourceInstance{ID: 7, UserID: 2, Generation: 3, Workspace: "/workspaces/openclaw/user-2/instance-7", Type: "openclaw", Mode: "lite", OS: "linux", Status: "running"}
			row := originalGatewayRow{UID: "original-runtime-pod-uid", Port: 20000}
			request := services.RuntimeAgentCreateGatewayRequest{InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, WorkspacePath: source.Workspace, AgentType: "openclaw", PodUID: row.UID, GatewayPort: row.Port, UID: 1000, GID: 1000, PortRange: services.RuntimeAgentPortRange{Start: 20000, End: 20002}}
			store := runtimecustody.Store{Directory: directory, KeyFile: keyFile, Installation: "installation_original"}
			save := func(r services.RuntimeAgentCreateGatewayRequest) {
				t.Helper()
				raw, e := json.Marshal(r)
				if e != nil {
					t.Fatal(e)
				}
				if e = store.Save(context.Background(), raw); e != nil {
					t.Fatal(e)
				}
			}
			save(request)
			pin := BootstrapSourceFilePin{File: keyFile, SHA256: hash(key)}
			switch fault {
			case "wrong_key":
				key[0] ^= 1
				if e := os.WriteFile(keyFile, key, 0600); e != nil {
					t.Fatal(e)
				}
				pin.SHA256 = hash(key)
			case "wrong_generation":
				source.Generation++
			case "wrong_pod":
				row.UID = "replacement-runtime-pod-uid"
			case "different_port":
				row.Port++
			case "ambiguous_original":
				request.Environment = map[string]string{"ORIGINAL_VARIANT": "different-retained-request"}
				save(request)
			case "truncated_cipher":
				files, e := filepath.Glob(filepath.Join(directory, "gateway-*.enc"))
				if e != nil || len(files) != 1 {
					t.Fatal("actual custody missing")
				}
				raw, e := os.ReadFile(files[0])
				if e != nil {
					t.Fatal(e)
				}
				// Store.Save deliberately seals a read-only original. An authorized
				// fault injector must first clear Windows' read-only file attribute.
				if e = os.Chmod(files[0], 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(files[0], raw[:len(raw)-1], 0600); e != nil {
					t.Fatal(e)
				}
			}
			selected, e := originalSelectionGatewayCustody(context.Background(), store.Installation, source, row, directory, pin)
			if (e == nil) != (fault == "none") {
				t.Fatal("original custody boundary", fault, e)
			}
			if fault == "none" {
				raw, _ := json.Marshal(request)
				if selected.InstanceID != source.ID || selected.OriginalKey != pin || selected.OriginalPlainSHA256 != hash(raw) || selected.OriginalCipher.File == "" {
					t.Fatal("not the exact retained original")
				}
				sealed, e := ReadSourceMaterialFile(selected.OriginalCipher.File)
				if e != nil || hash(sealed) != selected.OriginalCipher.SHA256 || bytes.Contains(sealed, []byte(source.Workspace)) {
					t.Fatal("cipher pin/plaintext boundary")
				}
			}
		})
	}
}

func TestOriginalWriterSelectionLiteralDirectoriesNeverGuessImageDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []corev1.EnvVar
		want string
	}{
		{"literal", []corev1.EnvVar{{Name: "RUNTIME_AGENT_DATA_DIR", Value: "/var/lib/original-agent"}}, "/var/lib/original-agent"},
		{"absent", nil, ""},
		{"unresolved_secret", []corev1.EnvVar{{Name: "RUNTIME_AGENT_DATA_DIR", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "path"}}}}, ""},
		{"duplicate", []corev1.EnvVar{{Name: "RUNTIME_AGENT_DATA_DIR", Value: "/first"}, {Name: "RUNTIME_AGENT_DATA_DIR", Value: "/second"}}, ""},
		{"expansion", []corev1.EnvVar{{Name: "RUNTIME_AGENT_DATA_DIR", Value: "/data/$(POD_UID)"}}, ""},
		{"root", []corev1.EnvVar{{Name: "RUNTIME_AGENT_DATA_DIR", Value: "/"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, e := originalSelectionLiteralDirectory(corev1.Container{Env: tc.env}, "RUNTIME_AGENT_DATA_DIR")
			if value != tc.want || (e == nil) != (tc.want != "") {
				t.Fatal("actual original directory boundary", value, e)
			}
		})
	}
}
