package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	q "clawreef/internal/systembackup/quiesce"
)

// Material/renderer fixtures only: never invokes ELF, shell, systemd or CRI.
func sharedHostFixture(t *testing.T) (OriginalObserverHostDefinition, GeneratedOriginalObserverPKI) {
	t.Helper()
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	elf[18] = 0x3e
	file := filepath.Join(t.TempDir(), "agent-model.elf")
	if err := os.WriteFile(file, elf, 0600); err != nil {
		t.Fatal(err)
	}
	input := BootstrapSourceFilePin{File: file, SHA256: hash(elf)}
	anchor := BootstrapSourceFilePin{File: filepath.Join(t.TempDir(), "whole-anchor.key"), SHA256: strings.Repeat("a", 64)}
	whole := OriginalObserverPKIEndpoint{Kind: "whole", Node: "node-model", NodeUID: "uid-model", MachineID: "machine-model", BootID: "boot-model", AnchorKey: anchor, Endpoint: q.ProofEndpoint{URL: "https://192.0.2.1:19443/observation/v1"}}
	shared := whole
	shared.Kind, shared.Endpoint.URL = "shared", "https://192.0.2.1:19446/shared-runtime-lifecycle/v1"
	def := OriginalObserverHostDefinition{BinaryDirectory: "/usr/local/libexec/clawreef-model", MaterialDirectory: "/etc/clawreef/model", Binaries: map[string]BootstrapSourceFilePin{"shared": input}, SharedRuntime: &OriginalObserverSharedRuntimeHostConfig{OwnerDirectory: "/var/lib/clawmanager-system-backup/model/shared-owner", CgroupMount: "/sys/fs/cgroup", AgentExecutables: map[string]BootstrapSourceFilePin{"openclaw": input, "hermes": input}}}
	return def, GeneratedOriginalObserverPKI{ClientURI: "spiffe://model/controller", Endpoints: []OriginalObserverPKIEndpoint{whole, shared}}
}

func TestSharedObserverHostRejectsMixedNativeInputs(t *testing.T) {
	for _, name := range []string{"missing-config", "missing-runtime", "changed-elf", "foreign-anchor", "foreign-node", "missing-whole", "wrong-cgroup", "unsafe-store"} {
		t.Run(name, func(t *testing.T) {
			def, pki := sharedHostFixture(t)
			if validateSharedObserverHostConfig(def, pki) != nil {
				t.Fatal("valid material fixture refused")
			}
			switch name {
			case "missing-config":
				def.SharedRuntime = nil
			case "missing-runtime":
				delete(def.SharedRuntime.AgentExecutables, "hermes")
			case "changed-elf":
				if err := os.WriteFile(def.SharedRuntime.AgentExecutables["hermes"].File, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-anchor":
				pki.Endpoints[1].AnchorKey.SHA256 = strings.Repeat("b", 64)
			case "foreign-node":
				pki.Endpoints[1].NodeUID = "foreign-uid"
			case "missing-whole":
				pki.Endpoints = pki.Endpoints[1:]
			case "wrong-cgroup":
				def.SharedRuntime.CgroupMount = "/tmp/cgroup"
			case "unsafe-store":
				def.SharedRuntime.OwnerDirectory = "/var/lib/clawmanager-system-backup/../foreign"
			}
			if validateSharedObserverHostConfig(def, pki) == nil {
				t.Fatal("mixed native material admitted")
			}
		})
	}
}

func TestSharedObserverHostUsesOneKeyAndSeparateCLI(t *testing.T) {
	def, pki := sharedHostFixture(t)
	cri := OriginalObserverHostCRI{Binary: "/usr/bin/crictl", Endpoint: "unix:///run/containerd/containerd.sock"}
	owner, err := observerHostUnit(pki, pki.Endpoints[1], def, cri)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := observerHostUnit(pki, pki.Endpoints[0], def, cri)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{string(owner), string(reader)} {
		for _, required := range []string{"whole-anchor.key", sharedObserverHostDirectory(def.SharedRuntime, "uid-model"), def.SharedRuntime.AgentExecutables["openclaw"].SHA256, "PrivateMounts=false", "PrivateUsers=false", "\"--host-proc\" \"/proc\""} {
			if !strings.Contains(text, required) {
				t.Fatal("native linkage missing", required)
			}
		}
		if strings.Contains(text, "shared-anchor.key") {
			t.Fatal("second owner key admitted")
		}
	}
	if !strings.Contains(string(owner), "backup-shared-runtime-node-owner") || !strings.Contains(string(owner), "\"--owner-directory\"") || strings.Contains(string(owner), "\"--shared-owner-directory\"") {
		t.Fatal("owner CLI boundary lost")
	}
	if !strings.Contains(string(reader), "backup-node-observer") || !strings.Contains(string(reader), "\"--shared-owner-directory\"") || strings.Contains(string(reader), "\"--owner-directory\"") {
		t.Fatal("readonly CLI boundary lost")
	}
}

func TestSharedObserverHostCreatesPersistentStoreBeforeStart(t *testing.T) {
	def, pki := sharedHostFixture(t)
	cri := OriginalObserverHostCRI{Binary: "/usr/bin/crictl", BinarySHA256: strings.Repeat("c", 64), Endpoint: "unix:///run/containerd/containerd.sock"}
	script := string(observerHostInstallScript(pki.Endpoints[0], def, cri, []string{"shared", "whole"}))
	privateStore := strings.Index(script, "== 0:0:700")
	start := strings.Index(script, "systemctl enable --now")
	if privateStore < 0 || start < privateStore || !strings.Contains(script, "cgroup2fs") || !strings.Contains(script, "safe_parent '"+sharedObserverHostDirectory(def.SharedRuntime, "uid-model")+"'") {
		t.Fatal("native store/cgroup preflight ordering lost")
	}
	if strings.Contains(script, "copy_exact 'shared-anchor.key'") || strings.Contains(script, "observer-client-key.pem") || strings.Contains(script, "cgroup.freeze") {
		t.Fatal("installer crosses native lifecycle/key boundary")
	}
}
