package install

import (
	"strings"
	"testing"
)

// Renderer fixture only. No executable, systemd or CRI invocation occurs.
func TestObserverHostOfflineCRIChecksRuntimeBeforeInstalling(t *testing.T) {
	def := OriginalObserverHostDefinition{BinaryDirectory: "/opt/clawreef/bin", MaterialDirectory: "/etc/clawreef/observer"}
	cri := OriginalObserverHostCRI{
		Binary: "/opt/clawreef/cri/crictl-v1.31.1", BinarySHA256: observerHostCRIBinarySHA256,
		Endpoint:      "unix:///run/containerd/containerd.sock",
		ReleaseBinary: BootstrapSourceFilePin{File: "/release/crictl", SHA256: observerHostCRIBinarySHA256},
	}
	script := string(observerHostInstallScript(OriginalObserverPKIEndpoint{NodeUID: "node-fixture", MachineID: "machine-fixture", BootID: "boot-fixture"}, def, cri, []string{"whole"}))
	probe := strings.Index(script, "--timeout 5s version >/dev/null")
	apply := strings.Index(script, "[[ ${1:-} == --apply ]]")
	copy := strings.Index(script, "copy_exact crictl-v1.31.1")
	start := strings.Index(script, "systemctl enable --now")
	if probe < 0 || apply < probe || copy < apply || start < copy {
		t.Fatal("native CRI probe or create-only install order lost")
	}
	for _, binding := range []string{observerHostCRIBinarySHA256, "crictl version v1.31.1", "check_crictl", "safe_parent '/opt/clawreef/cri'", "! -L $binary", "8#$mode & 0022"} {
		if !strings.Contains(script, binding) {
			t.Fatal("offline runtime binding missing", binding)
		}
	}
	if strings.Contains(script, "observer-client-key.pem") || strings.Contains(script, "rm -rf") {
		t.Fatal("unrelated private key or broad deletion")
	}
}
