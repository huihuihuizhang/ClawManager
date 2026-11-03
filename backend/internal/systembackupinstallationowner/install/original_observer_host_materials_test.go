package install

import (
	"strings"
	"testing"
)

// Renderer fixture, not a native host/CRI/deployment test.
func TestObserverHostMaterialRendererKeepsPrivateAnchorAndNativeNamespaces(t *testing.T) {
	unitArg := observerUnitArg("spiffe://test/system-backup/a%3Ab")
	if !strings.Contains(unitArg, "%%3A") {
		t.Fatal("systemd URI specifier not escaped")
	}
	def := OriginalObserverHostDefinition{BinaryDirectory: "/usr/local/libexec/clawreef", MaterialDirectory: "/etc/clawreef/observers"}
	cri := OriginalObserverHostCRI{Binary: "/usr/bin/crictl", BinarySHA256: strings.Repeat("a", 64), Endpoint: "unix:///run/containerd/containerd.sock"}
	script := string(observerHostInstallScript(OriginalObserverPKIEndpoint{NodeUID: "actual-node-model", MachineID: "actual-machine-model", BootID: "actual-boot-model"}, def, cri, []string{"whole"}))
	for _, required := range []string{"/etc/machine-id", "/proc/sys/kernel/random/boot_id", "whole-anchor.key", " 600\n", "safe_parent", "flock -n", "--apply", "copy_exact", "/usr/bin/crictl"} {
		if !strings.Contains(script, required) {
			t.Fatal("missing safety binding", required)
		}
	}
	if strings.Contains(script, "observer-client-key.pem") || strings.Contains(script, "rm -rf") {
		t.Fatal("client private key or broad deletion in node script")
	}
}
