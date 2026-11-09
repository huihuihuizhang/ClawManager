package install

import (
	"strings"
	"testing"
)

func TestObserverHostUpdateIsOptInAndScopedToSharedOwner(t *testing.T) {
	def, pki := sharedHostFixture(t)
	cri := OriginalObserverHostCRI{Binary: "/usr/bin/crictl", BinarySHA256: strings.Repeat("c", 64), Endpoint: "unix:///run/containerd/containerd.sock"}
	script := string(observerHostInstallScript(pki.Endpoints[0], def, cri, []string{"whole", "shared"}))
	previousBinary := `check_update_target backup-shared-runtime-node-owner "$shared_binary" 755 "$3"`
	previousUnit := `check_update_target clawreef-backup-shared-runtime-node-owner.service "$shared_unit" 644 "$4"`
	writeBinary := `replace_update_target backup-shared-runtime-node-owner "$shared_binary" 755 "$3"`
	writeUnit := `replace_update_target clawreef-backup-shared-runtime-node-owner.service "$shared_unit" 644 "$4"`
	last := -1
	for _, step := range []string{"flock -n 9", "$2 == --update-shared", "shared_stopped || exit 30", previousBinary, previousUnit, writeBinary, writeUnit, "systemctl daemon-reload", "systemctl enable --now"} {
		index := strings.Index(script, step)
		if index <= last {
			t.Fatalf("missing or out-of-order update step %q", step)
		}
		last = index
	}
	for _, step := range []string{`== disabled`, `== inactive`, `--property=MainPID`, `--property=ControlPID`, `mv -T -- "$temporary" "$target"`, `copy_exact 'whole-anchor.key'`, `copy_exact 'backup-node-observer'`} {
		if !strings.Contains(script, step) {
			t.Fatalf("missing update condition %q", step)
		}
	}
	for _, step := range []string{"systemctl stop", "systemctl restart", "replace_update_target backup-node-observer"} {
		if strings.Contains(script, step) {
			t.Fatalf("unexpected installer operation %q", step)
		}
	}
	readerOnly := string(observerHostInstallScript(pki.Endpoints[0], def, cri, []string{"whole"}))
	if strings.Contains(readerOnly, "--update-shared") || !strings.Contains(readerOnly, "[[ $# == 1 ]] || exit 30") {
		t.Fatal("observer bundle without the shared owner accepted the update option")
	}
}
