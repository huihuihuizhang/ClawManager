package install

import (
	"reflect"
	"strings"
	"testing"
)

func TestNativeHostCompositionPreservesConcreteInstancesWithoutFillingOwners(t *testing.T) {
	capture, files, resources := terminalSevenConcreteSources(t)
	original, err := NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		t.Fatal(err)
	}
	stronger, err := original.WithNativeHostSource(BootstrapNativeHostFiles{RecordFile: "not-opened", RecordSHA256: strings.Repeat("a", 64), SignatureFile: "not-opened"})
	if err != nil || stronger.terminal == original || stronger.terminal.capture != original.capture || !reflect.DeepEqual(stronger.MissingTerminalResources(), original.MissingTerminalResources()) || len(stronger.MissingTerminalResources()) != 23 {
		t.Fatal("composition replaced capture or manufactured a resource", err)
	}
	for key, source := range original.resources {
		if stronger.terminal.resources[key] != source {
			t.Fatal("recreated concrete owner/group alias", key)
		}
	}
	if _, _, err := original.NativeHostDeploymentCandidates(nil, stronger.files); err == nil {
		t.Fatal("empty selection created candidate route")
	}
	var absent *BootstrapTerminalOriginal
	if _, err := absent.WithNativeHostSource(stronger.files); err == nil {
		t.Fatal("absent concrete terminal was replaced by a generic success source")
	}
}
