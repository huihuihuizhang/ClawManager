package install

import (
	"strings"
	"testing"
)

func TestOriginalCSIContainerIDRequiresExactRuntimePin(t *testing.T) {
	valid := strings.Repeat("a", 64)
	id, err := originalCSIContainerID("containerd://" + valid)
	if err != nil || id != valid {
		t.Fatal("valid containerd identity rejected")
	}
	for _, bad := range []string{valid, "containerd://" + valid[:63], "docker://" + valid, "containerd://" + strings.Repeat("g", 64)} {
		if _, err := originalCSIContainerID(bad); err == nil {
			t.Fatal("invalid runtime identity accepted")
		}
	}
}
