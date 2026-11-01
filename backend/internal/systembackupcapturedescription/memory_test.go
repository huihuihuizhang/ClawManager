package systembackupcapturedescription

import (
	"fmt"
	"testing"
)

func TestDescriptionMemoryAdmissionUsesOriginalBoundedSet(t *testing.T) {
	for _, n := range []int{1, 8, MaxMembers} {
		seed := Seed{Version: SeedVersion, Members: []Selection{}}
		for i := 0; i < n; i++ {
			seed.Members = append(seed.Members, Selection{Part: fmt.Sprintf("member_%05d", i), Operation: "capture-workspace", PartIndex: uint32(i + 3)})
		}
		seed.MaxPlaintextBytes, _ = Budget(n)
		memory, err := DecodeMemoryBudget(seed)
		if err != nil || memory <= 12*seed.MaxPlaintextBytes || memory > 3<<30 {
			t.Fatal(n, memory, err)
		}
	}
	if _, err := DecodeMemoryBudget(Seed{}); err == nil {
		t.Fatal("unadmitted body")
	}
}
