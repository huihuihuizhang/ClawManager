package systembackupcapturedescription

import (
	"fmt"
	"math"
	"runtime/debug"
	"testing"
)

func TestDescriptionMemoryAdmissionBeforeAllocationAndConcurrentUse(t *testing.T) {
	seed := descriptionFixture(t).Seed
	original := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(original)
	if release, err := AdmitDecodeMemory(seed); err == nil {
		release()
		t.Fatal("unbounded process declaration accepted")
	}
	debug.SetMemoryLimit(32 << 20)
	if release, err := AdmitDecodeMemory(seed); err == nil {
		release()
		t.Fatal("insufficient declared process memory accepted")
	}
	debug.SetMemoryLimit(4 << 30)
	release, err := AdmitDecodeMemory(seed)
	if err != nil {
		t.Fatal(err)
	}
	another, err := AdmitDecodeMemory(seed)
	if err != nil {
		t.Fatal("two small independently accounted pipelines", err)
	}
	another()
	release()
	release()
	final, err := AdmitDecodeMemory(seed)
	if err != nil {
		t.Fatal("released bounded slot", err)
	}
	final()
	maximum := Seed{Version: SeedVersion, Members: []Selection{}}
	for i := 0; i < MaxMembers; i++ {
		maximum.Members = append(maximum.Members, Selection{Part: fmt.Sprintf("member_%05d", i), Operation: "capture-workspace", PartIndex: uint32(i + 3)})
	}
	maximum.MaxPlaintextBytes, _ = Budget(MaxMembers)
	large, err := AdmitDecodeMemory(maximum)
	if err != nil {
		t.Fatal("one declared large arithmetic-only reservation", err)
	}
	if second, err := AdmitDecodeMemory(maximum); err == nil {
		second()
		large()
		t.Fatal("combined reservations exceeded real process declaration")
	}
	large()
}
