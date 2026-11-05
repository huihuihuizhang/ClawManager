package install

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOriginalMinIOColdCutRequiresStableIdentityAndColdBytes(t *testing.T) {
	warm := originalMinIOFullTree{Phase: "warm", Root: "/original", Node: json.RawMessage(`{"boot_id":"original"}`), Mount: json.RawMessage(`{"device":"original"}`), Format: json.RawMessage(`{"deployment_id":"original"}`), Tree: json.RawMessage(`[{"path":"original-file"}]`), TreeSHA256: "warm", Excluded: []string{}}
	cold := warm
	cold.Phase = "cold"
	cold.Tree = json.RawMessage(`[{"path":"original-file"},{"path":"actual-native-shutdown-file"}]`)
	cold.TreeSHA256 = "cold"
	if !sameOriginalMinIOSource(warm, cold) || sameOriginalMinIOTree(warm, cold) {
		t.Fatal("source transition must preserve identity without claiming running/cold bytes equal")
	}
	if !sameOriginalMinIOTree(cold, cold) {
		t.Fatal("identical complete cold cuts refused")
	}
	changed := cold
	changed.Tree = append(json.RawMessage(nil), cold.Tree...)
	changed.Tree[3] = 'X'
	if sameOriginalMinIOTree(cold, changed) {
		t.Fatal("cold byte drift accepted")
	}
	changed = cold
	changed.Node = json.RawMessage(`{"boot_id":"foreign"}`)
	if sameOriginalMinIOSource(warm, changed) || sameOriginalMinIOTree(cold, changed) {
		t.Fatal("foreign cold source identity accepted")
	}
	changed = cold
	changed.Excluded = []string{"arbitrary-internal-file"}
	if sameOriginalMinIOSource(warm, changed) || sameOriginalMinIOTree(cold, changed) {
		t.Fatal("physical exclusions accepted")
	}
}

func TestOriginalMinIOExactNativeCommitmentDoesNotRoundIntegerBytes(t *testing.T) {
	a := originalMinIOFullTree{raw: []byte(`{"mtime_ns":1793890000000000001}`), TreeSHA256: "exact-tree"}
	b := a
	b.raw = []byte(`{"mtime_ns":1793890000000000003}`)
	ca, cb := originalMinIOInventoryCommitment(a, BootstrapSourceFilePin{}), originalMinIOInventoryCommitment(b, BootstrapSourceFilePin{})
	ra, e := canonical(ca)
	if e != nil {
		t.Fatal(e)
	}
	rb, e := canonical(cb)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(ra, rb) || ca.ExactNativeSHA256 == cb.ExactNativeSHA256 {
		t.Fatal("exact native integer difference lost through signed commitment")
	}
}
