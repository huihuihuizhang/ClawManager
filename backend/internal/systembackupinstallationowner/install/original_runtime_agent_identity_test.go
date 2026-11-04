package install

import "testing"

func TestOriginalRuntimePerKindAgentIdentity(t *testing.T) {
	type identity struct {
		kind, sha string
		size      int64
	}
	approved := []identity{
		{"openclaw", "63a68c0a916a5d873c420c086f81a77d7d3c3f41bd5d798428b4608db0552cc1", 9994402},
		{"hermes", "851104a524ff26797c58c6a5a1e0e8172353ecdd31c31a07032a81073a225a42", 10072226},
	}
	for index, v := range approved {
		if !originalRuntimeAgentSHA(v.kind, v.sha, v.size) {
			t.Fatal("actual qualified runtime executable refused", v.kind)
		}
		other := approved[1-index]
		if originalRuntimeAgentSHA(v.kind, other.sha, other.size) {
			t.Fatal("cross-runtime executable identity accepted", v.kind)
		}
		if originalRuntimeAgentSHA(v.kind, v.sha, v.size-1) || originalRuntimeAgentSHA(v.kind, v.sha, v.size+1) {
			t.Fatal("wrong executable size accepted", v.kind)
		}
		if originalRuntimeAgentSHA(other.kind, v.sha, v.size) {
			t.Fatal("kind changed without new qualification", v.kind)
		}
	}
	if originalRuntimeAgentSHA("unknown", approved[0].sha, approved[0].size) || originalRuntimeAgentSHA("OpenClaw", approved[0].sha, approved[0].size) {
		t.Fatal("unknown/normalized runtime accepted")
	}
}
