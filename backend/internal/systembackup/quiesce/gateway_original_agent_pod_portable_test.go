package quiesce

import "testing"

func TestGatewayOriginalSourcePathOverlapPortable(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"/data", "/data", true},
		{"/data", "/data/skills", true},
		{"/data/skills", "/data/skills/workspace", true},
		{"/data", "/database", false},
		{"/data/skills", "/data/skills2", false},
		{"/source-a", "/source-b", false},
		{"/", "/data", true},
	} {
		if gatewayOriginalSourcePathsOverlap(c.a, c.b) != c.want || gatewayOriginalSourcePathsOverlap(c.b, c.a) != c.want {
			t.Fatalf("POSIX path boundary changed for %q and %q", c.a, c.b)
		}
	}
}
