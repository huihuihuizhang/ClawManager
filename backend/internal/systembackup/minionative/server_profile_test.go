package minionative

import "testing"

func TestMinIOReadServiceServerProfile(t *testing.T) {
	compat := "docker-pullable://registry.example/minio@" + DeleteCompatManifest
	for _, tc := range []struct {
		name, image, version, commit string
		want                         bool
	}{
		{"september", "original-image", SeptemberServerVersion, SeptemberServerCommit, true},
		{"compatibility manifest", compat, DeleteCompatVersion, DeleteCompatCommit, true},
		{"compatibility version requires its manifest", "original-image", DeleteCompatVersion, DeleteCompatCommit, false},
		{"compatibility manifest requires its version", compat, SeptemberServerVersion, SeptemberServerCommit, false},
		{"compatibility commit must match", compat, DeleteCompatVersion, SeptemberServerCommit, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesReadGateServer(tc.image, tc.version, tc.commit); got != tc.want {
				t.Fatalf("profile match = %t, want %t", got, tc.want)
			}
		})
	}
}
