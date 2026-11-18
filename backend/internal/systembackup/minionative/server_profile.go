package minionative

import "strings"

const (
	SeptemberServerVersion = "2025-09-07T16:13:09Z"
	SeptemberServerCommit  = "07c3a429bfed433e49018cb0f78a52145d4bedeb"
	DeleteCompatVersion    = "2026-11-05T07:23:54Z"
	DeleteCompatCommit     = "0f7c8e3a781129ddbf1c7a6ce834727ff5efdedb"
	DeleteCompatManifest   = "sha256:b01b328707219c9d27f818583e0aef896a10e7580e59ad5bb2930a6965969548"
)

func MatchesDeleteCompatImageID(imageID string) bool {
	return imageID == DeleteCompatManifest || MatchesDeleteCompatImageReference(strings.TrimPrefix(imageID, "docker-pullable://"))
}

func MatchesDeleteCompatImageReference(image string) bool {
	repository, digest, ok := strings.Cut(image, "@")
	return ok && repository != "" && !strings.ContainsAny(repository, " \t\r\n?#\\") &&
		!strings.Contains(repository, "://") && digest == DeleteCompatManifest
}

func MatchesReadGateServer(imageID, version, commit string) bool {
	if MatchesDeleteCompatImageID(imageID) {
		return version == DeleteCompatVersion && commit == DeleteCompatCommit
	}
	return version == SeptemberServerVersion && commit == SeptemberServerCommit
}
