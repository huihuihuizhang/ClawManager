package systembackupexecution

import "testing"

// Arithmetic-only request DATA. No huge body allocation or SQL authority.
func TestPublicationUploadCapacityIncludesPhysicalObjectsIndexAndManifest(t *testing.T) {
	for _, mode := range []string{"16gib", "900gib", "over-budget", "aggregate-overflow", "index-budget", "manifest-overhead", "missing-index", "negative"} {
		t.Run(mode, func(t *testing.T) {
			limits := ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 1 << 20}
			request := PublicationUploadRequest{Objects: []PublicationUploadInput{{Path: "parts/workspace.enc", Bytes: (16 << 30) - 2048}, {Path: "artifact-index.json", Bytes: 1024}}}
			manifest := int64(1024)
			switch mode {
			case "900gib":
				limits.MaxArtifactBytes = 900 << 30
				request.Objects[0].Bytes = (900 << 30) - 2048
			case "over-budget":
				request.Objects[0].Bytes++
			case "aggregate-overflow":
				request.Objects[0].Bytes = 1 << 62
			case "index-budget":
				request.Objects[1].Bytes = limits.MaxIndexBytes + 1
			case "manifest-overhead":
				manifest++
			case "missing-index":
				request.Objects = request.Objects[:1]
			case "negative":
				request.Objects[0].Bytes = -1
			}
			err := publicationUploadBytesWithinLimits(request, manifest, limits)
			if (err == nil) != (mode == "16gib" || mode == "900gib") {
				t.Fatal("wrong actual physical budget decision", mode, err)
			}
		})
	}
}
