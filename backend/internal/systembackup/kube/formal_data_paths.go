package kube

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Explicit original input layout. The same immutable Secret/ConfigMap bytes
// are mounted at a source owner's already-signed controller data path. Source
// signatures, credentials, CA hashes and scopes are never rewritten.
const OriginalFormalDataPathsV1 = "original-controller-source-data-paths.v1"

func FormalInputDataPath(materials *FormalJobMaterials, input FormalInputMount, item corev1.KeyToPath) (string, error) {
	if materials == nil {
		return "", ErrResource
	}
	if materials.ProjectionProtocol == "" {
		if len(input.DataPaths) != 0 {
			return "", ErrResource
		}
		return path.Join(input.Directory, item.Path), nil
	}
	if materials.ProjectionProtocol != OriginalFormalDataPathsV1 || len(input.DataPaths) != len(input.Items) {
		return "", ErrResource
	}
	selected, ok := input.DataPaths[item.Path]
	if !ok || selected == "" || path.Clean(selected) != selected || !path.IsAbs(selected) || strings.ContainsAny(selected, "\\\x00\r\n:") {
		return "", ErrResource
	}
	if !strings.HasPrefix(selected, "/run/system-backup/runtime/") && !strings.HasPrefix(selected, "/var/lib/system-backup/staging/") {
		return "", ErrResource
	}
	return selected, nil
}

func formalDataPathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
