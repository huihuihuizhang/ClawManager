package systembackup

import (
	"context"
	"sort"
)

// Concrete counterpart to the r7 opaque material loader. The D recovery
// factory need not expose secret descriptors or import execution/install.
// SAME original native input/journal and currently valid original-key/version
// material plus genuine fresh recovery authority are mandatory. No cap renews.
func RestoreMinIOReadServiceGateFromMaterials(ctx context.Context, g *MinIOReadServiceGate, file, sha, operation, inventory string, outputs []string, fresh TeamSourceCheck) error {
	if g == nil || g.origin != g {
		return ErrMinIOReadGate
	}
	mat, creds, key, e := readMinioGateMaterials(ctx, file, sha, operation, inventory, outputs, fresh)
	defer clear(key)
	for i := range creds {
		defer clear(creds[i].SecretKey)
	}
	if e != nil {
		return e
	}
	sort.Strings(mat.Native.BusinessBuckets)
	sort.Strings(mat.Native.OutputAccounts)
	if minioGateHash(mat.Native) != minioGateHash(g.in) {
		return ErrMinIOReadGate
	}
	return g.RestoreWithFreshAuthority(ctx, creds[0], creds[1], creds[2], fresh)
}
