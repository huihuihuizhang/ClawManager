package systembackup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Actual native observation before the original owner freezes builtin identity
// records. V1 descriptors must STILL be live; this cannot rescue expired setup
// input. No gate journal/hold/task/capture authority is made or returned.
func ObserveOriginalMinIOBuiltinIdentityMaterial(ctx context.Context, kube kubernetes.Interface, file, sha string, check TeamSourceCheck) error {
	if ctx == nil || kube == nil || check == nil || check(ctx) != nil {
		return ErrMinIOReadGate
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return ErrMinIOReadGate
	}
	operation := hex.EncodeToString(nonce)
	raw, e := minioGateReadPin(file, sha, 262144)
	var original minioGateMaterial
	if e != nil || minioGateDecode(raw, &original) != nil || original.Version != "original-minio-source-read-materials.v1" || !time.Now().Before(original.Until) {
		return ErrMinIOReadGate
	}
	inventory := minioGateHash(struct{ Purpose, MaterialSHA, Challenge string }{"original-native-builtin-identity-observation", sha, operation})
	mat, creds, key, e := readMinioGateMaterials(ctx, file, sha, operation, inventory, nil, check)
	clear(key)
	for n := range creds {
		defer clear(creds[n].SecretKey)
	}
	if e != nil {
		return e
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return ErrMinIOReadGate
	}
	for _, credential := range creds {
		if credential.Until.Before(until) {
			until = credential.Until
		}
	}
	g := &MinIOReadServiceGate{in: mat.Native, kube: kube, check: check, credentials: creds, until: until}
	g.origin = g
	defer g.Close()
	g.native, e = newMinioGateNative(ctx, g)
	if e != nil {
		return e
	}
	if g.identity(ctx, true) != nil {
		return ErrMinIOReadGate
	}
	first, e := g.collect(ctx)
	if e != nil {
		return e
	}
	second, e := g.collect(ctx)
	if e != nil || !reflect.DeepEqual(first, second) || g.identity(ctx, false) != nil || check(ctx) != nil {
		return ErrMinIOReadGate
	}
	if g.native.rootAccessProbe(ctx, first.RootAccess == "off") != nil || check(ctx) != nil {
		return ErrMinIOReadGate
	}
	// Both dedicated builtin user policy hashes, root identity and original
	// server/Pod/CA/SPKI/native metadata were read by the real native census.
	return nil
}
