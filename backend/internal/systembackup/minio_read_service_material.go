package systembackup

import (
	"context"
	"time"

	"k8s.io/client-go/kubernetes"
)

// The wire schema matches C's execution producer without importing execution
// or install into this lower package. This avoids an install->execution->install
// cycle in the actual D writer factory. Files/pins are DATA, never authority.
type minioGateMaterialPin struct{ File, SHA256 string }
type minioGateMaterial struct {
	Version, SourceSelectionSHA256, ProviderDefinitionSHA256                                string
	Native                                                                                  MinIOReadGateInput
	RootCredential, KeeperCredential, ReaderCredential, CaptureReaderCredential, CustodyKey minioGateMaterialPin
	KeeperPolicy, ReaderPolicy                                                              minioGateMaterialPin
	Until                                                                                   time.Time
}

// Genuine original factory caller supplies its actual operation/inventory and
// owner check. This is the concrete existing native Prepare path, not an opaque
// Held adapter, callback-success conversion or permission observation DTO.
func PrepareMinIOReadServiceGateFromMaterials(ctx context.Context, kube kubernetes.Interface, file, sha, operation, inventory string, outputAccounts []string, check TeamSourceCheck) (*MinIOReadServiceGate, error) {
	mat, creds, key, e := readMinioGateMaterials(ctx, file, sha, operation, inventory, outputAccounts, check)
	defer clear(key)
	for i := range creds {
		defer clear(creds[i].SecretKey)
	}
	if e != nil {
		return nil, e
	}
	return PrepareMinIOReadServiceGate(ctx, kube, mat.Native, creds[0], creds[1], creds[2], check, key)
}

// Reopens SAME original encrypted journal only. Fresh genuine D recovery owner
// and currently valid fixed material credentials are required. An expired
// material is refused, never re-dated or used to renew capture authority.
// The returned recovery gate still requires RestoreWithFreshAuthority, then
// ObserveRecovered; it cannot produce ObserveHeld/capture authority.
func OpenMinIOReadServiceRecoveryFromMaterials(ctx context.Context, kube kubernetes.Interface, file, sha, operation, inventory string, outputAccounts []string, fresh TeamSourceCheck) (*MinIOReadServiceGate, error) {
	mat, creds, key, e := readMinioGateMaterials(ctx, file, sha, operation, inventory, outputAccounts, fresh)
	defer clear(key)
	for i := range creds {
		defer clear(creds[i].SecretKey)
	}
	if e != nil {
		return nil, e
	}
	return OpenMinIOReadServiceRecovery(ctx, kube, mat.Native, creds[0], creds[1], creds[2], fresh, key)
}

func readMinioGateMaterials(ctx context.Context, file, sha, operation, inventory string, outputs []string, check TeamSourceCheck) (mat minioGateMaterial, creds [3]MinIOGateCredential, key []byte, result error) {
	fail := func() (minioGateMaterial, [3]MinIOGateCredential, []byte, error) {
		return mat, creds, key, ErrMinIOReadGate
	}
	if ctx == nil || check == nil || check(ctx) != nil {
		return fail()
	}
	if _, ok := ctx.Deadline(); !ok {
		return fail()
	}
	raw, e := minioGateReadPin(file, sha, 262144)
	if e != nil || minioGateDecode(raw, &mat) != nil {
		return fail()
	}
	static := mat.Version == "original-minio-source-read-identities.v2"
	if static && !mat.Until.IsZero() || !static && (mat.Version != "original-minio-source-read-materials.v1" || !time.Now().Before(mat.Until)) {
		return fail()
	}
	// Original producer intentionally leaves these two fields blank. Actual D
	// owner supplies current fixed identity, never a fixture/default operation.
	if mat.Native.Operation != "" && mat.Native.Operation != operation || mat.Native.InventorySHA256 != "" && mat.Native.InventorySHA256 != inventory {
		return fail()
	}
	mat.Native.Operation, mat.Native.InventorySHA256 = operation, inventory
	if len(mat.Native.OutputAccounts) != 0 {
		return fail()
	}
	mat.Native.OutputAccounts = append([]string(nil), outputs...)
	if !minioGateInputValid(mat.Native) {
		return fail()
	}
	for i, pin := range []minioGateMaterialPin{mat.RootCredential, mat.KeeperCredential, mat.ReaderCredential} {
		raw, e := minioGateReadPin(pin.File, pin.SHA256, 16384)
		if e != nil {
			clear(raw)
			return fail()
		}
		if static {
			var identity MinIOBuiltinIdentity
			if minioGateDecode(raw, &identity) != nil {
				clear(raw)
				return fail()
			}
			creds[i], e = resolveMinIOBuiltinIdentity(ctx, identity, check)
			clear(identity.SecretKey)
			if e != nil {
				clear(raw)
				return fail()
			}
		} else if minioGateDecode(raw, &creds[i]) != nil {
			clear(raw)
			return fail()
		}
		clear(raw)
		if !static && mat.Until.Before(creds[i].Until) {
			creds[i].Until = mat.Until
		}
		if !minioGateCredentialValid(creds[i], time.Now()) {
			return fail()
		}
	}
	key, e = minioGateReadPin(mat.CustodyKey.File, mat.CustodyKey.SHA256, 32)
	if e != nil || len(key) != 32 || check(ctx) != nil {
		return fail()
	}
	return mat, creds, key, nil
}
