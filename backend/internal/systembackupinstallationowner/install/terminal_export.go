package install

import "bytes"

// SaveFrozenBootstrapOriginalMapping writes inert signed transport bytes.
// It cannot enroll an issuer, install consumer trust or authorize consumption.
// The independent consumer verifies the original enrollment/public pin and all
// current source rows. Existing output is never overwritten or re-signed.
func SaveFrozenBootstrapOriginalMapping(directory string, signed SignedBootstrapOriginalMapping) error {
	raw, signature := bytes.Clone(signed.Record), bytes.Clone(signed.Signature)
	var mapping BootstrapOriginalMapping
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != 64 || decodeExact(raw, &mapping) != nil || mapping.SchemaVersion != BootstrapOriginalMappingVersion {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{
		"bootstrap-original.record.json": raw,
		"bootstrap-original.signature":   signature,
		"bootstrap-original.sha256":      []byte(hash(raw)),
	})
}
