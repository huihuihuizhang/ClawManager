package install

// ReadPrivateFile's closed maximum is256KiB, as is decodeExact's JSON bound.
// Passing a larger limit rejects even a one-byte input before opening it.
// Keep the original private-file/identity/permission checks unchanged.
const originalArchivePrivateFileLimit int64 = 262144

func readOriginalArchivePrivateFile(path string) ([]byte, error) {
	return ReadPrivateFile(path, originalArchivePrivateFileLimit)
}
