package main

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// The mounted Secret contains 32 raw random bytes. Keep the existing explicit
// hex setting compatible, but reject two competing key sources. No key bytes,
// filenames or filesystem diagnostics escape through the error response.
func loadBackupReadCursorKey(getenv func(string) string) ([]byte, error) {
	rejected := errors.New("system-backup cursor key unavailable")
	if getenv == nil {
		return nil, rejected
	}
	path, encoded := getenv("SYSTEM_BACKUP_READ_CURSOR_KEY_FILE"), getenv("SYSTEM_BACKUP_READ_CURSOR_KEY_HEX")
	if path == "" {
		key, err := hex.DecodeString(encoded)
		if err != nil || len(key) < 32 {
			return nil, rejected
		}
		return key, nil
	}
	if encoded != "" || !filepath.IsAbs(path) {
		return nil, rejected
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, rejected
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 32 {
		return nil, rejected
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(key) != 32 {
		for i := range key {
			key[i] = 0
		}
		return nil, rejected
	}
	return key, nil
}
