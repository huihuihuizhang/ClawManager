package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupReadCursorKeyUsesExactlyOneTrustedSource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "key")
	key := bytes.Repeat([]byte{0xa7}, 32)
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, path, hex string
		want            bool
	}{
		{"mounted", path, "", true},
		{"legacy", "", strings.Repeat("a7", 32), true},
		{"both", path, strings.Repeat("a7", 32), false},
		{"missing", "", "", false},
		{"short_hex", "", strings.Repeat("a7", 31), false},
		{"bad_hex", "", strings.Repeat("zz", 32), false},
		{"relative_path", "key", "", false},
		{"missing_file", filepath.Join(root, "absent"), "", false},
		{"directory", root, "", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			env := map[string]string{"SYSTEM_BACKUP_READ_CURSOR_KEY_FILE": item.path, "SYSTEM_BACKUP_READ_CURSOR_KEY_HEX": item.hex}
			got, err := loadBackupReadCursorKey(func(name string) string { return env[name] })
			if item.want {
				if err != nil || !bytes.Equal(got, key) {
					t.Fatal("explicit key source rejected")
				}
			} else if err == nil || got != nil || err.Error() != "system-backup cursor key unavailable" {
				t.Fatal("invalid source did not fail closed")
			}
		})
	}
	for _, length := range []int{0, 31, 33, 4096} {
		if err := os.WriteFile(path, bytes.Repeat([]byte{'k'}, length), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := loadBackupReadCursorKey(func(name string) string {
			if name == "SYSTEM_BACKUP_READ_CURSOR_KEY_FILE" {
				return path
			}
			return ""
		})
		if err == nil || got != nil {
			t.Fatal("invalid raw key length accepted", length)
		}
	}
	if got, err := loadBackupReadCursorKey(nil); got != nil || err == nil {
		t.Fatal("missing environment reader accepted")
	}
}
