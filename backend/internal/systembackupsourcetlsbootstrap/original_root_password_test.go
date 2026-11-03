package systembackupsourcetlsbootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// File/environment fixture only; does not authenticate SQL or run TLS.
func TestOriginalRootPasswordUsesConsistentInputForUnixAndTLS(t *testing.T) {
	file := filepath.Join(t.TempDir(), "original-root-password")
	if os.WriteFile(file, []byte("original-private-password\n"), 0600) != nil {
		t.Fatal("fixture write failed")
	}
	t.Setenv("MYSQL_ROOT_PASSWORD", "")
	t.Setenv("MYSQL_ROOT_PASSWORD_FILE", file)
	actual, err := originalRootPassword()
	if err != nil || actual != "original-private-password" {
		t.Fatal("password file rejected")
	}
	t.Setenv("MYSQL_ROOT_PASSWORD", "original-env-password")
	actual, err = originalRootPassword()
	if err != nil || actual != "original-env-password" {
		t.Fatal("original environment precedence changed")
	}
	t.Setenv("MYSQL_ROOT_PASSWORD", "")
	t.Setenv("MYSQL_ROOT_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := originalRootPassword(); err == nil {
		t.Fatal("missing selected private file accepted")
	}
}
