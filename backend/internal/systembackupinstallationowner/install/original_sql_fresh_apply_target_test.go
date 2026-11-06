package install

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalSQLFreshApplyRequiresAppSelectorWithoutChangingRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	unopened := filepath.Join(directory, "absent")
	common := []string{
		"--fresh-installation", "--runtime-profile", originalSQLMinIOMetadataProfile,
		"--admin-dsn-file", unopened, "--admin-dsn-sha256", digest,
		"--source-tls-file", unopened, "--source-tls-sha256", digest,
		"--kubeconfig-file", unopened, "--kubeconfig-sha256", digest,
		"--local-admin-password-file", unopened, "--output-directory", directory,
		"--namespace", "isolated", "--namespace-uid", "ns-uid", "--cluster-uid", "cluster-uid",
		"--expected-server-uuid", "server", "--database", "appdb",
		"--expected-ledger-sha256", digest, "--operation-sha256", digest,
		"--operation-file", filepath.Join(directory, "operation.json"),
	}
	app := []string{"--app-deployment", "clawmanager-app", "--app-deployment-uid", "app-uid"}
	for _, tc := range []struct {
		mode string
		args []string
		want int
	}{
		{"apply", nil, 2},
		{"apply", app[:2], 2},
		{"apply", app, 1},
		{"query", nil, 1},
		{"rollback", nil, 1},
		{"rollback", app, 2},
	} {
		// 1 reaches the pinned input preflight and refuses the absent kubeconfig.
		args := append(append(append([]string(nil), common...), "--mode", tc.mode), tc.args...)
		if got := RunOriginalSQLAccounts(context.Background(), args, io.Discard); got != tc.want {
			t.Errorf("%s %v = %d, want %d", tc.mode, tc.args, got, tc.want)
		}
	}
}
