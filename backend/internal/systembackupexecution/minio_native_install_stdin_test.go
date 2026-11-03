package systembackupexecution

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMinIONativeInstallUserAddKeepsCredentialsOffArguments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	native := &minioPermissionHTTP{provider: minioPermissionProvider{Endpoint: "https://original-minio:9000"}, credential: nativePublicationCredential{AccessKey: "original-admin", SecretKey: "original-admin-secret"}}
	input := []byte("new-access-key\nnew-secret-key\n")
	defer clear(input)
	command := nativeInstallMCCommand(ctx, "/operator/private", native, MinIONativeAdminFiles{MCFile: "/operator/mc"}, input, "admin", "user", "add", "native")
	args := strings.Join(command.Args, " ")
	for _, value := range []string{"original-admin", "original-admin-secret", "new-access-key", "new-secret-key"} {
		if strings.Contains(args, value) {
			t.Fatal("credential appeared in child arguments")
		}
	}
	actual, e := io.ReadAll(command.Stdin)
	defer clear(actual)
	if e != nil || !bytes.Equal(actual, input) || command.Stdout != io.Discard || command.Stderr != io.Discard {
		t.Fatal("private stdin/discarded diagnostics contract changed")
	}
}
