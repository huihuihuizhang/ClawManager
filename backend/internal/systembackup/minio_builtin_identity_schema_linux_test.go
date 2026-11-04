package systembackup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMinIOBuiltinIdentityRejectsEmbeddedAuthorityWindow(t *testing.T) {
	for _, extra := range []string{`,"Until":"2099-01-01T00:00:00Z"`, `,"NotBefore":"2000-01-01T00:00:00Z"`, `,"Task":"fixture"`, `,"Passed":true`} {
		raw := []byte(`{"Kind":"minio-builtin-static-identity.v1","AccessKey":"fixture","SecretKey":"Zml4dHVyZS1ub3QtYS1ncmFudA==","Version":"original"` + extra + `}`)
		var identity MinIOBuiltinIdentity
		if minioGateDecode(raw, &identity) == nil {
			clear(identity.SecretKey)
			t.Fatal("identity record gained an embedded authority field")
		}
	}
}

func TestMinIOExpiredV1DoesNotFallThroughToStaticIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fixtures := []minioGateMaterial{
		{Version: "original-minio-source-read-materials.v1", Until: time.Now().Add(-time.Second)},
		{Version: "original-minio-source-read-identities.v2", Until: time.Now().Add(time.Hour)},
		{Version: "original-minio-source-read-identities.v3"},
	}
	for n, fixture := range fixtures {
		raw, e := json.Marshal(fixture)
		if e != nil {
			t.Fatal(e)
		}
		file := filepath.Join(t.TempDir(), "material.json")
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("fixture write failed")
		}
		if _, credentials, key, e := readMinioGateMaterials(ctx, file, minioGateBytesHash(raw), "00112233445566778899aabbccddeeff", minioGateBytesHash([]byte("fixture")), nil, func(context.Context) error { return nil }); e == nil {
			clear(key)
			for i := range credentials {
				clear(credentials[i].SecretKey)
			}
			t.Fatalf("invalid material schema/expiry %d accepted", n)
		}
	}
}
