package install

import (
	"context"
	"testing"
	"time"
)

func TestOriginalMinIORequiresGenuineNativeOwnerAndHold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	zero := &originalMinIOReadKeeper{}
	if zero.check(ctx) == nil {
		t.Fatal("zero native source owner accepted")
	}
	hold := &OriginalWriterHold{}
	if _, _, e := hold.originalMinIOReadServicePeer(ctx, "pod", "container", "image"); e == nil {
		t.Fatal("zero holder supplied a native kept-source classification")
	}
	for _, action := range []string{"minio_native_gate_send_unknown", "minio_native_restore_send_unknown"} {
		if !originalSourceMutationIntent(action) {
			t.Fatal("real MinIO send omitted from closed journal boundary")
		}
	}
	if originalSourceMutationIntent("minio_passed") {
		t.Fatal("unknown synthetic outcome became a source dispatch")
	}
}
