package systembackupexecution

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestArtifactReadMaterialRetainsOriginalSafeRootsAndScope(t *testing.T) {
	store, state := newANativePublicationStore(t, time.Minute)
	material := artifactReadMaterials(store.config)
	for _, root := range []string{"archive/" + material.InstallationID + "/", "tenant/signed-artifact-scope/"} {
		current := material
		current.Root = root
		original := store.config
		original.Root = root
		if original.validate() != nil {
			t.Fatal("original target rejected safe fixture root")
		}
		reader, err := NewArtifactReadOnlyS3(current)
		if err != nil {
			t.Fatal("original safe root became unreadable", root, err)
		}
		requests := 0
		state.onRead = func(http.ResponseWriter, *http.Request) bool { requests++; return true }
		for _, key := range []string{"foreign/original.enc", root + "../foreign.enc", "/" + root + "original.enc"} {
			if _, err = reader.ResolveIndexedObject(context.Background(), key, hash([]byte("fixture")), 7, ArtifactVersionSearchBudget{MaxVersions: 2, MaxPages: 1, MaxReadBytes: 16}, time.Now().Add(time.Second)); err == nil {
				t.Fatal("unsafe/out-of-scope key selected read", key)
			}
		}
		reader.Close()
		if requests != 0 {
			t.Fatal("unsafe/out-of-scope key caused native IO")
		}
	}
	for _, root := range []string{"archive/no-trailing-slash", "/absolute/", "../escape/", "safe/../escape/", "safe//empty/", "safe/./dot/"} {
		current := material
		current.Root = root
		if reader, err := NewArtifactReadOnlyS3(current); err == nil {
			reader.Close()
			t.Fatal("unsafe root accepted", root)
		}
	}
}
