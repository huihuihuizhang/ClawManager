package install

import (
	sec "clawreef/internal/systembackupsecurity"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestCatalogInitialInventorySignatureBindsInitialScopeAndMode(t *testing.T) {
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := CatalogInitialInventory{Version: CatalogInitialInventoryVersion, Mode: "inventory_manifest_initial_checkpoint", DefinitionSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64), Installation: "original", NamespaceUID: "original-namespace-uid", Reference: sec.BootstrapSecretRef{Purpose: "catalog_snapshot", IdentityHash: strings.Repeat("c", 64), Version: "original-v1"}, ProviderSHA256: strings.Repeat("d", 64), Bucket: "original-catalog", Root: "original/catalog/", CoveragePrefix: "original/catalog/", ScanSHA256: strings.Repeat("e", 64), CapturedAt: now, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	r.Key = CatalogInitialInventoryKey(r.DefinitionSHA256, r.Reference, r.Root)
	sign := func(value CatalogInitialInventory) SignedCatalogInitialInventory {
		raw, e := canonical(value)
		if e != nil {
			t.Fatal(e)
		}
		return SignedCatalogInitialInventory{raw, ed25519.Sign(key, append([]byte(catalogInitialInventoryDomain), raw...))}
	}
	signed := sign(r)
	if got, e := InspectCatalogInitialInventory(signed, public); e != nil || got != r {
		t.Fatal("original initial checkpoint refused", e)
	}
	successor := r
	successor.Root = r.Installation + "/catalog-" + r.ConfigSHA256 + "/"
	successor.CoveragePrefix = successor.Root
	successor.Key = CatalogInitialInventoryKey(r.DefinitionSHA256, r.Reference, successor.Root)
	if got, e := InspectCatalogInitialInventory(sign(successor), public); e != nil || got != successor {
		t.Fatal("config-bound successor checkpoint refused", e)
	}
	for _, root := range []string{r.Installation + "/catalog-" + strings.Repeat("f", 64) + "/", r.Root + r.ConfigSHA256 + "/"} {
		foreign := successor
		foreign.Root, foreign.CoveragePrefix = root, root
		foreign.Key = CatalogInitialInventoryKey(r.DefinitionSHA256, r.Reference, root)
		if _, e := InspectCatalogInitialInventory(sign(foreign), public); e == nil {
			t.Fatalf("foreign or overlapping catalog root admitted: %s", root)
		}
	}
	changed := r
	changed.Count = 1
	if _, e := InspectCatalogInitialInventory(sign(changed), public); e == nil {
		t.Fatal("nonempty initial inventory admitted")
	}
	changed = r
	changed.Mode = "current_catalog"
	if _, e := InspectCatalogInitialInventory(sign(changed), public); e == nil {
		t.Fatal("current-source reinterpretation admitted")
	}
	changed = r
	changed.CoveragePrefix = "foreign/"
	if _, e := InspectCatalogInitialInventory(sign(changed), public); e == nil {
		t.Fatal("foreign coverage admitted")
	}
	changed = r
	changed.Reference.Version = "current"
	if _, e := InspectCatalogInitialInventory(sign(changed), public); e == nil {
		t.Fatal("floating reference admitted")
	}
	signed.Record[0] ^= 1
	if _, e := InspectCatalogInitialInventory(signed, public); e == nil {
		t.Fatal("tampered checkpoint admitted")
	}
}
