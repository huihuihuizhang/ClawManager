package main

import (
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"testing"
)

func TestOriginalCatalogPreflightKeepsSixUnconstructedOwnersMissing(t *testing.T) {
	owners := sec.BootstrapOwnerAdapters{}
	before := sec.MissingBootstrapOwnerAdapters(owners)
	filtered := missingBeforeOriginalCatalog(owners)
	if len(before) != 30 || len(filtered) != 24 || len(sec.MissingBootstrapOwnerAdapters(owners)) != 30 {
		t.Fatal("pending six-role catalog counted as concrete")
	}
	for _, key := range []string{"reference:acceptance_signing", "reference:catalog_signing", "reference:status_relay", "cross_resources"} {
		found := false
		for _, missing := range filtered {
			found = found || key == missing
		}
		if !found {
			t.Fatal("unrelated missing owner hidden", key)
		}
	}
	if linked, original, e := addOriginalCatalogTerminal(owners, nil, install.BootstrapTerminalFiles{}, nil); e == nil || original != nil || linked.Candidates != nil {
		t.Fatal("detached catalog became terminal")
	}
	if originalSixReferenceAliases(owners, nil) {
		t.Fatal("missing original six-reference pointer accepted")
	}
}
