package main

import sec "clawreef/internal/systembackupsecurity"

// Exclude only the two signer slots whose actual constructor immediately
// follows; never change the inventory or count a pending source as installed.
func missingBeforeOriginalSigningResources(missing []string) []string {
	remaining := []string{}
	for _, key := range missing {
		if key != "reference:acceptance_signing" && key != "reference:catalog_signing" {
			remaining = append(remaining, key)
		}
	}
	return remaining
}

// Full post-signer check: only C's five still-unconstructed slots may remain.
func missingBeforeOriginalMinIOAfterSigning(owners sec.BootstrapOwnerAdapters) []string {
	missing := []string{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(owners) {
		switch key {
		case "reference:artifact_delete", "reference:artifact_read", "reference:artifact_write", "reference:catalog_append", "reference:catalog_read":
			continue
		}
		missing = append(missing, key)
	}
	return missing
}
