package db

import "testing"

func TestLegacy198OriginalReadproofDoesNotRelaxCopyIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, server, database string
		original, want         bool
	}{
		{"original", legacySiteServerUUID, "clawmanager", true, true},
		{"copy_api_rejects_original", legacySiteServerUUID, "clawmanager", false, false},
		{"copy", legacySiteServerUUID, "cm_import_0123456789abcdef0123456789abcdef", false, true},
		{"original_rejects_copy", legacySiteServerUUID, "cm_import_0123456789abcdef0123456789abcdef", true, false},
		{"wrong_server", "f1f5f76a-0000-11f1-b08e-366835b4a029", "clawmanager", true, false},
		{"other_database", legacySiteServerUUID, "clawmanager_other", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if legacy198ReadProofIdentity(tc.server, tc.database, tc.original) != tc.want {
				t.Fatal("original/copy identity separation")
			}
		})
	}
}
func TestLegacy198OriginalReadproofRequiresExactOriginalSchema(t *testing.T) {
	if !legacy198ReadProofSchema(legacySiteSchemaSHA, true) || legacy198ReadProofSchema(legacyDumpCopySchemaSHA, true) || legacy198ReadProofSchema("unknown", true) {
		t.Fatal("original schema broadened")
	}
	if !legacy198ReadProofSchema(legacySiteSchemaSHA, false) || !legacy198ReadProofSchema(legacyDumpCopySchemaSHA, false) {
		t.Fatal("original copy contract changed")
	}
}
