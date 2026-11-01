package systembackupexecution

import (
	"errors"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

func TestPublicationSnapshotPurposeReferencesAreExactAndUnique(t *testing.T) {
	ref := map[string]any{"purpose": "catalog_append", "identity_hash": hash([]byte("original catalog identity DATA")), "version": "original-v1"}
	valid, err := ce.Canonical(map[string]any{"references": []any{ref}})
	if err != nil {
		t.Fatal(err)
	}
	refs, err := publicationSnapshotReferences(valid, hash(valid))
	if err != nil || refs["catalog_append"] != (publicationConfigReference{"catalog_append", ref["identity_hash"].(string), "original-v1"}) {
		t.Fatal(refs, err)
	}
	for _, mode := range []string{"missing-array", "duplicate-purpose", "extra-ref-field", "wrong-identity-type", "wrong-version-field", "reserved-version", "foreign-sha"} {
		t.Run(mode, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range ref {
				copy[k] = v
			}
			values := map[string]any{"references": []any{copy}}
			switch mode {
			case "missing-array":
				delete(values, "references")
			case "duplicate-purpose":
				values["references"] = []any{copy, ref}
			case "extra-ref-field":
				copy["substitute"] = true
			case "wrong-identity-type":
				copy["identity_hash"] = 17
			case "wrong-version-field":
				delete(copy, "version")
				copy["ref_version"] = "original-v1"
			case "reserved-version":
				copy["version"] = "current"
			}
			raw, err := ce.Canonical(values)
			if err != nil {
				t.Fatal(err)
			}
			sha := hash(raw)
			if mode == "foreign-sha" {
				sha = hash([]byte("foreign snapshot DATA"))
			}
			if got, err := publicationSnapshotReferences(raw, sha); !errors.Is(err, c.ErrExecutionAuthority) || got != nil {
				t.Fatal("invalid original purpose refs accepted", got, err)
			}
		})
	}
}
