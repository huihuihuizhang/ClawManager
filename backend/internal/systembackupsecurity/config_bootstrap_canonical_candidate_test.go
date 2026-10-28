package systembackupsecurity

import (
	"bytes"
	"testing"
)

func TestBootstrapCanonicalCandidateInsertUsesOneValidatedConfig(t *testing.T) {
	c, err := DecodeBootstrapConfig(bootstrapFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	oldColumns, oldArgs := c.sqlValues("installation_synthetic", "42", "review")
	columns, args := c.sqlValuesWithCanonical("installation_synthetic", "42", "review")
	if len(columns) != len(oldColumns)+1 || len(args) != len(oldArgs)+1 ||
		columns[len(columns)-1] != "canonical_config_json" ||
		args[2] != c.SHA256() || args[3] != len(c.CanonicalJSON()) {
		t.Fatal("candidate insert lost canonical hash, size or column binding")
	}
	for i := range oldColumns {
		if columns[i] != oldColumns[i] || args[i] != oldArgs[i] {
			t.Fatal("candidate insert changed existing materialized column", oldColumns[i])
		}
	}
	stored, ok := args[len(args)-1].([]byte)
	if !ok || !bytes.Equal(stored, c.CanonicalJSON()) {
		t.Fatal("candidate insert used a different source than the config hash")
	}
	stored[0] = 'x'
	if c.CanonicalJSON()[0] != '{' {
		t.Fatal("candidate SQL argument aliased the validated config")
	}
}
