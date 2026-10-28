package systembackupexecution

import (
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

func TestPublicCaptureRejectsUnsupportedDomainsBeforePrepare(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *d.BackupSpec
		ok   bool
	}{
		{"workspace", &d.BackupSpec{TaskPurpose: "functional_test", RequestedParts: []string{"workspace"}}, true},
		{"missing", nil, false},
		{"acceptance", &d.BackupSpec{TaskPurpose: "acceptance", RequestedParts: []string{"workspace"}}, false},
		{"database", &d.BackupSpec{TaskPurpose: "functional_test", RequestedParts: []string{"database"}}, false},
		{"mixed", &d.BackupSpec{TaskPurpose: "functional_test", RequestedParts: []string{"workspace", "database"}}, false},
		{"unspecified", &d.BackupSpec{TaskPurpose: "functional_test"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := supportedPublicCapture(d.Input{Backup: tc.spec}); (e == nil) != tc.ok {
				t.Fatalf("supported=%v, error=%v", tc.ok, e)
			}
		})
	}
}
