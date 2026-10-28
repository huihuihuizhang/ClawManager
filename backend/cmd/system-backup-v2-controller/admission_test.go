package main

import "testing"

func TestVersionedControlDoesNotInheritLegacyActivation(t *testing.T) {
	for _, env := range []map[string]string{{}, {"SYSTEM_BACKUP_ENABLED": "true"}, {"SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED": "true", "SYSTEM_BACKUP_ENABLED": "true"}, {"SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED": "true", "SYSTEM_BACKUP_ENABLED": "garbage"}} {
		if versionedControlAdmission(func(k string) string { return env[k] }) == nil {
			t.Fatal("uncomposed versioned engine admitted", env)
		}
	}
	if err := versionedControlAdmission(func(k string) string {
		if k == "SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED" {
			return "true"
		}
		return "false"
	}); err != nil {
		t.Fatal(err)
	}
}
