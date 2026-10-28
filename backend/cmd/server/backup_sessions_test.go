package main

import (
	"database/sql"
	"strings"
	"testing"
)

func TestBackupSessionsRequireExplicitConfiguration(t *testing.T) {
	for _, enabled := range []string{"", "false"} {
		s, err := backupSessionRecorder(nil, "", "", func(string) string { return enabled })
		if s != nil || err != nil {
			t.Fatal("disabled sessions required configuration")
		}
	}
	for _, bad := range []string{"flag", "uuid", "installation", "database", "secret", "driver"} {
		t.Run(bad, func(t *testing.T) {
			env := map[string]string{"SYSTEM_BACKUP_READ_SESSIONS_ENABLED": "true", "SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID": "11111111-2222-3333-4444-555555555555", "SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID": "installation_sessions"}
			database := "synthetic"
			secret := strings.Repeat("s", 32)
			db := new(sql.DB)
			switch bad {
			case "flag":
				env["SYSTEM_BACKUP_READ_SESSIONS_ENABLED"] = "yes"
			case "uuid":
				env["SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID"] = ""
			case "installation":
				env["SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID"] = ""
			case "database":
				database = ""
			case "secret":
				secret = "short"
			case "driver":
				db = nil
			}
			if s, err := backupSessionRecorder(db, database, secret, func(k string) string { return env[k] }); s != nil || err == nil {
				t.Fatal("incomplete configuration accepted")
			}
		})
	}
	s, err := backupSessionRecorder(new(sql.DB), "synthetic", strings.Repeat("s", 32), func(k string) string {
		switch k {
		case "SYSTEM_BACKUP_READ_SESSIONS_ENABLED":
			return "true"
		case "SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID":
			return "11111111-2222-3333-4444-555555555555"
		default:
			return "installation_sessions"
		}
	})
	if s == nil || err != nil {
		t.Fatal("valid explicit configuration rejected")
	}
}
