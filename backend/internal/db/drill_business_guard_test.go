package db

import (
	"strings"
	"testing"

	"clawreef/internal/config"
)

func TestEveryBusinessConnectionRejectsIsolatedDrillBeforeIO(t *testing.T) {
	for _, name := range []string{"cm_drill_worker", "cm_drill_0123456789abcdef", "CM_DRILL_WORKER", "CM_RESTORE_0123456789ABCDEF0123456789ABCDEF", "cm_import_0123456789abcdef0123456789abcdef"} {
		for _, entry := range []string{"initialize", "connect", "read"} {
			t.Run(name+"/"+entry, func(t *testing.T) {
				cfg := config.DatabaseConfig{Host: "127.0.0.1", Port: 1, User: "unused", Database: name}
				before := Session
				var err error
				switch entry {
				case "initialize":
					_, err = Initialize(cfg)
				case "connect":
					_, err = Connect(cfg)
				case "read":
					_, err = OpenSystemBackupRead(cfg)
				}
				if err == nil || !strings.Contains(err.Error(), "isolated restore databases cannot run business services") || Session != before {
					t.Fatal("isolated drill reached business SQL or replaced Session", err)
				}
			})
		}
	}
}
