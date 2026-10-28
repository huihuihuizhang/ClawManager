package db

import (
	"clawreef/internal/config"
	"context"
	"database/sql"
	"testing"
)

func TestPublicMetadataConnectionRequiresDedicatedAdmission(t *testing.T) {
	for _, tc := range []struct {
		user  string
		admit func(context.Context, *sql.DB) error
	}{
		{"root", func(context.Context, *sql.DB) error { t.Fatal("root reached grant admission"); return nil }},
		{"backup_capture", nil},
		{"", func(context.Context, *sql.DB) error { t.Fatal("empty user reached grant admission"); return nil }},
	} {
		if s, e := ConnectPublicBackupMetadata(config.DatabaseConfig{User: tc.user}, tc.admit); e == nil || s != nil {
			t.Fatal("unadmitted metadata pool escaped")
		}
	}
}
