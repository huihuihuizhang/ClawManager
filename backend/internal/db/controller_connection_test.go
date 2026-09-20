package db

import (
	"testing"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/upper/db/v4/adapter/mysql"
)

func TestSystemBackupControllerOptionsConfigureEveryMySQLConnectionForUTC(t *testing.T) {
	options := systemBackupControllerOptions()
	if options["loc"] != "UTC" || options["time_zone"] != "'+00:00'" {
		t.Fatalf("controller UTC options drifted: %#v", options)
	}
	settings := mysql.ConnectionURL{
		Host: "127.0.0.1:3306", User: "sbk_controller", Database: "clawmanager",
		Options: options,
	}
	parsed, err := mysqlDriver.ParseDSN(settings.String())
	if err != nil {
		t.Fatalf("controller connection URL is not a valid MySQL DSN: %v", err)
	}
	if parsed.Loc.String() != "UTC" || parsed.Params["time_zone"] != "'+00:00'" {
		t.Fatalf("controller UTC settings were lost when encoded into the MySQL DSN: loc=%s time_zone=%q", parsed.Loc, parsed.Params["time_zone"])
	}
}
