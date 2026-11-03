package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"database/sql"
	mysql "github.com/go-sql-driver/mysql"
	"strings"
	"time"
)

// The constructor still calls checkSource on this pool before capture runtime
// composition. TLS never substitutes for source account, UUID or grant checks.
func openDeploymentSource(cfg DeploymentConfig) (*sql.DB, error) {
	raw, err := readPrivate(cfg.SourceDSNFile, 16384)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	driver, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || driver.User != cfg.SourceUser || driver.DBName != cfg.SourceDatabase || driver.MultiStatements || driver.AllowAllFiles {
		return nil, c.ErrExecutionAuthority
	}
	driver.ParseTime = true
	driver.Loc = time.UTC
	driver.Timeout = 5 * time.Second
	driver.ReadTimeout = 10 * time.Second
	driver.WriteTimeout = 10 * time.Second
	if driver.Params == nil {
		driver.Params = map[string]string{}
	}
	driver.Params["time_zone"] = "'+00:00'"
	if cfg.SourceTLS != nil {
		if !cfg.SourceTLS.Selected() || cfg.SourceTLS.Apply(driver) != nil {
			return nil, c.ErrExecutionAuthority
		}
	}
	connector, err := mysql.NewConnector(driver)
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	pool := sql.OpenDB(connector)
	pool.SetMaxOpenConns(4)
	pool.SetMaxIdleConns(2)
	return pool, nil
}
