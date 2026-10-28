package main

import (
	"database/sql"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// The registration API and download runtime have different write boundaries.
// The caller owns this pool. Loading download authority never borrows the
// registration pool or grants it the download account's privileges.
func openDownloadDatabase(path, registrationPath string, registration *mysql.Config) (*sql.DB, string, error) {
	if registration == nil || registration.User == "" || strings.EqualFold(registration.User, "root") || registration.MultiStatements {
		return nil, "", errDownloadDeployment
	}
	base, err := os.Stat(registrationPath)
	if err != nil || !base.Mode().IsRegular() {
		return nil, "", errDownloadDeployment
	}
	file, err := os.Stat(path)
	if err != nil || !file.Mode().IsRegular() || os.SameFile(base, file) {
		return nil, "", errDownloadDeployment
	}
	raw, err := deploymentBytes(path, 8192)
	if err != nil {
		return nil, "", errDownloadDeployment
	}
	defer func() {
		for n := range raw {
			raw[n] = 0
		}
	}()
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || !downloadUser.MatchString(cfg.User) || strings.EqualFold(cfg.User, "root") || strings.EqualFold(cfg.User, registration.User) || cfg.DBName == "" || cfg.DBName != registration.DBName || cfg.MultiStatements {
		return nil, "", errDownloadDeployment
	}
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 30*time.Second, 30*time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, "", errDownloadDeployment
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	return db, cfg.User, nil
}
