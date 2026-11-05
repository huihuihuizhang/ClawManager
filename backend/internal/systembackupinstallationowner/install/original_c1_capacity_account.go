package install

import (
	"clawreef/internal/mysqltls"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"github.com/go-sql-driver/mysql"
	"io"
	"path/filepath"
	"reflect"
	"time"
)

type originalC1CapacityOperation struct {
	Version, Operation, ServerUUID, Database, Address, KubeconfigSHA256, OriginalUsersSHA256 string
	AdminID                                                                                  int64
	AdminUsername                                                                            string
	Identity                                                                                 originalSQLIdentity
	Account                                                                                  originalSQLAccount
	Capacity                                                                                 sec.CapacityCollectorConfig
	TLS                                                                                      mysqltls.Material
	Tables                                                                                   []string
}

type OriginalC1CapacityAccountReceipt struct {
	Version, State                                      string
	Operation, CapacityConfig, CapacityDSN, CapacityTLS BootstrapSourceFilePin
	Config                                              sec.CapacityCollectorConfig
	OriginalUsersPreserved                              bool
}

func (s *originalSQLSession) c1CapacityTables(ctx context.Context) ([]string, error) {
	rows, e := s.conn.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' AND (LEFT(TABLE_NAME,14)='system_backup_' OR LEFT(TABLE_NAME,15)='system_restore_' OR TABLE_NAME='audit_logs') ORDER BY TABLE_NAME")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) != nil || !originalSQLName.MatchString(n) {
			return nil, errOriginalSQLAccounts
		}
		names = append(names, n)
	}
	if rows.Err() != nil {
		return nil, errOriginalSQLAccounts
	}
	return names, nil
}
func (s *originalSQLSession) c1CapacityCheck(ctx context.Context, p originalC1CapacityOperation) error {
	if p.Version != "original-c1-capacity-account-operation.v1" || p.ServerUUID != s.input.server || p.Database != s.input.database || p.Address != s.cfg.Addr || p.KubeconfigSHA256 != s.input.kubeSHA || !reflect.DeepEqual(p.Identity, s.identity) || !reflect.DeepEqual(p.TLS, s.material) || p.Capacity.Validate() != nil || p.Account.Role != "capacity" || p.Account.User != p.Capacity.User || s.identityCheck(ctx) != nil {
		return errOriginalSQLAccounts
	}
	id, name, e := s.admin(ctx, p.AdminUsername)
	if e != nil || id != p.AdminID || name != p.AdminUsername {
		return errOriginalSQLAccounts
	}
	tables, e := s.tables(ctx)
	if e != nil || !reflect.DeepEqual(tables, p.Tables) {
		return errOriginalSQLAccounts
	}
	selected, e := s.c1CapacityTables(ctx)
	if e != nil || !reflect.DeepEqual(selected, p.Capacity.Tables) {
		return errOriginalSQLAccounts
	}
	old, e := s.originalUsers(ctx, map[string]bool{p.Account.User + "@" + p.Account.Host: true})
	if e != nil {
		return e
	}
	raw, e := canonical(old)
	if e != nil || hash(raw) != p.OriginalUsersSHA256 {
		return errOriginalSQLAccounts
	}
	return nil
}
func (s *originalSQLSession) c1CapacityQuery(ctx context.Context, p originalC1CapacityOperation, directory string) (OriginalC1CapacityAccountReceipt, error) {
	var zero OriginalC1CapacityAccountReceipt
	if s.c1CapacityCheck(ctx, p) != nil {
		return zero, errOriginalSQLAccounts
	}
	present, e := s.owned(ctx, originalSQLPlan{Operation: p.Operation}, p.Account)
	if e != nil || !present {
		return zero, errOriginalSQLAccounts
	}
	var locked, ssl string
	if s.conn.QueryRowContext(ctx, "SELECT account_locked,ssl_type FROM mysql.user WHERE User=? AND Host=?", p.Account.User, p.Account.Host).Scan(&locked, &ssl) != nil || locked != "N" || ssl != "ANY" {
		return zero, errOriginalSQLAccounts
	}
	privileges, e := s.actualPrivileges(ctx, p.Account)
	if e != nil || !reflect.DeepEqual(privileges, p.Account.Privileges) {
		return zero, errOriginalSQLAccounts
	}
	cfg := s.cfg.Clone()
	cfg.User = p.Account.User
	cfg.Passwd = p.Account.Password
	cfg.TLS = nil
	cfg.TLSConfig = ""
	if p.TLS.Apply(cfg) != nil {
		return zero, errOriginalSQLAccounts
	}
	cfg.Logger = silentDatabaseSourceLogger{}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return zero, errOriginalSQLAccounts
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	if _, e = sec.CollectPinnedRegistrationCapacity(ctx, db, p.Capacity); e != nil {
		return zero, errOriginalSQLAccounts
	}
	if s.c1CapacityCheck(ctx, p) != nil {
		return zero, errOriginalSQLAccounts
	}
	pin := func(name string) BootstrapSourceFilePin {
		b, e := ReadPrivateFile(filepath.Join(directory, name), 262144)
		if e != nil {
			return BootstrapSourceFilePin{}
		}
		return BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(b)}
	}
	receipt := OriginalC1CapacityAccountReceipt{Version: "original-c1-capacity-account-result.v1", State: "original_capacity_select_only_native_verified", Operation: pin("capacity-operation.json"), CapacityConfig: pin("capacity-config.json"), CapacityDSN: pin("capacity.dsn"), CapacityTLS: pin("capacity-tls.json"), Config: p.Capacity, OriginalUsersPreserved: true}
	if !bootstrapSourcePinValid(receipt.Operation) || !bootstrapSourcePinValid(receipt.CapacityConfig) || !bootstrapSourcePinValid(receipt.CapacityDSN) || !bootstrapSourcePinValid(receipt.CapacityTLS) {
		return zero, errOriginalSQLAccounts
	}
	raw, e := readBootstrapSourcePin(receipt.CapacityConfig, 65536)
	var config sec.CapacityCollectorConfig
	if e != nil || decodeExact(raw, &config) != nil || !reflect.DeepEqual(config, p.Capacity) {
		return zero, errOriginalSQLAccounts
	}
	raw, e = readBootstrapSourcePin(receipt.CapacityTLS, 65536)
	var tls mysqltls.Material
	if e != nil || decodeExact(raw, &tls) != nil || !reflect.DeepEqual(tls, p.TLS) {
		return zero, errOriginalSQLAccounts
	}
	raw, e = readBootstrapSourcePin(receipt.CapacityDSN, 16384)
	if e != nil {
		return zero, e
	}
	defer clear(raw)
	actual, e := mysql.ParseDSN(string(raw))
	if e != nil || actual.User != p.Account.User || actual.Passwd != p.Account.Password || actual.Addr != p.Address || actual.DBName != p.Database || actual.TLSConfig != "" || actual.TLS != nil {
		return zero, errOriginalSQLAccounts
	}
	opraw, e := readBootstrapSourcePin(receipt.Operation, 262144)
	var retained originalC1CapacityOperation
	if e != nil || originalSQLJSON(opraw, &retained) != nil || !reflect.DeepEqual(retained, p) {
		return zero, errOriginalSQLAccounts
	}
	return receipt, nil
}

// Standalone existing original SQL owner authentication/serialization is reused.
// This action adds ONE exact-table SELECT-only principal, no schema/routine,
// global settings, enrollment, backup permission or source observation DTO.
func RunOriginalC1CapacityAccount(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-c1-native-inputs capacity", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var in originalSQLInputs
	mode := f.String("mode", "", "issue, query or rollback")
	datadir := f.String("data-directory", "", "actual approved native readonly MySQL datadir")
	for _, v := range []struct {
		name   string
		target *string
	}{{"admin-dsn-file", &in.dsn}, {"admin-dsn-sha256", &in.dsnSHA}, {"source-tls-file", &in.tls}, {"source-tls-sha256", &in.tlsSHA}, {"kubeconfig-file", &in.kube}, {"kubeconfig-sha256", &in.kubeSHA}, {"namespace", &in.namespace}, {"namespace-uid", &in.nsUID}, {"cluster-uid", &in.clusterUID}, {"expected-server-uuid", &in.server}, {"database", &in.database}, {"local-admin-password-file", &in.password}, {"local-admin-username", &in.username}, {"account-host", &in.host}, {"output-directory", &in.directory}, {"operation-file", &in.operationFile}, {"operation-sha256", &in.operationSHA}} {
		f.StringVar(v.target, v.name, "", "")
	}
	f.BoolVar(&in.allowAny, "allow-wildcard-host", false, "")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 || (*mode != "issue" && *mode != "query" && *mode != "rollback") || privateDirectory(in.directory) != nil || in.password == "" || (!originalSQLHost.MatchString(in.host) && !(in.host == "%" && in.allowAny)) {
		return 2
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s, e := openOriginalSQLAccounts(active, in)
	if e != nil {
		return 1
	}
	defer s.close()
	var p originalC1CapacityOperation
	if *mode == "issue" {
		if in.operationFile != "" || in.operationSHA != "" {
			return 2
		}
		id, name, e := s.admin(active, in.username)
		if e != nil {
			return 1
		}
		tables, e := s.tables(active)
		if e != nil {
			return 1
		}
		selected, e := s.c1CapacityTables(active)
		if e != nil {
			return 1
		}
		operation, e := originalSQLRandom(16)
		if e != nil {
			return 1
		}
		password, e := originalSQLRandom(32)
		if e != nil {
			return 1
		}
		user := "sbk_cap_" + operation[:16]
		account := originalSQLAccount{Role: "capacity", User: user, Host: in.host, Password: password}
		for _, t := range selected {
			account.Privileges = append(account.Privileges, originalSQLPrivilege{Kind: "table", Database: in.database, Object: t, Verb: "SELECT"})
		}
		originalSQLSortPrivileges(account.Privileges)
		old, e := s.originalUsers(active, map[string]bool{})
		if e != nil {
			return 1
		}
		raw, e := canonical(old)
		if e != nil {
			return 1
		}
		p = originalC1CapacityOperation{Version: "original-c1-capacity-account-operation.v1", Operation: operation, ServerUUID: in.server, Database: in.database, Address: s.cfg.Addr, KubeconfigSHA256: in.kubeSHA, OriginalUsersSHA256: hash(raw), AdminID: id, AdminUsername: name, Identity: s.identity, Account: account, Capacity: sec.CapacityCollectorConfig{ServerUUID: in.server, Database: in.database, User: user, DataDir: *datadir, Tables: selected}, TLS: s.material, Tables: tables}
		if p.Capacity.Validate() != nil || s.c1CapacityCheck(active, p) != nil {
			return 1
		}
		cfg := s.cfg.Clone()
		cfg.User = user
		cfg.Passwd = password
		cfg.TLS = nil
		cfg.TLSConfig = ""
		if originalSQLWrite(in.directory, "capacity-operation.json", p) != nil || originalSQLWrite(in.directory, "capacity-config.json", p.Capacity) != nil || originalSQLWrite(in.directory, "capacity-tls.json", p.TLS) != nil || originalSQLWriteBytes(in.directory, "capacity.dsn", []byte(cfg.FormatDSN())) != nil {
			return 1
		}
		if s.send(active, in.directory, "create_capacity_locked", "CREATE USER "+originalSQLAccountName(account)+" IDENTIFIED BY "+originalSQLQuote(password)+" REQUIRE SSL ACCOUNT LOCK ATTRIBUTE "+originalSQLQuote(`{"clawmanager_sql_bootstrap":"`+operation+`:capacity"}`)) != nil {
			return 3
		}
		for _, v := range account.Privileges {
			if s.c1CapacityCheck(active, p) != nil || s.send(active, in.directory, "grant_capacity_"+v.Object, originalSQLGrant(originalSQLPlan{Database: in.database}, account, v)) != nil {
				return 3
			}
		}
		if s.send(active, in.directory, "unlock_capacity", "ALTER USER "+originalSQLAccountName(account)+" ACCOUNT UNLOCK") != nil {
			return 3
		}
	} else {
		if in.operationFile != filepath.Join(in.directory, "capacity-operation.json") || len(in.operationSHA) != 64 {
			return 2
		}
		raw, e := originalSQLBytes(in.operationFile, in.operationSHA, 262144)
		if e != nil || originalSQLJSON(raw, &p) != nil || p.Account.Host != in.host || s.c1CapacityCheck(active, p) != nil {
			return 1
		}
	}
	if *mode == "rollback" {
		present, e := s.owned(active, originalSQLPlan{Operation: p.Operation}, p.Account)
		if e != nil {
			return 1
		}
		if present && s.send(active, in.directory, "drop_original_owned_capacity", "DROP USER "+originalSQLAccountName(p.Account)) != nil {
			return 3
		}
		if s.c1CapacityCheck(active, p) != nil {
			return 1
		}
		_ = json.NewEncoder(out).Encode(map[string]string{"state": "original_capacity_account_absent_original_users_preserved"})
		return 0
	}
	receipt, e := s.c1CapacityQuery(active, p, in.directory)
	if e != nil {
		return 3
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
