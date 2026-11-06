package install

// Original SQL identity/material production. This does NOT migrate business
// schema, issue enrollment/owner authority, adopt history or enable a config.
import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/schemaobjects"
	controller "clawreef/internal/systembackupcontroller"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	authentication "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var errOriginalSQLAccounts = errors.New("original SQL account operation not confirmed; retain exact private operation")
var originalSQLName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var originalSQLHost = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)

type originalSQLPrivilege struct{ Kind, Database, Object, Column, Verb string }
type originalSQLAccount struct {
	Role, User, Host, Password string
	Locked                     bool
	Privileges                 []originalSQLPrivilege
}
type originalSQLUser struct {
	User, Host, Plugin, Authentication, Locked, SSL string
	Grants                                          []string
}
type originalSQLIdentity struct {
	Namespace, NamespaceUID, ClusterUID, Subject, UID string
	Groups                                            []string
}
type originalSQLPlan struct {
	Version, Operation, ServerUUID, Database, Address, LedgerSHA256, KubeconfigSHA256 string
	AdminID                                                                           int64
	AdminUsername                                                                     string
	Identity                                                                          originalSQLIdentity
	Secure                                                                            bool
	PersistedSecure                                                                   *string
	OriginalUsers                                                                     []originalSQLUser
	Tables                                                                            []string
	PartialRevokes                                                                    bool
	CensusDefinition                                                                  string
	Census                                                                            domain.SchemaCensusSpec
	Accounts                                                                          []originalSQLAccount
	TLS                                                                               mysqltls.Material
}
type originalSQLInputs struct {
	appDeployment, appDeploymentUID                                                                                                                                      string
	dsn, dsnSHA, tls, tlsSHA, kube, kubeSHA, namespace, nsUID, clusterUID, server, database, ledgerSHA, password, username, host, directory, operationFile, operationSHA string
	allowAny                                                                                                                                                             bool
	freshInstallation                                                                                                                                                    bool
	runtimeProfile                                                                                                                                                       string
}
type originalSQLSession struct {
	db       *sql.DB
	conn     *sql.Conn
	cfg      *mysql.Config
	material mysqltls.Material
	kube     kubernetes.Interface
	identity originalSQLIdentity
	input    originalSQLInputs
}

func originalSQLJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errOriginalSQLAccounts
	}
	return nil
}
func originalSQLBytes(file, pin string, limit int64) ([]byte, error) {
	b, e := ReadPrivateFile(file, limit)
	if e != nil || pin != "" && hash(b) != pin {
		clear(b)
		return nil, errOriginalSQLAccounts
	}
	return b, nil
}
func originalSQLWrite(directory, name string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return errOriginalSQLAccounts
	}
	defer clear(raw)
	return originalSQLWriteBytes(directory, name, raw)
}
func originalSQLWriteBytes(directory, name string, raw []byte) error {
	if privateDirectory(directory) != nil || filepath.Base(name) != name || len(raw) < 1 || len(raw) > 262144 {
		return errOriginalSQLAccounts
	}
	canonical, pathErr := filepath.EvalSymlinks(directory)
	if pathErr != nil || canonical != directory {
		return errOriginalSQLAccounts
	}
	f, e := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errOriginalSQLAccounts
	}
	n, w := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if w != nil || syncErr != nil || closeErr != nil || n != len(raw) {
		return errOriginalSQLAccounts
	}
	dir, e := os.Open(directory)
	if e != nil {
		return errOriginalSQLAccounts
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errOriginalSQLAccounts
	}
	return nil
}
func originalSQLMark(directory, kind string, details any) error {
	var id [12]byte
	if _, e := rand.Read(id[:]); e != nil {
		return errOriginalSQLAccounts
	}
	return originalSQLWrite(directory, kind+"-"+hex.EncodeToString(id[:])+".json", details)
}
func originalSQLQuote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", "''") + "'"
}
func originalSQLAccountName(a originalSQLAccount) string {
	return originalSQLQuote(a.User) + "@" + originalSQLQuote(a.Host)
}
func originalSQLIdentifier(s string) string { return "`" + s + "`" }
func originalSQLRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", errOriginalSQLAccounts
	}
	defer clear(b)
	return hex.EncodeToString(b), nil
}

func openOriginalSQLAccounts(ctx context.Context, in originalSQLInputs) (*originalSQLSession, error) {
	if !originalSQLName.MatchString(in.database) || in.server == "" || (in.ledgerSHA != "" && len(in.ledgerSHA) != 64) || in.nsUID == "" || in.clusterUID == "" {
		return nil, errOriginalSQLAccounts
	}
	kube, _, _, e := openOriginalEnrollmentKubernetes(BootstrapSourceFilePin{File: in.kube, SHA256: in.kubeSHA})
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	who, e := kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authentication.SelfSubjectReview{}, metav1.CreateOptions{})
	if e != nil || who.Status.UserInfo.Username == "" || who.Status.UserInfo.Username == "system:anonymous" {
		return nil, errOriginalSQLAccounts
	}
	ns, e := kube.CoreV1().Namespaces().Get(ctx, in.namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != in.nsUID || ns.DeletionTimestamp != nil {
		return nil, errOriginalSQLAccounts
	}
	cluster, e := kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || string(cluster.UID) != in.clusterUID || cluster.DeletionTimestamp != nil {
		return nil, errOriginalSQLAccounts
	}
	identity := originalSQLIdentity{Namespace: in.namespace, NamespaceUID: in.nsUID, ClusterUID: in.clusterUID, Subject: who.Status.UserInfo.Username, UID: who.Status.UserInfo.UID, Groups: append([]string{}, who.Status.UserInfo.Groups...)}
	sort.Strings(identity.Groups)
	raw, e := originalSQLBytes(in.dsn, in.dsnSHA, 16384)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	cfg, e := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if e != nil || cfg.User != "root" || cfg.Net != "tcp" || cfg.DBName != in.database || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext {
		return nil, errOriginalSQLAccounts
	}
	for k := range cfg.Params {
		if k != "time_zone" {
			return nil, errOriginalSQLAccounts
		}
	}
	body, e := originalSQLBytes(in.tls, in.tlsSHA, 65536)
	if e != nil {
		return nil, e
	}
	defer clear(body)
	var mat mysqltls.Material
	if originalSQLJSON(body, &mat) != nil || !mat.Selected() || mat.Apply(cfg) != nil {
		return nil, errOriginalSQLAccounts
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	cfg.Logger = silentDatabaseSourceLogger{}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	conn, e := db.Conn(ctx)
	if e != nil {
		db.Close()
		return nil, errOriginalSQLAccounts
	}
	s := &originalSQLSession{db: db, conn: conn, cfg: cfg, material: mat, kube: kube, identity: identity, input: in}
	if s.identityCheck(ctx) != nil {
		s.close()
		return nil, errOriginalSQLAccounts
	}
	// This native session lock serializes *all* account/routine/global mutation
	// sends and recovery, including a prior disconnected operation still running.
	lock := "sbk-sql-accounts-" + hash([]byte(in.server + "/" + in.database))[:40]
	var held int
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,0)", lock).Scan(&held) != nil || held != 1 {
		s.close()
		return nil, errOriginalSQLAccounts
	}
	return s, nil
}
func (s *originalSQLSession) close() {
	if s.conn != nil {
		s.conn.Raw(func(any) error { return driver.ErrBadConn })
		s.conn.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.cfg != nil {
		s.cfg.Passwd = ""
	}
}
func (s *originalSQLSession) identityCheck(ctx context.Context) error {
	var server, database, user, role, name, version string
	if s.conn.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE()").Scan(&server, &database, &user, &role) != nil || server != s.input.server || database != s.input.database || !strings.HasPrefix(user, "root@") || role != "NONE" {
		return errOriginalSQLAccounts
	}
	if s.conn.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &version) != nil || name != "Ssl_version" || version != "TLSv1.3" {
		return errOriginalSQLAccounts
	}
	return nil
}
func (s *originalSQLSession) admin(ctx context.Context, selected string) (int64, string, error) {
	password, e := ReadPrivateFile(s.input.password, 1024)
	if e != nil {
		return 0, "", errOriginalSQLAccounts
	}
	defer clear(password)
	rows, e := s.conn.QueryContext(ctx, "SELECT id,username,password_hash FROM users WHERE role='admin' AND is_active=1 AND auth_provider='local' ORDER BY id")
	if e != nil {
		return 0, "", errOriginalSQLAccounts
	}
	count := 0
	matches := 0
	var id, chosen int64
	var username, stored, name string
	for rows.Next() {
		count++
		if count > 1000 || rows.Scan(&id, &username, &stored) != nil {
			rows.Close()
			return 0, "", errOriginalSQLAccounts
		}
		if (selected == "" || selected == username) && bcrypt.CompareHashAndPassword([]byte(stored), password) == nil {
			matches++
			chosen = id
			name = username
		}
		stored = ""
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || matches != 1 || chosen < 1 || name == "" {
		return 0, "", errOriginalSQLAccounts
	}
	return chosen, name, nil
}
func (s *originalSQLSession) unused(ctx context.Context) error {
	var n int
	for _, table := range []string{"system_backup_installation_owner_heads", "system_backup_v2_configs"} {
		if s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+originalSQLIdentifier(table)).Scan(&n) != nil || n != 0 {
			return errOriginalSQLAccounts
		}
	}
	cms, e := s.kube.CoreV1().ConfigMaps(s.input.namespace).List(ctx, metav1.ListOptions{})
	if e != nil {
		return errOriginalSQLAccounts
	}
	for _, cm := range cms.Items {
		if raw := cm.Data["enrollment.json"]; raw != "" {
			// Even a malformed/unknown enrollment must be reconciled before
			// original account rollback; do not erase its SQL prerequisites.
			return errOriginalSQLAccounts
		}
	}
	return nil
}
func (s *originalSQLSession) ledger(ctx context.Context) ([]string, string, error) {
	rows, e := s.conn.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	if e != nil {
		return nil, "", errOriginalSQLAccounts
	}
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) != nil || len(names) >= 4096 {
			rows.Close()
			return nil, "", errOriginalSQLAccounts
		}
		names = append(names, n)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || !s.input.ledgerMatches(names) {
		return nil, "", errOriginalSQLAccounts
	}
	raw, _ := json.Marshal(names)
	h := hash(raw)
	if s.input.ledgerSHA != "" && h != s.input.ledgerSHA {
		return nil, "", errOriginalSQLAccounts
	}
	return names, h, nil
}
func (s *originalSQLSession) originalUsers(ctx context.Context, exclude map[string]bool) ([]originalSQLUser, error) {
	rows, e := s.conn.QueryContext(ctx, "SELECT User,Host,plugin,authentication_string,account_locked,ssl_type FROM mysql.user ORDER BY User,Host")
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	var users []originalSQLUser
	for rows.Next() {
		var u originalSQLUser
		if rows.Scan(&u.User, &u.Host, &u.Plugin, &u.Authentication, &u.Locked, &u.SSL) != nil || len(users) > 10000 {
			rows.Close()
			return nil, errOriginalSQLAccounts
		}
		if !exclude[u.User+"@"+u.Host] {
			users = append(users, u)
		}
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, errOriginalSQLAccounts
	}
	for j := range users {
		u := &users[j]
		r, e := s.conn.QueryContext(ctx, "SHOW GRANTS FOR "+originalSQLQuote(u.User)+"@"+originalSQLQuote(u.Host))
		if e != nil {
			return nil, errOriginalSQLAccounts
		}
		for r.Next() {
			var g string
			if r.Scan(&g) != nil || len(u.Grants) > 1000 {
				r.Close()
				return nil, errOriginalSQLAccounts
			}
			u.Grants = append(u.Grants, g)
		}
		if errors.Join(r.Err(), r.Close()) != nil {
			return nil, errOriginalSQLAccounts
		}
		sort.Strings(u.Grants)
	}
	return users, nil
}
func (s *originalSQLSession) tables(ctx context.Context) ([]string, error) {
	rows, e := s.conn.QueryContext(ctx, "SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME")
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	var names []string
	var forbidden []string
	if s.input.freshInstallation {
		forbidden = schemaobjects.RetainedOriginalLegacyControlTables()
	}
	for rows.Next() {
		var name, kind, engine string
		if rows.Scan(&name, &kind, &engine) != nil || kind != "BASE TABLE" || engine != "InnoDB" || !originalSQLName.MatchString(name) || len(names) > 1000 || slices.Contains(forbidden, name) {
			rows.Close()
			return nil, errOriginalSQLAccounts
		}
		names = append(names, name)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || len(names) == 0 {
		return nil, errOriginalSQLAccounts
	}
	return names, nil
}
func originalSQLPriv(table, verb string) originalSQLPrivilege {
	return originalSQLPrivilege{Kind: "table", Object: table, Verb: verb}
}
func originalSQLPrivilegesKey(p originalSQLPrivilege) string {
	return p.Kind + "/" + p.Database + "/" + p.Object + "/" + p.Column + "/" + p.Verb
}
func originalSQLSortPrivileges(v []originalSQLPrivilege) {
	sort.Slice(v, func(i, j int) bool { return originalSQLPrivilegesKey(v[i]) < originalSQLPrivilegesKey(v[j]) })
}
func (s *originalSQLSession) prepare(ctx context.Context) (originalSQLPlan, error) {
	var p originalSQLPlan
	if s.unused(ctx) != nil || s.retainedLegacyEmpty(ctx) != nil {
		return p, errOriginalSQLAccounts
	}
	id, name, e := s.admin(ctx, s.input.username)
	if e != nil {
		return p, e
	}
	_, ledger, e := s.ledger(ctx)
	if e != nil {
		return p, e
	}
	tables, e := s.tables(ctx)
	if e != nil {
		return p, e
	}
	users, e := s.originalUsers(ctx, map[string]bool{})
	if e != nil {
		return p, e
	}
	var secure, partial bool
	if s.conn.QueryRowContext(ctx, "SELECT @@require_secure_transport,@@partial_revokes").Scan(&secure, &partial) != nil {
		return p, errOriginalSQLAccounts
	}
	var persisted *string
	var persistedValue string
	e = s.conn.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='require_secure_transport'").Scan(&persistedValue)
	if e == nil {
		persisted = &persistedValue
	} else if !errors.Is(e, sql.ErrNoRows) {
		return p, errOriginalSQLAccounts
	}
	var routineCount int
	if s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()").Scan(&routineCount) != nil || routineCount != 0 {
		return p, errOriginalSQLAccounts
	}
	operation, e := originalSQLRandom(16)
	if e != nil {
		return p, e
	}
	p = originalSQLPlan{Version: s.input.operationVersion(), Operation: operation, ServerUUID: s.input.server, Database: s.input.database, Address: s.cfg.Addr, LedgerSHA256: ledger, KubeconfigSHA256: s.input.kubeSHA, AdminID: id, AdminUsername: name, Identity: s.identity, Secure: secure, PersistedSecure: persisted, OriginalUsers: users, Tables: tables, PartialRevokes: partial, TLS: s.material}
	present := map[string]bool{}
	for _, t := range tables {
		present[t] = true
	}
	allowed := map[string]bool{}
	for _, t := range schemaobjects.ExcludedControlTables() {
		allowed[t] = true
	}
	for _, t := range domain.BusinessCaptureTables() {
		allowed[t] = true
	}
	for _, t := range tables {
		if !allowed[t] {
			return originalSQLPlan{}, errOriginalSQLAccounts
		}
	}
	optional := map[string]bool{}
	for _, t := range schemaobjects.OptionalBusinessTables() {
		optional[t] = true
	}
	for _, t := range domain.BusinessCaptureTables() {
		if !present[t] && !optional[t] {
			return originalSQLPlan{}, errOriginalSQLAccounts
		}
	}
	for _, role := range []string{"installer", "business", "source", "runtime", "control_sql", "census"} {
		password, e := originalSQLRandom(32)
		if e != nil {
			return originalSQLPlan{}, e
		}
		a := originalSQLAccount{Role: role, User: "sbk_" + role + "_" + operation[:12], Host: s.input.host, Password: password, Locked: role == "census"}
		if role == "census" {
			a.Host = "localhost"
		}
		privileges, err := originalSQLRolePrivilegesForProfile(role, p.Database, a, present, s.input.allowAny, s.input.runtimeProfile)
		if err != nil {
			return originalSQLPlan{}, err
		}
		a.Privileges = privileges
		originalSQLSortPrivileges(a.Privileges)
		p.Accounts = append(p.Accounts, a)
	}
	definer := p.Accounts[len(p.Accounts)-1]
	projection, e := domain.SchemaCensusProjection(p.Database, definer.User+"@"+definer.Host, partial)
	if e != nil {
		return originalSQLPlan{}, errOriginalSQLAccounts
	}
	p.CensusDefinition = "BEGIN " + projection + "; END"
	p.Census = domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: definer.User + "@" + definer.Host, DefinitionSHA256: hash([]byte(p.CensusDefinition)), PartialRevokes: partial}
	return p, nil
}

func originalSQLRolePrivileges(role, database string, a originalSQLAccount, present map[string]bool, allowAny bool) ([]originalSQLPrivilege, error) {
	return originalSQLRolePrivilegesForProfile(role, database, a, present, allowAny, originalSQLHistoricalRuntimeProfile)
}
func originalSQLRolePrivilegesForProfile(role, database string, a originalSQLAccount, present map[string]bool, allowAny bool, profile string) ([]originalSQLPrivilege, error) {
	if originalSQLProfileOperationVersion(profile) == "" {
		return nil, errOriginalSQLAccounts
	}
	a.Privileges = nil
	if role != "installer" && role != "business" && role != "source" && role != "runtime" && role != "control_sql" && role != "census" {
		return nil, errOriginalSQLAccounts
	}
	if matrix, ok := originalSQLAuthorityGrants[role]; ok {
		for t, verbs := range matrix {
			if present[t] {
				for _, verb := range verbs {
					a.Privileges = append(a.Privileges, originalSQLPriv(t, verb))
				}
			}
		}
		// Only original authority consumers inspect retained empty control rows.
		// The business capture/source account never receives this permission.
		for _, table := range schemaobjects.RetainedOriginalLegacyControlTables() {
			if present[table] {
				a.Privileges = append(a.Privileges, originalSQLPriv(table, "SELECT"))
			}
		}
		if role == "installer" {
			for _, t := range domain.BusinessCaptureTables() {
				if present[t] {
					a.Privileges = append(a.Privileges, originalSQLPriv(t, "SELECT"))
				}
			}
		} else {
			a.Privileges = append(a.Privileges, originalSQLPriv("instances", "SELECT"))
			for _, c := range []string{"id", "username", "role", "is_active", "auth_provider"} {
				a.Privileges = append(a.Privileges, originalSQLPrivilege{Kind: "column", Object: "users", Column: c, Verb: "SELECT"})
			}
		}
	}
	if role == "source" {
		for _, t := range domain.BusinessCaptureTables() {
			if present[t] {
				a.Privileges = append(a.Privileges, originalSQLPriv(t, "SELECT"))
			}
		}
		a.Privileges = append(a.Privileges, originalSQLPrivilege{Kind: "global", Verb: "SHOW_ROUTINE"}, originalSQLPrivilege{Kind: "routine", Object: domain.SchemaCensusRoutine, Verb: "EXECUTE"})
	}
	if role == "control_sql" {
		a.Privileges = []originalSQLPrivilege{originalSQLPriv("system_backup_participants", "SELECT")}
	}
	if role == "runtime" {
		stmts, e := controller.ControllerGrantSQL(database, a.User, a.Host, allowAny)
		if profile == originalSQLPublicRuntimeProfile || originalSQLC1Selected(profile) {
			stmts, e = controller.ControlEvidenceGrantSQL(database, a.User, a.Host, allowAny, true, true, true)
		}
		if e != nil {
			return nil, errOriginalSQLAccounts
		}
		pattern := regexp.MustCompile("^GRANT ([A-Z, ]+) ON `[^`]+`\\.`([^`]+)` TO ")
		for _, stmt := range stmts {
			m := pattern.FindStringSubmatch(stmt)
			if len(m) != 3 || !present[m[2]] {
				return nil, errOriginalSQLAccounts
			}
			for _, verb := range strings.Split(m[1], ", ") {
				a.Privileges = append(a.Privileges, originalSQLPriv(m[2], verb))
			}
		}
	}
	if role == "runtime" && profile == originalSQLMinIOMetadataProfile {
		for _, table := range []string{"system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs"} {
			if !present[table] {
				return nil, errOriginalSQLAccounts
			}
			a.Privileges = append(a.Privileges, originalSQLPriv(table, "SELECT"))
		}
		if !present["users"] {
			return nil, errOriginalSQLAccounts
		}
		for _, column := range []string{"id", "username", "role", "is_active", "auth_provider"} {
			a.Privileges = append(a.Privileges, originalSQLPrivilege{Kind: "column", Object: "users", Column: column, Verb: "SELECT"})
		}
	}

	if role == "census" {
		for _, verb := range []string{"SELECT", "SHOW VIEW", "TRIGGER", "EVENT"} {
			a.Privileges = append(a.Privileges, originalSQLPrivilege{Kind: "schema", Verb: verb})
		}
		a.Privileges = append(a.Privileges, originalSQLPrivilege{Kind: "global", Verb: "SHOW_ROUTINE"}, originalSQLPrivilege{Kind: "table", Database: "mysql", Object: "global_grants", Verb: "SELECT"}, originalSQLPrivilege{Kind: "table", Database: "mysql", Object: "role_edges", Verb: "SELECT"})
	}
	if originalSQLC1Selected(profile) {
		var err error
		a.Privileges, err = originalSQLC1RoleDelta(role, present, a.Privileges)
		if err != nil {
			return nil, err
		}
	}
	originalSQLSortPrivileges(a.Privileges)
	return a.Privileges, nil
}

func (s *originalSQLSession) checkPlan(ctx context.Context, p originalSQLPlan, unused bool) error {
	if version := s.input.operationVersion(); version == "" || p.Version != version || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(p.Operation) || p.ServerUUID != s.input.server || p.Database != s.input.database || p.Address != s.cfg.Addr || p.LedgerSHA256 != s.input.ledgerSHA || p.KubeconfigSHA256 != s.input.kubeSHA || !reflect.DeepEqual(p.Identity, s.identity) || p.TLS != s.material || len(p.Accounts) != 6 || p.Census.Validate() != nil {
		return errOriginalSQLAccounts
	}
	if s.identityCheck(ctx) != nil {
		return errOriginalSQLAccounts
	}
	if s.retainedLegacyEmpty(ctx) != nil {
		return errOriginalSQLAccounts
	}
	if _, _, e := s.ledger(ctx); e != nil {
		return e
	}
	tables, e := s.tables(ctx)
	if e != nil || !reflect.DeepEqual(tables, p.Tables) {
		return errOriginalSQLAccounts
	}
	id, name, e := s.admin(ctx, p.AdminUsername)
	if e != nil || id != p.AdminID || name != p.AdminUsername {
		return errOriginalSQLAccounts
	}
	excluded := map[string]bool{}
	present := map[string]bool{}
	for _, t := range p.Tables {
		present[t] = true
	}
	roles := []string{"installer", "business", "source", "runtime", "control_sql", "census"}
	for index, a := range p.Accounts {
		if a.Role != roles[index] || a.User != "sbk_"+a.Role+"_"+p.Operation[:12] || !originalSQLName.MatchString(a.User) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(a.Password) || a.Locked != (a.Role == "census") || (!originalSQLHost.MatchString(a.Host) && !(a.Host == "%" && s.input.allowAny)) || (a.Role == "census" && a.Host != "localhost") {
			return errOriginalSQLAccounts
		}
		want, err := originalSQLRolePrivilegesForProfile(a.Role, p.Database, a, present, s.input.allowAny, s.input.runtimeProfile)
		if err != nil || !reflect.DeepEqual(want, a.Privileges) {
			return errOriginalSQLAccounts
		}
		excluded[a.User+"@"+a.Host] = true
	}
	definer := p.Accounts[len(p.Accounts)-1]
	projection, err := domain.SchemaCensusProjection(p.Database, definer.User+"@"+definer.Host, p.PartialRevokes)
	if err != nil || p.CensusDefinition != "BEGIN "+projection+"; END" || p.Census.Definer != definer.User+"@"+definer.Host || p.Census.DefinitionSHA256 != hash([]byte(p.CensusDefinition)) || p.Census.PartialRevokes != p.PartialRevokes {
		return errOriginalSQLAccounts
	}
	var partial bool
	if s.conn.QueryRowContext(ctx, "SELECT @@partial_revokes").Scan(&partial) != nil || partial != p.PartialRevokes {
		return errOriginalSQLAccounts
	}

	originals, e := s.originalUsers(ctx, excluded)
	if e != nil {
		return errOriginalSQLAccounts
	}
	// A disconnected CREATE can leave MySQL's automatic root routine grant.
	// Only that exact new procedure and only exact automatic privileges are
	// tolerated for ownership recovery; final Verify requires original grants.
	if !reflect.DeepEqual(originals, p.OriginalUsers) {
		matches, err := s.routineMatches(ctx, p)
		if err != nil || !matches {
			return errOriginalSQLAccounts
		}
		for j := range originals {
			if originals[j].User == "root" {
				var clean []string
				for _, g := range originals[j].Grants {
					if !originalSQLCreatorGrant(g, p.Database) {
						clean = append(clean, g)
					}
				}
				originals[j].Grants = clean
			}
		}
		if !reflect.DeepEqual(originals, p.OriginalUsers) {
			return errOriginalSQLAccounts
		}
	}
	if unused && s.unused(ctx) != nil {
		return errOriginalSQLAccounts
	}
	return nil
}
func originalSQLGrant(p originalSQLPlan, a originalSQLAccount, v originalSQLPrivilege) string {
	db := v.Database
	if db == "" {
		db = p.Database
	}
	target := originalSQLIdentifier(db) + "." + originalSQLIdentifier(v.Object)
	priv := v.Verb
	switch v.Kind {
	case "global":
		target = "*.*"
	case "schema":
		if !p.PartialRevokes {
			db = strings.ReplaceAll(db, "_", `\_`)
		}
		target = originalSQLIdentifier(db) + ".*"
	case "routine":
		target = "PROCEDURE " + target
	case "column":
		priv += " (" + originalSQLIdentifier(v.Column) + ")"
	}
	return "GRANT " + priv + " ON " + target + " TO " + originalSQLAccountName(a)
}
func (s *originalSQLSession) owned(ctx context.Context, p originalSQLPlan, a originalSQLAccount) (bool, error) {
	var owner sql.NullString
	e := s.conn.QueryRowContext(ctx, "SELECT ATTRIBUTE->>'$.clawmanager_sql_bootstrap' FROM information_schema.USER_ATTRIBUTES WHERE USER=? AND HOST=?", a.User, a.Host).Scan(&owner)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil || !owner.Valid || owner.String != p.Operation+":"+a.Role {
		return false, errOriginalSQLAccounts
	}
	return true, nil
}
func (s *originalSQLSession) send(ctx context.Context, directory, label, statement string) error {
	if originalSQLMark(directory, "send-unknown", map[string]string{"step": label, "sql_sha256": hash([]byte(statement))}) != nil {
		return errOriginalSQLAccounts
	}
	if _, e := s.conn.ExecContext(ctx, statement); e != nil {
		return errOriginalSQLAccounts
	}
	return nil
}

// The root connection is already TLS verified and holds the account operation lock.
func (s *originalSQLSession) freshApplyTarget(ctx context.Context) (freshAppDatabase, error) {
	target, err := observeFreshAppDatabase(ctx, s.kube, FreshInstallationIdentityInputs{
		OriginalEnrollmentInputs: OriginalEnrollmentInputs{
			Namespace:             s.input.namespace,
			DatabaseTLSServerName: s.material.ServerName,
			DatabaseCA:            BootstrapSourceFilePin{SHA256: s.material.CASHA256},
		},
		AppDeployment:    s.input.appDeployment,
		AppDeploymentUID: s.input.appDeploymentUID,
		ExpectedDatabase: s.input.database,
	})
	if err != nil || target.Address != s.cfg.Addr || checkFreshDatabaseHostname(ctx, s.conn, target) != nil {
		return freshAppDatabase{}, errOriginalSQLAccounts
	}
	return target, nil
}

func (s *originalSQLSession) apply(ctx context.Context, p originalSQLPlan, directory string) error {
	if s.checkPlan(ctx, p, true) != nil {
		return errOriginalSQLAccounts
	}
	var appTarget freshAppDatabase
	if s.input.freshInstallation {
		var err error
		appTarget, err = s.freshApplyTarget(ctx)
		if err != nil {
			return err
		}
	}
	if originalSQLWrite(directory, "apply.sent.json", map[string]string{"operation": p.Operation, "state": "dispatch_intent_no_resend"}) != nil {
		return errOriginalSQLAccounts
	}
	for _, a := range p.Accounts {
		exists, e := s.owned(ctx, p, a)
		if e != nil || exists {
			return errOriginalSQLAccounts
		}
		locked := "LOCK"
		stmt := "CREATE USER " + originalSQLAccountName(a) + " IDENTIFIED BY " + originalSQLQuote(a.Password) + " REQUIRE SSL ACCOUNT " + locked + " ATTRIBUTE " + originalSQLQuote(`{"clawmanager_sql_bootstrap":"`+p.Operation+":"+a.Role+`"}`)
		if s.send(ctx, directory, "create_"+a.Role, stmt) != nil {
			return errOriginalSQLAccounts
		}
		for _, v := range a.Privileges {
			if v.Kind == "routine" {
				continue
			}
			if s.send(ctx, directory, "grant_"+a.Role, originalSQLGrant(p, a, v)) != nil {
				return errOriginalSQLAccounts
			}
		}
	}
	definer := p.Accounts[len(p.Accounts)-1]
	stmt := "CREATE DEFINER=" + originalSQLAccountName(definer) + " PROCEDURE " + originalSQLIdentifier(p.Database) + "." + originalSQLIdentifier(domain.SchemaCensusRoutine) + "() READS SQL DATA SQL SECURITY DEFINER " + p.CensusDefinition
	if s.send(ctx, directory, "create_exact_metadata_census", stmt) != nil {
		return errOriginalSQLAccounts
	}
	// MySQL may add automatic creator privileges to the original root when
	// creating a routine. Remove only this new exact routine's auto-grants;
	// no preexisting routine existed at Prepare and no original grant is reset.
	if s.clearCreatorRoutinePrivileges(ctx, p, directory) != nil {
		return errOriginalSQLAccounts
	}
	for _, a := range p.Accounts {
		for _, v := range a.Privileges {
			if v.Kind == "routine" {
				if s.send(ctx, directory, "grant_exact_source_census", originalSQLGrant(p, a, v)) != nil {
					return errOriginalSQLAccounts
				}
			}
		}
	}
	if s.input.freshInstallation {
		current, err := s.freshApplyTarget(ctx)
		if err != nil || current != appTarget {
			return errOriginalSQLAccounts
		}
	}
	if s.send(ctx, directory, "persist_require_secure_transport_on", "SET PERSIST require_secure_transport=ON") != nil {
		return errOriginalSQLAccounts
	}
	for _, a := range p.Accounts {
		if !a.Locked {
			if s.send(ctx, directory, "unlock_"+a.Role, "ALTER USER "+originalSQLAccountName(a)+" ACCOUNT UNLOCK") != nil {
				return errOriginalSQLAccounts
			}
		}
	}
	return s.verify(ctx, p, directory)
}
func (s *originalSQLSession) actualPrivileges(ctx context.Context, a originalSQLAccount) ([]originalSQLPrivilege, error) {
	grantee := originalSQLAccountName(a)
	var all []originalSQLPrivilege
	queries := []struct{ kind, query string }{
		{"global", "SELECT '', '', '', PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE<>'USAGE'"},
		{"schema", "SELECT TABLE_SCHEMA,'','',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=?"},
		{"table", "SELECT TABLE_SCHEMA,TABLE_NAME,'',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=?"},
		{"column", "SELECT TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=?"},
	}
	for _, q := range queries {
		rows, e := s.conn.QueryContext(ctx, q.query, grantee)
		if e != nil {
			return nil, errOriginalSQLAccounts
		}
		for rows.Next() {
			var v originalSQLPrivilege
			var grantable string
			v.Kind = q.kind
			if rows.Scan(&v.Database, &v.Object, &v.Column, &v.Verb, &grantable) != nil || grantable != "NO" || len(all) > 2000 {
				rows.Close()
				return nil, errOriginalSQLAccounts
			}
			all = append(all, v)
		}
		if errors.Join(rows.Err(), rows.Close()) != nil {
			return nil, errOriginalSQLAccounts
		}
	}
	rows, e := s.conn.QueryContext(ctx, "SELECT Db,Routine_name,Proc_priv,Routine_type FROM mysql.procs_priv WHERE User=? AND Host=?", a.User, a.Host)
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	for rows.Next() {
		var db, name, verbs, kind string
		if rows.Scan(&db, &name, &verbs, &kind) != nil || kind != "PROCEDURE" {
			rows.Close()
			return nil, errOriginalSQLAccounts
		}
		for _, verb := range strings.Split(verbs, ",") {
			all = append(all, originalSQLPrivilege{Kind: "routine", Database: db, Object: name, Verb: strings.ToUpper(verb)})
		}
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, errOriginalSQLAccounts
	}
	// Dynamic SHOW_ROUTINE is listed by mysql.global_grants rather than the
	// static USER_PRIVILEGES view on MySQL8; merge it, rejecting delegation.
	rows, e = s.conn.QueryContext(ctx, "SELECT PRIV,WITH_GRANT_OPTION FROM mysql.global_grants WHERE USER=? AND HOST=?", a.User, a.Host)
	if e != nil {
		return nil, errOriginalSQLAccounts
	}
	for rows.Next() {
		var verb, delegated string
		if rows.Scan(&verb, &delegated) != nil || delegated != "N" {
			rows.Close()
			return nil, errOriginalSQLAccounts
		}
		v := originalSQLPrivilege{Kind: "global", Verb: verb}
		found := false
		for _, old := range all {
			found = found || old == v
		}
		if !found {
			all = append(all, v)
		}
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, errOriginalSQLAccounts
	}
	var roles, proxies int
	if s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER=? AND TO_HOST=?", a.User, a.Host).Scan(&roles) != nil || roles != 0 || s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.proxies_priv WHERE User=? AND Host=?", a.User, a.Host).Scan(&proxies) != nil || proxies != 0 {
		return nil, errOriginalSQLAccounts
	}
	originalSQLSortPrivileges(all)
	return all, nil
}
func (s *originalSQLSession) routineMatches(ctx context.Context, p originalSQLPlan) (bool, error) {
	var body, definer, security, access string
	e := s.conn.QueryRowContext(ctx, "SELECT ROUTINE_DEFINITION,DEFINER,SECURITY_TYPE,SQL_DATA_ACCESS FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME=? AND ROUTINE_TYPE='PROCEDURE'", domain.SchemaCensusRoutine).Scan(&body, &definer, &security, &access)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil || body != p.CensusDefinition || hash([]byte(body)) != p.Census.DefinitionSHA256 || definer != p.Census.Definer || security != "DEFINER" || access != "READS SQL DATA" {
		return false, errOriginalSQLAccounts
	}
	return true, nil
}

type originalSQLVerifyError struct {
	Stage, Role string
	MySQLNumber uint16
}

func (e *originalSQLVerifyError) Error() string { return errOriginalSQLAccounts.Error() }
func (e *originalSQLVerifyError) Unwrap() error { return errOriginalSQLAccounts }

func originalSQLVerifyFailure(stage, role string, cause error) *originalSQLVerifyError {
	out := &originalSQLVerifyError{Stage: stage, Role: role}
	var mysqlError *mysql.MySQLError
	if errors.As(cause, &mysqlError) {
		out.MySQLNumber = mysqlError.Number
	}
	return out
}

func (s *originalSQLSession) verify(ctx context.Context, p originalSQLPlan, directory string) (err error) {
	stage, role := "verify_operation", ""
	defer func() {
		if err != nil {
			var detail *originalSQLVerifyError
			if !errors.As(err, &detail) {
				err = originalSQLVerifyFailure(stage, role, err)
			}
		}
	}()
	if s.checkPlan(ctx, p, false) != nil {
		return errOriginalSQLAccounts
	}
	excluded := map[string]bool{}
	for _, a := range p.Accounts {
		excluded[a.User+"@"+a.Host] = true
	}
	stage = "verify_original_users"
	originals, originalErr := s.originalUsers(ctx, excluded)
	if originalErr != nil || !reflect.DeepEqual(originals, p.OriginalUsers) {
		return errOriginalSQLAccounts
	}

	stage = "verify_secure_transport"
	var secure bool
	var persisted string
	if s.conn.QueryRowContext(ctx, "SELECT @@require_secure_transport").Scan(&secure) != nil || !secure || s.conn.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='require_secure_transport'").Scan(&persisted) != nil || (persisted != "ON" && persisted != "1") {
		return errOriginalSQLAccounts
	}
	stage = "verify_census_definition"
	matched, e := s.routineMatches(ctx, p)
	if e != nil || !matched {
		return errOriginalSQLAccounts
	}
	for _, a := range p.Accounts {
		stage, role = "verify_account_attributes", a.Role
		exists, e := s.owned(ctx, p, a)
		if e != nil || !exists {
			return errOriginalSQLAccounts
		}
		var ssl, locked string
		if s.conn.QueryRowContext(ctx, "SELECT ssl_type,account_locked FROM mysql.user WHERE User=? AND Host=?", a.User, a.Host).Scan(&ssl, &locked) != nil || ssl != "ANY" || (locked == "Y") != a.Locked {
			return errOriginalSQLAccounts
		}
		stage = "verify_account_privileges"
		actual, e := s.actualPrivileges(ctx, a)
		if e != nil {
			return e
		}
		expected := append([]originalSQLPrivilege{}, a.Privileges...)
		for j := range expected {
			if expected[j].Kind != "global" && expected[j].Database == "" {
				expected[j].Database = p.Database
			}
			if expected[j].Kind == "schema" && !p.PartialRevokes {
				expected[j].Database = strings.ReplaceAll(expected[j].Database, "_", `\_`)
			}
		}
		originalSQLSortPrivileges(expected)
		if !reflect.DeepEqual(actual, expected) {
			return errOriginalSQLAccounts
		}
		if a.Locked {
			continue
		}
		stage = "verify_account_login"
		cfg := s.cfg.Clone()
		cfg.User = a.User
		cfg.Passwd = a.Password
		connector, e := mysql.NewConnector(cfg)
		cfg.Passwd = ""
		if e != nil {
			return errOriginalSQLAccounts
		}
		db := sql.OpenDB(connector)
		e = func() error {
			defer db.Close()
			var user, uuid, name, version, role string
			if loginErr := db.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,CURRENT_ROLE()").Scan(&user, &uuid, &role); loginErr != nil {
				return loginErr
			}
			if user != a.User+"@"+a.Host || uuid != p.ServerUUID || role != "NONE" {
				return errOriginalSQLAccounts
			}
			stage = "verify_account_tls"
			if db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &version) != nil || version != "TLSv1.3" {
				return errOriginalSQLAccounts
			}
			if originalSQLC1Selected(s.input.runtimeProfile) {
				stage = "verify_c1_account_grants"
				if err := originalSQLC1OwnGrantProbe(ctx, db, p, a); err != nil {
					return err
				}
			}
			if a.Role == "runtime" {
				stage = "verify_runtime_grants"
				if s.input.runtimeProfile == originalSQLMinIOMetadataProfile {
					return (controller.SQLMinIOMetadataReadGrantProbe{DB: db, Schema: p.Database, User: a.User, Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx)
				}
				if s.input.runtimeProfile == originalSQLPublicRuntimeProfile || originalSQLC1Selected(s.input.runtimeProfile) {
					return (controller.SQLControlEvidenceGrantProbe{DB: db, Schema: p.Database, User: a.User, Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx)
				}
				return (controller.SQLControllerGrantProbe{DB: db, Schema: p.Database, User: a.User}).Check(ctx)
			}
			if a.Role == "source" {
				stage = "verify_source_grants"
				conn, e := db.Conn(ctx)
				if e != nil {
					return e
				}
				defer conn.Close()
				var grants []string
				r, e := conn.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
				if e != nil {
					return e
				}
				for r.Next() {
					var g string
					if r.Scan(&g) != nil {
						r.Close()
						return errOriginalSQLAccounts
					}
					grants = append(grants, g)
				}
				if errors.Join(r.Err(), r.Close()) != nil || domain.ValidateBusinessSourceGrants(p.Database, grants) != nil {
					return errOriginalSQLAccounts
				}
				stage = "verify_source_census"
				return domain.CheckBusinessSchemaCensus(ctx, conn, p.Census)
			}
			if a.Role == "installer" {
				stage = "verify_installer_read"
				var heads int
				var username, stored string
				if db.QueryRowContext(ctx, "SELECT username,password_hash FROM users WHERE id=?", p.AdminID).Scan(&username, &stored) != nil || username != p.AdminUsername || db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_installation_owner_heads").Scan(&heads) != nil {
					return errOriginalSQLAccounts
				}
				stored = ""
			}
			if a.Role == "business" {
				stage = "verify_business_read"
				var username string
				if db.QueryRowContext(ctx, "SELECT username FROM users WHERE id=?", p.AdminID).Scan(&username) != nil || username != p.AdminUsername {
					return errOriginalSQLAccounts
				}
			}
			return nil
		}()
		if e != nil {
			return e
		}
	}
	// Output failures remain unknown. Query may finish missing create-only
	// deliveries with the SAME stored passwords; it never dispatches SQL writes.
	stage, role = "verify_deliver_materials", ""
	for _, a := range p.Accounts {
		if a.Locked {
			continue
		}
		cfg := s.cfg.Clone()
		cfg.User = a.User
		cfg.Passwd = a.Password
		cfg.TLS = nil
		cfg.TLSConfig = ""
		dsn := []byte(cfg.FormatDSN())
		cfg.Passwd = ""
		e := originalSQLDeliver(directory, "mysql-"+a.Role+".dsn", dsn)
		clear(dsn)
		if e != nil {
			return e
		}
		cred, _ := json.Marshal(struct {
			Username string `json:"username"`
			Password []byte `json:"password"`
		}{a.User, []byte(a.Password)})
		e = originalSQLDeliver(directory, "mysql-"+a.Role+"-credential.json", cred)
		clear(cred)
		if e != nil {
			return e
		}
	}
	census, _ := json.Marshal(p.Census)
	if originalSQLDeliver(directory, "mysql-source-schema-census.json", census) != nil {
		return errOriginalSQLAccounts
	}
	if originalSQLDeliver(directory, "local-admin-username.txt", []byte(p.AdminUsername)) != nil {
		return errOriginalSQLAccounts
	}
	materials := map[string]any{"version": originalSQLMaterialsVersion(s.input.runtimeProfile), "server_uuid": p.ServerUUID, "database": p.Database, "local_admin_username": p.AdminUsername, "source_tls": p.TLS, "schema_census": p.Census, "runtime_profile": originalSQLProfileName(s.input.runtimeProfile), "configuration_enabled": false}
	files := map[string]BootstrapSourceFilePin{}
	for _, a := range p.Accounts {
		if a.Locked {
			continue
		}
		for _, name := range []string{"mysql-" + a.Role + ".dsn", "mysql-" + a.Role + "-credential.json"} {
			raw, e := ReadPrivateFile(filepath.Join(directory, name), 16384)
			if e != nil {
				return errOriginalSQLAccounts
			}
			files[name] = BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(raw)}
			clear(raw)
		}
	}
	for _, name := range []string{"mysql-source-schema-census.json", "local-admin-username.txt"} {
		raw, e := ReadPrivateFile(filepath.Join(directory, name), 65536)
		if e != nil {
			return errOriginalSQLAccounts
		}
		files[name] = BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(raw)}
		clear(raw)
	}
	materials["files"] = files
	publicRaw, e := json.Marshal(materials)
	if e != nil || originalSQLDeliver(directory, "sql-accounts-materials.public.json", publicRaw) != nil {
		return errOriginalSQLAccounts
	}
	return originalSQLMark(directory, "verified", map[string]any{"state": originalSQLStatePrefix(s.input.runtimeProfile) + "_finite_accounts_tls13_global_secure_and_source_census_verified", "operation": p.Operation, "server_uuid": p.ServerUUID, "local_admin_username": p.AdminUsername, "configuration_enabled": false})
}
func originalSQLDeliver(directory, name string, raw []byte) error {
	file := filepath.Join(directory, name)
	if _, e := os.Lstat(file); e == nil {
		before, readErr := ReadPrivateFile(file, int64(len(raw)+1))
		defer clear(before)
		if readErr == nil && bytes.Equal(before, raw) {
			return nil
		}
		return errOriginalSQLAccounts
	} else if !os.IsNotExist(e) {
		return errOriginalSQLAccounts
	}
	return originalSQLWriteBytes(directory, name, raw)
}
func (s *originalSQLSession) rollback(ctx context.Context, p originalSQLPlan, directory string) error {
	if s.checkPlan(ctx, p, true) != nil {
		return errOriginalSQLAccounts
	}
	if originalSQLMark(directory, "rollback-intent", map[string]string{"operation": p.Operation}) != nil {
		return errOriginalSQLAccounts
	}
	// All SQL sends are serialized by the SAME native lock. A partial rollback
	// can continue only after querying exact original ownership for each object.
	exists, e := s.routineMatches(ctx, p)
	if e != nil {
		return e
	}
	if exists {
		if s.send(ctx, directory, "drop_owned_exact_census", "DROP PROCEDURE "+originalSQLIdentifier(p.Database)+"."+originalSQLIdentifier(domain.SchemaCensusRoutine)) != nil {
			return errOriginalSQLAccounts
		}
	}
	for _, a := range p.Accounts {
		present, e := s.owned(ctx, p, a)
		if e != nil {
			return e
		}
		if present {
			if s.send(ctx, directory, "drop_owned_"+a.Role, "DROP USER "+originalSQLAccountName(a)) != nil {
				return errOriginalSQLAccounts
			}
		}
	}
	var current bool
	if s.conn.QueryRowContext(ctx, "SELECT @@require_secure_transport").Scan(&current) != nil {
		return errOriginalSQLAccounts
	}
	if current != p.Secure {
		value := "OFF"
		if p.Secure {
			value = "ON"
		}
		if s.send(ctx, directory, "restore_original_runtime_secure_transport", "SET GLOBAL require_secure_transport="+value) != nil {
			return errOriginalSQLAccounts
		}
	}
	var persistedNow string
	persistedErr := s.conn.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='require_secure_transport'").Scan(&persistedNow)
	if persistedErr != nil && !errors.Is(persistedErr, sql.ErrNoRows) {
		return errOriginalSQLAccounts
	}
	if p.PersistedSecure == nil && !errors.Is(persistedErr, sql.ErrNoRows) {
		if s.send(ctx, directory, "restore_original_absent_persisted_secure_transport", "RESET PERSIST IF EXISTS require_secure_transport") != nil {
			return errOriginalSQLAccounts
		}
	} else if p.PersistedSecure != nil && (persistedErr != nil || persistedNow != *p.PersistedSecure) {
		value := strings.ToUpper(*p.PersistedSecure)
		if value != "ON" && value != "OFF" && value != "0" && value != "1" {
			return errOriginalSQLAccounts
		}
		if s.send(ctx, directory, "restore_original_persisted_secure_transport", "SET PERSIST_ONLY require_secure_transport="+value) != nil {
			return errOriginalSQLAccounts
		}
	}
	original, e := s.originalUsers(ctx, map[string]bool{})
	if e != nil || !reflect.DeepEqual(original, p.OriginalUsers) {
		return errOriginalSQLAccounts
	}
	var actual bool
	if s.conn.QueryRowContext(ctx, "SELECT @@require_secure_transport").Scan(&actual) != nil || actual != p.Secure {
		return errOriginalSQLAccounts
	}
	var v string
	e = s.conn.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='require_secure_transport'").Scan(&v)
	if p.PersistedSecure == nil && !errors.Is(e, sql.ErrNoRows) || p.PersistedSecure != nil && (e != nil || v != *p.PersistedSecure) {
		return errOriginalSQLAccounts
	}
	return originalSQLMark(directory, "rollback-verified", map[string]string{"state": "original_accounts_grants_and_secure_transport_restored_no_business_schema_change", "operation": p.Operation})
}

// RunOriginalSQLAccounts is reached only through the existing same-version
// system-backup-original-enroll sql-accounts subcommand (no new image target).
func RunOriginalSQLAccounts(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-original-enroll sql-accounts", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var in originalSQLInputs
	mode := f.String("mode", "", "inspect, prepare, apply, query or rollback")
	for _, entry := range []struct {
		name   string
		target *string
	}{{"admin-dsn-file", &in.dsn}, {"admin-dsn-sha256", &in.dsnSHA}, {"source-tls-file", &in.tls}, {"source-tls-sha256", &in.tlsSHA}, {"kubeconfig-file", &in.kube}, {"kubeconfig-sha256", &in.kubeSHA}, {"namespace", &in.namespace}, {"namespace-uid", &in.nsUID}, {"cluster-uid", &in.clusterUID}, {"expected-server-uuid", &in.server}, {"database", &in.database}, {"expected-ledger-sha256", &in.ledgerSHA}, {"local-admin-password-file", &in.password}, {"local-admin-username", &in.username}, {"account-host", &in.host}, {"output-directory", &in.directory}, {"operation-file", &in.operationFile}, {"operation-sha256", &in.operationSHA}} {
		f.StringVar(entry.target, entry.name, "", "")
	}
	f.StringVar(&in.runtimeProfile, "runtime-profile", originalSQLHistoricalRuntimeProfile, "frozen controller profile; old operations retain original profile")
	f.BoolVar(&in.allowAny, "allow-wildcard-host", false, "")
	f.BoolVar(&in.freshInstallation, "fresh-installation", false, "require the exact current embedded migration ledger and no retained legacy tables")
	f.StringVar(&in.appDeployment, "app-deployment", "", "actual App Deployment for fresh apply")
	f.StringVar(&in.appDeploymentUID, "app-deployment-uid", "", "independently selected App Deployment UID for fresh apply")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 || in.operationVersion() == "" || in.dsn == "" || len(in.dsnSHA) != 64 || in.tls == "" || len(in.tlsSHA) != 64 || in.kube == "" || len(in.kubeSHA) != 64 || in.password == "" || in.directory == "" || (*mode != "inspect" && *mode != "prepare" && *mode != "apply" && *mode != "query" && *mode != "rollback") {
		return 2
	}
	if in.freshInstallation && *mode == "apply" {
		if in.appDeployment == "" || in.appDeploymentUID == "" {
			return 2
		}
	} else if in.appDeployment != "" || in.appDeploymentUID != "" {
		return 2
	}
	if *mode != "inspect" && len(in.ledgerSHA) != 64 {
		return 2
	}
	if *mode == "prepare" || *mode == "inspect" {
		if in.operationFile != "" || in.operationSHA != "" || (*mode == "prepare" && !originalSQLHost.MatchString(in.host) && !(in.host == "%" && in.allowAny)) {
			return 2
		}
		if !filepath.IsAbs(in.directory) || filepath.Clean(in.directory) != in.directory {
			return 2
		}
		parent := filepath.Dir(in.directory)
		resolved, e := filepath.EvalSymlinks(parent)
		if e != nil || resolved != parent || os.Mkdir(in.directory, 0700) != nil {
			return 1
		}
	} else if in.operationFile != filepath.Join(in.directory, "operation.json") || len(in.operationSHA) != 64 || privateDirectory(in.directory) != nil {
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	session, e := openOriginalSQLAccounts(bounded, in)
	if e != nil {
		return 1
	}
	defer session.close()
	var p originalSQLPlan
	if *mode == "inspect" {
		id, name, authErr := session.admin(bounded, in.username)
		if authErr != nil || id < 1 {
			return 1
		}
		ledger, pin, readErr := session.ledger(bounded)
		if readErr != nil {
			return 1
		}
		tables, readErr := session.tables(bounded)
		if readErr != nil {
			return 1
		}
		var secure bool
		if session.conn.QueryRowContext(bounded, "SELECT @@require_secure_transport").Scan(&secure) != nil {
			return 1
		}
		receipt := map[string]any{"state": originalSQLStatePrefix(in.runtimeProfile) + "_inventory_no_mutation", "server_uuid": in.server, "database": in.database, "ledger_rows": len(ledger), "ledger_sha256": pin, "ledger": ledger, "tables": tables, "local_admin_username": name, "require_secure_transport": secure, "tls_version": "TLSv1.3", "tls_server_name": session.material.ServerName}
		if originalSQLWrite(in.directory, "inventory.json", receipt) != nil || originalSQLWriteBytes(in.directory, "local-admin-username.txt", []byte(name)) != nil {
			return 3
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 3
		}
		return 0
	}
	if *mode == "prepare" {
		p, e = session.prepare(bounded)
		if e != nil {
			return 1
		}
		if originalSQLWrite(in.directory, "operation.json", p) != nil {
			return 3
		}
		publicAccounts := []map[string]any{}
		for _, a := range p.Accounts {
			grants := []string{}
			for _, v := range a.Privileges {
				grants = append(grants, originalSQLGrant(p, a, v))
			}
			publicAccounts = append(publicAccounts, map[string]any{"role": a.Role, "user": a.User, "host": a.Host, "locked": a.Locked, "grants": grants})
		}
		if originalSQLWrite(in.directory, "account-plan.public.json", map[string]any{"version": "original198-sql-account-review.v1", "runtime_profile": originalSQLProfileName(in.runtimeProfile), "operation": p.Operation, "server_uuid": p.ServerUUID, "database": p.Database, "ledger_sha256": p.LedgerSHA256, "tables": p.Tables, "local_admin_username": p.AdminUsername, "tls_server_name": p.TLS.ServerName, "original_require_secure_transport": p.Secure, "original_persisted_require_secure_transport": p.PersistedSecure, "accounts": publicAccounts}) != nil {
			return 3
		}
		raw, e := ReadPrivateFile(filepath.Join(in.directory, "operation.json"), 262144)
		if e != nil {
			return 3
		}
		pin := hash(raw)
		clear(raw)
		if json.NewEncoder(out).Encode(map[string]any{"state": originalSQLStatePrefix(in.runtimeProfile) + "_prepared_no_sql_mutation", "operation_file": filepath.Join(in.directory, "operation.json"), "operation_sha256": pin, "local_admin_username": p.AdminUsername, "server_uuid": p.ServerUUID, "schema_census": p.Census, "account_count": len(p.Accounts), "runtime_profile": originalSQLProfileName(in.runtimeProfile)}) != nil {
			return 3
		}
		return 0
	}
	raw, e := originalSQLBytes(in.operationFile, in.operationSHA, 262144)
	if e != nil {
		return 1
	}
	defer clear(raw)
	if originalSQLJSON(raw, &p) != nil {
		return 1
	}
	queryState := ""
	switch *mode {
	case "apply":
		e = session.apply(bounded, p, in.directory)
	case "query":
		var restored bool
		restored, e = session.observeQuery(bounded, p, in.directory)
		if e == nil && !restored {
			e = session.verify(bounded, p, in.directory)
			queryState = "desired_actual_accounts_verified"
		} else if e == nil {
			queryState = "original_state_no_owned_changes_remaining"
		}
	case "rollback":
		e = session.rollback(bounded, p, in.directory)
	}
	if e != nil {
		failure := map[string]any{"mode": *mode, "operation": p.Operation}
		var detail *originalSQLVerifyError
		if errors.As(e, &detail) {
			failure["stage"] = detail.Stage
			if detail.Role != "" {
				failure["role"] = detail.Role
			}
			if detail.MySQLNumber != 0 {
				failure["mysql_number"] = detail.MySQLNumber
			}
		}
		_ = originalSQLMark(in.directory, "not-confirmed", failure)
		return 3
	}
	state := originalSQLStatePrefix(in.runtimeProfile) + "_" + *mode + "_verified"
	if *mode == "query" {
		state = originalSQLStatePrefix(in.runtimeProfile) + "_query_" + queryState
	}
	if json.NewEncoder(out).Encode(map[string]any{"state": state, "operation": p.Operation, "local_admin_username": p.AdminUsername, "directory": in.directory, "runtime_profile": originalSQLProfileName(in.runtimeProfile), "configuration_enabled": false}) != nil {
		return 3
	}
	return 0
}

func originalSQLCreatorGrant(grant, database string) bool {
	pattern := regexp.MustCompile("^GRANT (ALTER ROUTINE, EXECUTE|EXECUTE, ALTER ROUTINE|ALTER ROUTINE|EXECUTE) ON PROCEDURE `" + regexp.QuoteMeta(database) + "`\\.`" + domain.SchemaCensusRoutine + "` TO (?:'root'|`root`)@(?:'[^']+'|`[^`]+`)$")
	return pattern.MatchString(grant)
}
func (s *originalSQLSession) clearCreatorRoutinePrivileges(ctx context.Context, p originalSQLPlan, directory string) error {
	var current string
	if s.conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&current) != nil {
		return errOriginalSQLAccounts
	}
	at := strings.LastIndexByte(current, '@')
	if at < 1 || current[:at] != "root" {
		return errOriginalSQLAccounts
	}
	var privilege string
	e := s.conn.QueryRowContext(ctx, "SELECT Proc_priv FROM mysql.procs_priv WHERE User=? AND Host=? AND Db=? AND Routine_name=? AND Routine_type='PROCEDURE'", current[:at], current[at+1:], p.Database, domain.SchemaCensusRoutine).Scan(&privilege)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return errOriginalSQLAccounts
	}
	var verbs []string
	for _, v := range strings.Split(privilege, ",") {
		upper := strings.ToUpper(v)
		if upper != "EXECUTE" && upper != "ALTER ROUTINE" {
			return errOriginalSQLAccounts
		}
		verbs = append(verbs, upper)
	}
	if len(verbs) == 0 {
		return errOriginalSQLAccounts
	}
	return s.send(ctx, directory, "remove_new_census_creator_auto_grants", "REVOKE "+strings.Join(verbs, ", ")+" ON PROCEDURE "+originalSQLIdentifier(p.Database)+"."+originalSQLIdentifier(domain.SchemaCensusRoutine)+" FROM "+originalSQLQuote(current[:at])+"@"+originalSQLQuote(current[at+1:]))
}

func (s *originalSQLSession) retainedLegacyEmpty(ctx context.Context) error {
	if s.input.freshInstallation {
		// The table census rejects retained aliases outright for a fresh ledger.
		return nil
	}
	aliases := schemaobjects.RetainedOriginalLegacyControlTables()
	if len(aliases) != 35 {
		return errOriginalSQLAccounts
	}
	for _, table := range aliases {
		var count uint64
		if !originalSQLName.MatchString(table) || s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+originalSQLIdentifier(table)).Scan(&count) != nil || count != 0 {
			return errOriginalSQLAccounts
		}
	}
	return nil
}

// Only the native original producer uses this second-session reservation.
// General Installer callers keep their existing connection/transaction model.
func lockOriginalSQLAccountScope(ctx context.Context, db *sql.DB, server, database string) (func(), error) {
	_, release, err := lockOriginalSQLAccountSession(ctx, db, server, database)
	return release, err
}

// A fresh bootstrap runs the transaction on this exact session, so a later
// query cannot obtain the lock before the previous SQL session has ended.
func lockOriginalSQLAccountSession(ctx context.Context, db *sql.DB, server, database string) (*sql.Conn, func(), error) {
	if db == nil || server == "" || database == "" {
		return nil, nil, errOriginalSQLAccounts
	}
	db.SetMaxOpenConns(2)
	conn, e := db.Conn(ctx)
	if e != nil {
		return nil, nil, errOriginalSQLAccounts
	}
	release := func() { conn.Raw(func(any) error { return driver.ErrBadConn }); conn.Close() }
	var actualServer, actualDatabase string
	if conn.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&actualServer, &actualDatabase) != nil || actualServer != server || actualDatabase != database {
		release()
		return nil, nil, errOriginalSQLAccounts
	}
	var held int
	lock := "sbk-sql-accounts-" + hash([]byte(server + "/" + database))[:40]
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,0)", lock).Scan(&held) != nil || held != 1 {
		release()
		return nil, nil, errOriginalSQLAccounts
	}
	return conn, release, nil
}

// Query emits actual partial native state, not just a success boolean. It can
// resolve an unknown rollback as well as an unknown complete Apply, and never
// sends account/global/routine SQL. Native GET_LOCK excludes late old sends.
func (s *originalSQLSession) observeQuery(ctx context.Context, p originalSQLPlan, directory string) (bool, error) {
	if s.checkPlan(ctx, p, false) != nil {
		return false, errOriginalSQLAccounts
	}
	var secure bool
	if s.conn.QueryRowContext(ctx, "SELECT @@require_secure_transport").Scan(&secure) != nil {
		return false, errOriginalSQLAccounts
	}
	var persisted *string
	var value string
	e := s.conn.QueryRowContext(ctx, "SELECT VARIABLE_VALUE FROM performance_schema.persisted_variables WHERE VARIABLE_NAME='require_secure_transport'").Scan(&value)
	if e == nil {
		persisted = &value
	} else if !errors.Is(e, sql.ErrNoRows) {
		return false, errOriginalSQLAccounts
	}
	routine, e := s.routineMatches(ctx, p)
	if e != nil {
		return false, e
	}
	accounts := []map[string]any{}
	owned := 0
	for _, a := range p.Accounts {
		exists, e := s.owned(ctx, p, a)
		if e != nil {
			return false, e
		}
		row := map[string]any{"role": a.Role, "user": a.User, "host": a.Host, "owned_exists": exists}
		if exists {
			owned++
			actual, e := s.actualPrivileges(ctx, a)
			if e != nil {
				return false, e
			}
			row["actual_privileges"] = actual
			var ssl, locked string
			if s.conn.QueryRowContext(ctx, "SELECT ssl_type,account_locked FROM mysql.user WHERE User=? AND Host=?", a.User, a.Host).Scan(&ssl, &locked) != nil {
				return false, errOriginalSQLAccounts
			}
			row["actual_ssl_type"] = ssl
			row["actual_locked"] = locked
		}
		accounts = append(accounts, row)
	}
	restored := owned == 0 && !routine && secure == p.Secure && reflect.DeepEqual(persisted, p.PersistedSecure)
	if restored {
		users, e := s.originalUsers(ctx, map[string]bool{})
		if e != nil || !reflect.DeepEqual(users, p.OriginalUsers) {
			return false, errOriginalSQLAccounts
		}
	}
	state := "actual_partial_or_complete_apply_requires_exact_verification"
	if restored {
		state = "actual_original_state_no_owned_changes_remaining"
	}
	e = originalSQLMark(directory, "native-query", map[string]any{"state": state, "operation": p.Operation, "require_secure_transport": secure, "persisted_require_secure_transport": persisted, "exact_owned_census_exists": routine, "accounts": accounts, "sql_mutations_sent": false})
	return restored, e
}
