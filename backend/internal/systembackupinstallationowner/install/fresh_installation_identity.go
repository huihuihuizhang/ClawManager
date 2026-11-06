package install

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	backup "clawreef/internal/systembackup"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type FreshInstallationIdentityInputs struct {
	OriginalEnrollmentInputs
	AppDeployment, AppDeploymentUID                               string
	Operation, NamespaceUID, ExpectedServerUUID, ExpectedDatabase string
	Apply                                                         bool
	UseAppDatabaseSecret                                          bool
}

type FreshInstallationIdentityReceipt struct {
	Version, State, Operation, Namespace, NamespaceUID, ClusterUID, ServerUUID, Database string
	AppDeploymentUID, MySQLDeploymentUID, MySQLServiceUID, MySQLPodUID                   string
	InstallationID                                                                       string `json:",omitempty"`
	Engine                                                                               string `json:",omitempty"`
}

var freshOperationID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var freshServerUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

const freshIdentityAbsent = "authenticated_fresh_installation_identity_absent"
const freshIdentityInitialized = "actual_fresh_installation_identity_initialized_unconfigured"

type freshKubeIdentity struct{ ClusterUID, Username, UID, GroupsSHA256 string }

func readFreshKubeIdentity(ctx context.Context, client kubernetes.Interface, input FreshInstallationIdentityInputs) (freshKubeIdentity, error) {
	var zero freshKubeIdentity
	ns, err := client.CoreV1().Namespaces().Get(ctx, input.Namespace, metav1.GetOptions{})
	if err != nil || ns.Name != input.Namespace || string(ns.UID) != input.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	cluster, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || cluster.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	self, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || self.Status.UserInfo.Username == "" || self.Status.UserInfo.Username == "system:anonymous" {
		return zero, ErrInstall
	}
	access, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: input.Namespace, Verb: "create", Resource: "configmaps", Name: "system-backup-owner"}}}, metav1.CreateOptions{})
	if err != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return zero, ErrInstall
	}
	objects, err := client.CoreV1().ConfigMaps(input.Namespace).List(ctx, metav1.ListOptions{Limit: 1000})
	if err != nil || objects.Continue != "" {
		return zero, ErrInstall
	}
	for _, item := range objects.Items {
		if item.Name == "system-backup-owner" || item.Data["enrollment.json"] != "" {
			return zero, ErrInstall
		}
	}
	groups := append([]string(nil), self.Status.UserInfo.Groups...)
	sort.Strings(groups)
	raw, err := canonical(groups)
	if err != nil {
		return zero, ErrInstall
	}
	return freshKubeIdentity{string(cluster.UID), self.Status.UserInfo.Username, self.Status.UserInfo.UID, hash(raw)}, nil
}

func freshInstallationID(input FreshInstallationIdentityInputs, kube freshKubeIdentity, target freshAppDatabase, adminID int64) (string, error) {
	// A separately retained random operation identifies a retry. Bind it to the
	// actual target and both authenticated principals without creating an owner.
	raw, err := canonical(struct {
		Version, Operation, Namespace, NamespaceUID, ServerUUID, Database, Admin, TLSServerName, TLSCASHA256 string
		AdminID                                                                                              int64
		Kube                                                                                                 freshKubeIdentity
		AppUID, MySQLUID, ServiceUID                                                                         string
	}{"fresh-backup-installation-identity.v1", input.Operation, input.Namespace, input.NamespaceUID,
		input.ExpectedServerUUID, input.ExpectedDatabase, input.LocalAdminUsername, input.DatabaseTLSServerName, input.DatabaseCA.SHA256, adminID, kube, target.AppUID, target.DBUID, target.ServiceUID})
	if err != nil {
		return "", ErrInstall
	}
	return "installation_" + hash(raw)[:32], nil
}

func readFreshSQLAdmin(ctx context.Context, tx *sql.Tx, expected originalEnrollmentDatabaseIdentity, username string, password []byte) (int64, error) {
	var actual originalEnrollmentDatabaseIdentity
	var secure bool
	var status, version string
	if tx.QueryRowContext(ctx, `SHOW SESSION STATUS LIKE 'Ssl_version'`).Scan(&status, &version) != nil || status != "Ssl_version" || version != "TLSv1.3" ||
		tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),CURRENT_USER(),@@require_secure_transport`).Scan(&actual.ServerUUID, &actual.Database, &actual.Account, &secure) != nil || !secure || actual != expected {
		return 0, ErrInstall
	}
	var id int64
	var name, passwordHash, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`, username).Scan(&id, &name, &passwordHash, &role, &active, &provider) != nil || id <= 0 || name != username || !active || role != "admin" || provider != "local" || bcrypt.CompareHashAndPassword([]byte(passwordHash), password) != nil {
		return 0, ErrInstall
	}
	return id, nil
}

type freshSQLIdentityState struct {
	InstallationID            string
	Present, ControllerUnseen bool
	ConfigVersion             uint64
	EnginePresent             bool
	EngineScope, Engine       string
	EngineVersion             uint64
}

func (s freshSQLIdentityState) classify(expected string) (string, error) {
	if s.EnginePresent && (s.EngineScope != "installation" || s.Engine != backup.LegacyEngine || s.EngineVersion != 1) {
		return "", ErrInstall
	}
	if !s.Present {
		return freshIdentityAbsent, nil
	}
	if s.InstallationID != expected || s.ConfigVersion != 0 || !s.ControllerUnseen || !s.EnginePresent {
		return "", ErrInstall
	}
	return freshIdentityInitialized, nil
}

func readFreshSQLInstallation(ctx context.Context, tx *sql.Tx, expected string) (string, error) {
	for _, table := range []string{
		"system_backup_config_versions", "system_backup_tasks", "system_backup_operations", "system_backup_v2_installation_state",
		"system_backup_v2_configs", "system_backup_v2_operations", "system_backup_v2_backups", "system_backup_v2_restore_drills",
		"system_backup_installation_owner_heads", "system_backup_installation_owner_grants",
	} {
		var present bool
		if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" LIMIT 1)").Scan(&present) != nil || present {
			return "", ErrInstall
		}
	}
	var s freshSQLIdentityState
	err := tx.QueryRowContext(ctx, `SELECT origin_installation_id,config_version,controller_seen_at IS NULL FROM system_backup_installation_state WHERE singleton_id=1`).Scan(&s.InstallationID, &s.ConfigVersion, &s.ControllerUnseen)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", ErrInstall
	}
	s.Present = err == nil
	var engines int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_engine_bindings`).Scan(&engines) != nil || engines > 1 {
		return "", ErrInstall
	}
	if engines == 1 {
		s.EnginePresent = true
		if tx.QueryRowContext(ctx, `SELECT scope,engine,row_version FROM system_backup_v2_engine_bindings`).Scan(&s.EngineScope, &s.Engine, &s.EngineVersion) != nil {
			return "", ErrInstall
		}
	}
	return s.classify(expected)
}

// InitializeFreshInstallationIdentity authenticates the fresh application and
// prepares only its unconfigured Store identity. Enrollment remains a separate
// operation. The SQL write is a single transaction guarded by the existing
// installation-account advisory lock and a serializable empty-state read.
func InitializeFreshInstallationIdentity(ctx context.Context, password []byte, input FreshInstallationIdentityInputs) (FreshInstallationIdentityReceipt, error) {
	var zero FreshInstallationIdentityReceipt
	if ctx == nil || ctx.Err() != nil || len(password) == 0 || len(password) > 1024 || input.Namespace == "" || input.NamespaceUID == "" || input.AppDeployment == "" || input.AppDeploymentUID == "" || input.ExpectedDatabase == "" || input.LocalAdminUsername == "" || !freshOperationID.MatchString(input.Operation) || !freshServerUUID.MatchString(input.ExpectedServerUUID) {
		return zero, ErrInstall
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Minute {
		return zero, ErrInstall
	}
	if input.UseAppDatabaseSecret == (input.BusinessDSN != (BootstrapSourceFilePin{})) {
		return zero, ErrInstall
	}
	k, _, _, err := openOriginalEnrollmentKubernetes(input.Kubeconfig)
	if err != nil {
		return zero, ErrInstall
	}
	kube, err := readFreshKubeIdentity(ctx, k, input)
	if err != nil {
		return zero, ErrInstall
	}
	target, err := observeFreshAppDatabase(ctx, k, input)
	if err != nil || checkFreshAppDatabaseDSN(input.InstallerDSN, target, false) != nil {
		return zero, ErrInstall
	}
	db, identity, err := openOriginalEnrollmentDatabase(ctx, input.InstallerDSN, input.DatabaseCA, input.DatabaseTLSServerName)
	if err != nil {
		return zero, ErrInstall
	}
	defer db.Close()
	if identity.ServerUUID != input.ExpectedServerUUID || identity.Database != input.ExpectedDatabase {
		return zero, ErrInstall
	}
	business, businessID, secret, err := openFreshBusinessDatabase(ctx, k, input, target)
	if err != nil {
		return zero, ErrInstall
	}
	defer business.Close()
	if businessID.ServerUUID != identity.ServerUUID || businessID.Database != identity.Database || !strings.HasPrefix(businessID.Account, target.User+"@") {
		return zero, ErrInstall
	}
	conn, release, err := lockOriginalSQLAccountSession(ctx, db, identity.ServerUUID, identity.Database)
	if err != nil {
		return zero, ErrInstall
	}
	defer release()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: !input.Apply})
	if err != nil {
		return zero, ErrInstall
	}
	defer tx.Rollback()
	admin, err := readFreshSQLAdmin(ctx, tx, identity, input.LocalAdminUsername, password)
	if err != nil {
		return zero, ErrInstall
	}
	if checkFreshDatabaseHostname(ctx, tx, target) != nil {
		return zero, ErrInstall
	}
	id, err := freshInstallationID(input, kube, target, admin)
	if err != nil {
		return zero, ErrInstall
	}
	state, err := readFreshSQLInstallation(ctx, tx, id)
	if err != nil {
		return zero, ErrInstall
	}
	current, err := readFreshKubeIdentity(ctx, k, input)
	if err != nil || current != kube {
		return zero, ErrInstall
	}
	currentTarget, err := observeFreshAppDatabase(ctx, k, input)
	if err != nil || currentTarget != target || !sameFreshAppDatabaseSecret(ctx, k, input, target, secret) {
		return zero, ErrInstall
	}
	write := input.Apply && state == freshIdentityAbsent
	if write {
		if (backup.Store{DB: db, InstallationID: id}).BootstrapTx(ctx, tx) != nil {
			return zero, ErrInstall
		}
		state, err = readFreshSQLInstallation(ctx, tx, id)
		if err != nil || state != freshIdentityInitialized {
			return zero, ErrInstall
		}
	}
	if tx.Commit() != nil {
		if write {
			return zero, ErrCommitUnknown
		}
		return zero, ErrInstall
	}
	if write {
		if observeFreshInstallationCommit(ctx, conn, identity, input, target, password, admin, id) != nil {
			return zero, ErrCommitUnknown
		}
		current, err = readFreshKubeIdentity(ctx, k, input)
		if err != nil || current != kube {
			return zero, ErrCommitUnknown
		}
		currentTarget, err = observeFreshAppDatabase(ctx, k, input)
		if err != nil || currentTarget != target || !sameFreshAppDatabaseSecret(ctx, k, input, target, secret) {
			return zero, ErrCommitUnknown
		}
	}
	receipt := FreshInstallationIdentityReceipt{Version: "fresh-backup-installation-identity-result.v1", State: state, Operation: input.Operation,
		Namespace: input.Namespace, NamespaceUID: input.NamespaceUID, ClusterUID: kube.ClusterUID, ServerUUID: identity.ServerUUID, Database: identity.Database,
		AppDeploymentUID: target.AppUID, MySQLDeploymentUID: target.DBUID, MySQLServiceUID: target.ServiceUID, MySQLPodUID: target.DBPodUID}
	if state == freshIdentityInitialized {
		receipt.InstallationID = id
		receipt.Engine = backup.LegacyEngine
	}
	return receipt, nil
}

func openFreshBusinessDatabase(ctx context.Context, client kubernetes.Interface, input FreshInstallationIdentityInputs, target freshAppDatabase) (*sql.DB, originalEnrollmentDatabaseIdentity, freshAppDatabaseSecret, error) {
	if !input.UseAppDatabaseSecret {
		if err := checkFreshAppDatabaseDSN(input.BusinessDSN, target, true); err != nil {
			return nil, originalEnrollmentDatabaseIdentity{}, freshAppDatabaseSecret{}, err
		}
		db, identity, err := openOriginalEnrollmentDatabase(ctx, input.BusinessDSN, input.DatabaseCA, input.DatabaseTLSServerName)
		return db, identity, freshAppDatabaseSecret{}, err
	}
	secret, password, err := readFreshAppDatabaseSecret(ctx, client, input.Namespace, target)
	if err != nil {
		return nil, originalEnrollmentDatabaseIdentity{}, freshAppDatabaseSecret{}, err
	}
	defer clear(password)
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = target.User, string(password)
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", target.Address, target.Database
	db, identity, err := openOriginalEnrollmentDatabaseConfig(ctx, cfg, input.DatabaseCA, input.DatabaseTLSServerName)
	return db, identity, secret, err
}

func sameFreshAppDatabaseSecret(ctx context.Context, client kubernetes.Interface, input FreshInstallationIdentityInputs, target freshAppDatabase, expected freshAppDatabaseSecret) bool {
	if !input.UseAppDatabaseSecret {
		return true
	}
	actual, password, err := readFreshAppDatabaseSecret(ctx, client, input.Namespace, target)
	clear(password)
	return err == nil && actual == expected
}

func observeFreshInstallationCommit(ctx context.Context, conn *sql.Conn, identity originalEnrollmentDatabaseIdentity, input FreshInstallationIdentityInputs, target freshAppDatabase, password []byte, admin int64, id string) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	user, err := readFreshSQLAdmin(ctx, tx, identity, input.LocalAdminUsername, password)
	if err != nil || user != admin || checkFreshDatabaseHostname(ctx, tx, target) != nil {
		return ErrInstall
	}
	state, err := readFreshSQLInstallation(ctx, tx, id)
	if err != nil || state != freshIdentityInitialized || tx.Commit() != nil {
		return ErrInstall
	}
	return nil
}
