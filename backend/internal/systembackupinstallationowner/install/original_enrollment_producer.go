package install

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	owner "clawreef/internal/systembackupinstallationowner"
	"github.com/go-sql-driver/mysql"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Only existing native connection INPUTS and an explicit target namespace/admin
// are selected. No Plan, observed user/UID, database UUID, enrollment pin, issuer
// key or successful authentication DTO is accepted from the caller.
type OriginalEnrollmentInputs struct {
	Namespace, LocalAdminUsername, DatabaseTLSServerName string
	Kubeconfig, InstallerDSN, BusinessDSN, DatabaseCA    BootstrapSourceFilePin
	OutputDirectory                                      string
}

type OriginalEnrollmentProduced struct {
	Version, State                          string
	Plan, IssuerPublic, Enrollment, Receipt BootstrapSourceFilePin
	EnrollmentIdentity                      EnrollmentReceipt
}

// BootstrapOriginalEnrollment is a real native producer, not the old utility
// which merely loads preexisting plan/enrollment files. It does not install TLS
// or fabricate transport security: both actual database connections must already
// use the selected CA/SAN and the server must enforce secure transport. Generated
// private issuer material remains solely in the selected private directory.
func BootstrapOriginalEnrollment(ctx context.Context, password []byte, input OriginalEnrollmentInputs) (OriginalEnrollmentProduced, error) {
	var zero OriginalEnrollmentProduced
	if ctx == nil || ctx.Err() != nil || len(password) == 0 || len(password) > 1024 || input.Namespace == "" || input.LocalAdminUsername == "" || privateDirectory(input.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) || deadline.After(time.Now().Add(2*time.Minute)) {
		return zero, ErrInstall
	}
	k, api, apiCASHA, err := openOriginalEnrollmentKubernetes(input.Kubeconfig)
	if err != nil {
		return zero, ErrInstall
	}
	identity, err := k.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || identity == nil || identity.Status.UserInfo.Username == "" || identity.Status.UserInfo.Username == "system:anonymous" {
		return zero, ErrInstall
	}
	groups := append([]string(nil), identity.Status.UserInfo.Groups...)
	sort.Strings(groups)
	ns, err := k.CoreV1().Namespaces().Get(ctx, input.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	cluster, err := k.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || cluster.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	installerDB, installerID, err := openOriginalEnrollmentDatabase(ctx, input.InstallerDSN, input.DatabaseCA, input.DatabaseTLSServerName)
	if err != nil {
		return zero, ErrInstall
	}
	defer installerDB.Close()
	businessDB, businessID, err := openOriginalEnrollmentDatabase(ctx, input.BusinessDSN, input.DatabaseCA, input.DatabaseTLSServerName)
	if err != nil {
		return zero, ErrInstall
	}
	defer businessDB.Close()
	if installerID.ServerUUID != businessID.ServerUUID || installerID.Database != businessID.Database {
		return zero, ErrInstall
	}
	// The same native scope serializes this original producer with SQL account
	// rollback. Keep one session solely for the lock and one for real enrollment
	// reads; no absent future owner/gate table is used as a bootstrap mutex.
	releaseSQLScope, err := lockOriginalSQLAccountScope(ctx, installerDB, installerID.ServerUUID, installerID.Database)
	if err != nil {
		return zero, ErrInstall
	}
	defer releaseSQLScope()
	// Authentication is performed before generating a signing key or creating a
	// cluster enrollment. A SQL password alone does not supply the local admin.
	var userID int64
	var username, passwordHash, role, provider string
	var active bool
	if installerDB.QueryRowContext(ctx, `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`, input.LocalAdminUsername).Scan(&userID, &username, &passwordHash, &role, &active, &provider) != nil || userID <= 0 || username != input.LocalAdminUsername || !active || role != "admin" || provider != "local" || bcrypt.CompareHashAndPassword([]byte(passwordHash), password) != nil {
		return zero, ErrInstall
	}
	// The existing installation singleton and every historical config version
	// come from this same actual authenticated installer DB, never default/new
	// operator-selected config or a newly generated installation identifier.
	until, _ := ctx.Deadline()
	installed, err := readOriginalInstalledBackupConfiguration(ctx, installerDB, until)
	if err != nil {
		return zero, ErrInstall
	}
	defer installed.close()
	if installed.serverUUID != installerID.ServerUUID || installed.database != installerID.Database || installed.account != installerID.Account ||
		!strings.HasPrefix(installed.installation, "installation_") || len(installed.installation) <= len("installation_") {
		// Incompatible legacy identity requires explicit original-identity
		// migration/linkage; do not silently substitute a new installation.
		return zero, ErrInstall
	}
	recheckMaterial := func() error {
		for _, item := range []struct {
			pin   BootstrapSourceFilePin
			limit int64
		}{
			{input.Kubeconfig, 262144}, {input.InstallerDSN, 16384}, {input.BusinessDSN, 16384}, {input.DatabaseCA, 65536},
		} {
			body, e := readBootstrapSourcePin(item.pin, item.limit)
			clear(body)
			if e != nil {
				return ErrInstall
			}
		}
		return nil
	}
	if recheckMaterial() != nil || installed.recheck(ctx) != nil {
		return zero, ErrInstall
	}
	// This is only a FIRST enrollment producer. Never mint a parallel
	// installation identity over an existing original enrollment/head. A previous
	// unknown operation must instead be inspected using its retained exact Plan.
	var heads uint64
	if installerDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_installation_owner_heads`).Scan(&heads) != nil || heads != 0 {
		return zero, ErrInstall
	}
	existing, err := k.CoreV1().ConfigMaps(input.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return zero, ErrInstall
	}
	for _, cm := range existing.Items {
		if body := cm.Data["enrollment.json"]; body != "" {
			var original enrollmentDocument
			if json.Unmarshal([]byte(body), &original) == nil && original.SchemaVersion == EnrollmentVersion {
				return zero, ErrInstall
			}
		}
	}
	// Installation identity is the actual retained SQL singleton. The stable
	// per-original-namespace ConfigMap name makes native create-only enrollment
	// arbitrate concurrent first producers; random issuer/enrollment IDs cannot
	// create parallel objects after the earlier advisory empty checks.
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return zero, ErrInstall
	}
	suffix := hex.EncodeToString(id[:])
	issuer, err := GenerateIssuer(input.OutputDirectory)
	if err != nil {
		return zero, err
	}
	public, err := ReadPrivateFile(issuer.PublicFile, 32)
	if err != nil {
		return zero, ErrInstall
	}
	plan := Plan{SchemaVersion: PlanVersion, EnrollmentName: "system-backup-owner", EnrollmentID: "enrollment_" + suffix, IssuerID: "issuer_" + suffix, EnrollmentRevision: 1, Target: owner.Target{InstallationID: installed.installation, ServerUUID: installerID.ServerUUID, Database: installerID.Database, DatabaseAccount: businessID.Account, ClusterID: string(cluster.UID), Namespace: ns.Name, NamespaceUID: string(ns.UID)}, InstallerDatabaseAccount: installerID.Account, LocalAdminUsername: input.LocalAdminUsername, OwnerUsername: identity.Status.UserInfo.Username, OwnerUID: identity.Status.UserInfo.UID, OwnerGroups: groups, IssuerPublicKeySHA256: issuer.PublicKeySHA256, KubernetesAPI: api, KubernetesCASHA256: apiCASHA, DatabaseCASHA256: input.DatabaseCA.SHA256, DatabaseTLSServerName: input.DatabaseTLSServerName}
	if !validPlan(plan) {
		return zero, ErrInstall
	}
	raw, err := canonical(plan)
	if err != nil {
		return zero, ErrInstall
	}
	if writeNewFiles(input.OutputDirectory, map[string][]byte{"original-enrollment-plan.json": raw}) != nil {
		return zero, ErrInstall
	}
	// Reopen with the EXISTING production strict transport constructor and run
	// its complete real admin, database, SSR and enrollment permission checks.
	db, actualKube, err := OpenConnections(plan, input.Kubeconfig.File, input.Kubeconfig.SHA256, input.InstallerDSN.File, input.DatabaseCA.File)
	if err != nil {
		return zero, ErrInstall
	}
	defer db.Close()
	installer, err := New(db, actualKube, raw, hash(raw), public, issuer.PublicKeySHA256)
	if err != nil {
		return zero, ErrInstall
	}
	if recheckMaterial() != nil || installed.recheck(ctx) != nil {
		return zero, ErrInstall
	}
	receipt, err := installer.Enroll(ctx, password)
	if err != nil {
		return zero, err
	}
	if recheckMaterial() != nil || installed.recheck(ctx) != nil {
		// Native enrollment may already exist. Preserve the exact key/Plan and
		// return unknown, never retry a new identity or accept changed refs.
		return zero, ErrCommitUnknown
	}
	// Reread the actual immutable enrollment through the authenticated original
	// path. An output-file failure after enrollment is UNKNOWN and retains every
	// original key/plan; it never triggers another issuer or replacement object.
	operator, err := installer.authenticate(ctx, password)
	if err != nil || operator.authority(ctx, receipt.Pin) != nil {
		return zero, ErrCommitUnknown
	}
	pinRaw, err := canonical(receipt.Pin)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	receiptRaw, err := canonical(receipt)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	if writeNewFiles(input.OutputDirectory, map[string][]byte{"original-enrollment-pin.json": pinRaw, "original-enrollment-receipt.json": receiptRaw}) != nil {
		return zero, ErrCommitUnknown
	}
	after, err := actualKube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || after == nil || identity.Status.UserInfo.Username != after.Status.UserInfo.Username || identity.Status.UserInfo.UID != after.Status.UserInfo.UID {
		return zero, ErrCommitUnknown
	}
	afterGroups := append([]string(nil), after.Status.UserInfo.Groups...)
	sort.Strings(afterGroups)
	if !reflect.DeepEqual(groups, afterGroups) {
		return zero, ErrCommitUnknown
	}
	return OriginalEnrollmentProduced{Version: "original-native-enrollment-produced.v1", State: "actual_enrollment_only_not_controller_grant_or_page_backup", Plan: BootstrapSourceFilePin{File: filepath.Join(input.OutputDirectory, "original-enrollment-plan.json"), SHA256: hash(raw)}, IssuerPublic: BootstrapSourceFilePin{File: issuer.PublicFile, SHA256: issuer.PublicKeySHA256}, Enrollment: BootstrapSourceFilePin{File: filepath.Join(input.OutputDirectory, "original-enrollment-pin.json"), SHA256: hash(pinRaw)}, Receipt: BootstrapSourceFilePin{File: filepath.Join(input.OutputDirectory, "original-enrollment-receipt.json"), SHA256: hash(receiptRaw)}, EnrollmentIdentity: receipt}, nil
}

type originalEnrollmentDatabaseIdentity struct{ ServerUUID, Database, Account string }

func openOriginalEnrollmentDatabase(ctx context.Context, dsnPin, caPin BootstrapSourceFilePin, serverName string) (*sql.DB, originalEnrollmentDatabaseIdentity, error) {
	var zero originalEnrollmentDatabaseIdentity
	raw, err := readBootstrapSourcePin(dsnPin, 16384)
	if err != nil {
		return nil, zero, ErrInstall
	}
	defer clear(raw)
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, zero, ErrInstall
	}
	return openOriginalEnrollmentDatabaseConfig(ctx, cfg, caPin, serverName)
}

func openOriginalEnrollmentDatabaseConfig(ctx context.Context, cfg *mysql.Config, caPin BootstrapSourceFilePin, serverName string) (*sql.DB, originalEnrollmentDatabaseIdentity, error) {
	var zero originalEnrollmentDatabaseIdentity
	if cfg.Net != "tcp" || cfg.DBName == "" || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext {
		return nil, zero, ErrInstall
	}
	defer func() { cfg.Passwd = "" }()
	ca, err := readBootstrapSourcePin(caPin, 65536)
	if err != nil {
		return nil, zero, ErrInstall
	}
	clear(ca)
	material := mysqltls.Material{CAFile: caPin.File, CASHA256: caPin.SHA256, ServerName: serverName}
	if !material.Selected() || material.Apply(cfg) != nil {
		return nil, zero, ErrInstall
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, zero, ErrInstall
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, zero, ErrInstall
	}
	defer conn.Close()
	var identity originalEnrollmentDatabaseIdentity
	var secure bool
	var name, version string
	if conn.QueryRowContext(ctx, `SHOW SESSION STATUS LIKE 'Ssl_version'`).Scan(&name, &version) != nil || name != "Ssl_version" || version != "TLSv1.3" || conn.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),CURRENT_USER(),@@require_secure_transport`).Scan(&identity.ServerUUID, &identity.Database, &identity.Account, &secure) != nil || !secure || identity.ServerUUID == "" || identity.Database == "" || identity.Account == "" {
		db.Close()
		return nil, zero, ErrInstall
	}
	return db, identity, nil
}
