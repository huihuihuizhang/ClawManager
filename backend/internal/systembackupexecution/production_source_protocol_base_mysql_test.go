package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	deployment "clawreef/internal/systembackupdeployment"
	permitdiag "clawreef/internal/systembackupkekadapter"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

// Independent taskless protocol fixture. It shares the real source-role/TLS/full-migration
// setup algorithm, but never calls the original 7-running/9-stopped fixture and
// creates no HTTP task/readiness/session/queue or native stopped witness.
func newTasklessProtocolBase(t *testing.T, scenario *sourceProtocolScenario) *dOriginalSixPartTask {
	options := dOriginalSixPartFixtureOptions{PublicationForward: true, CompleteNonDR: true}
	t.Helper()
	path := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires the separate task-owned SAN/TLS MySQL instance")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.ServerUUID == "" {
		t.Fatal("owned TLS MySQL fixture credentials unavailable")
	}
	clear(raw)
	ca, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("owned source CA")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "d-sixpart-" + run
	if err = mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	connection := mysql.NewConfig()
	connection.User, connection.Passwd, connection.Net, connection.Addr = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	connection.ParseTime, connection.Loc, connection.TLSConfig = true, time.UTC, tlsName
	connection.Params = map[string]string{"time_zone": "'+00:00'"}
	connection.Timeout, connection.ReadTimeout, connection.WriteTimeout = 5*time.Second, 30*time.Second, 30*time.Second
	credential.Password = ""
	admin, err := sql.Open("mysql", connection.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	f := &dOriginalSixPartTask{database: "ad_d_src_" + run, directory: t.TempDir(), captureDescription: options.CaptureDescription}
	if !scenario.empty {
		f.createOriginalPayloads(t)
	}
	ctx := context.Background()
	var actualServer string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualServer) != nil || actualServer != credential.ServerUUID {
		t.Fatal("owned SQL server identity before schema creation")
	}
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+f.database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal("owned original task schema", err)
	}
	t.Cleanup(func() {
		var observedServer string
		if admin.QueryRow("SELECT @@server_uuid").Scan(&observedServer) != nil || observedServer != credential.ServerUUID {
			t.Error("refusing cleanup on changed SQL server")
			return
		}
		if _, err := admin.Exec("DROP DATABASE `" + f.database + "`"); err != nil {
			t.Error(err)
		}
	})
	connection.DBName = f.database
	f.db, err = sql.Open("mysql", connection.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	if f.db.QueryRow("SELECT @@server_uuid").Scan(&f.server) != nil || f.server != credential.ServerUUID {
		t.Fatal("owned TLS MySQL original identity mismatch")
	}
	var cipher string
	if f.db.QueryRow("SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("actual SQL session has no TLS cipher")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	migrate, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err = appdb.ApplyPinnedMigrations(migrate, f.db, appdb.MigrationTarget{ServerUUID: f.server, Database: f.database, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal("original full migration runner", err)
	}
	// Full migrations create a default login/quota and Skill tags. Establish
	// this test-owned empty source BEFORE declaring/signing the independent
	// scenario; never filter those rows out of an observed source inventory.
	prepareSourceProtocolOriginalCollections(ctx, t, f)
	installation := "installation_d_six_" + run
	f.profile = deployment.ExecutionProfile{InstallationID: installation, Revision: "d-original-six-r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local-protocol-fixture", RestoreTargetRef: "isolated-original-target", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileSHA, err := f.profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rbac, _ := json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": "d-six-rbac-v1", "installation_id": installation, "bindings": []any{map[string]any{"actor_id": "42", "subject": "user:42", "role": "operator"}}})
	example, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Request struct {
			Config map[string]any `json:"config"`
		} `json:"config_update_request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(example))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		t.Fatal("original config example")
	}
	values := document.Request.Config
	if options.PublicationTarget != nil {
		if err := prepareDOriginalPublicationReferences(values, *options.PublicationTarget); err != nil {
			t.Fatal("actual original artifact references before config/task admission", err)
		}
	}
	// Independent, fixed LOCAL owner policy declared before config admission or
	// any source metadata/UID observation. Counts are never supplied here.
	policyVersion := "original-local-secret-policy-r1"
	policyRaw, err := ce.Canonical(root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryVersion: policyVersion, RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{ID: "application-original", SecretName: "original", Required: !scenario.empty, ExpectedType: "Opaque", Purpose: "application_secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.secretPolicyFile, f.secretPolicyVersion, f.secretPolicySHA = filepath.Join(f.directory, "original-owner-secret-policy.json"), policyVersion, hash(policyRaw)
	if err = os.WriteFile(f.secretPolicyFile, policyRaw, 0600); err != nil {
		t.Fatal(err)
	}
	values["enabled"] = true
	values["capacity"].(map[string]any)["control_metadata_capacity_bytes"] = json.Number("1073741824")
	for _, entry := range values["registries"].([]any) {
		registry := entry.(map[string]any)
		if registry["registry_kind"] == "rbac_bindings" {
			registry["version"], registry["sha256"] = "d-six-rbac-v1", hash(rbac)
		}
		if registry["registry_kind"] == "secret_allowlist" {
			registry["version"], registry["sha256"] = f.secretPolicyVersion, f.secretPolicySHA
		}
	}
	if options.BeforeOriginalConfig != nil {
		if err = options.BeforeOriginalConfig(ctx, t, f, values); err != nil {
			t.Fatal("explicit new original config before admission", err)
		}
	}
	f.config, _ = json.Marshal(values)
	flat := map[string]any{"origin_installation_id": installation, "version": 1, "config_sha256": hash(f.config), "config_size_bytes": len(f.config), "canonical_config_json": f.config, "created_by": "1", "change_reason": "named local original six-part task fixture"}
	for _, name := range []string{"enabled", "alert_profile", "minimum_recovery_points"} {
		flat[name] = values[name]
	}
	for _, group := range []string{"durations", "capacity", "concurrency", "preflight_limits"} {
		for name, value := range values[group].(map[string]any) {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			flat[name] = value
		}
	}
	for _, entry := range values["registries"].([]any) {
		registry := entry.(map[string]any)
		kind := registry["registry_kind"].(string)
		flat[kind+"_registry_version"], flat[kind+"_registry_sha256"] = registry["version"], registry["sha256"]
	}
	for _, entry := range values["references"].([]any) {
		reference := entry.(map[string]any)
		kind := reference["purpose"].(string)
		flat[kind+"_identity_hash"], flat[kind+"_ref_version"] = reference["identity_hash"], reference["version"]
	}
	columns := make([]string, 0, len(flat))
	for name := range flat {
		columns = append(columns, name)
	}
	sort.Strings(columns)
	arguments := make([]any, 0, len(columns))
	for _, name := range columns {
		value := flat[name]
		if number, ok := value.(json.Number); ok {
			value = number.String()
		}
		arguments = append(arguments, value)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")+")", arguments...); err != nil {
		t.Fatal("original task config", err)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key) VALUES(?,1,TRUE,UTC_TIMESTAMP(6),'k8s-cluster')", installation); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_engine_bindings(scope,engine) VALUES('installation','v2')"); err != nil {
		t.Fatal(err)
	}
	scenario.seedSource(ctx, t, f)
	capacityFile := filepath.Join(f.directory, "capacity.json")
	var observed time.Time
	if f.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&observed) != nil {
		t.Fatal("SQL fixture clock")
	}
	capacity, _ := json.Marshal(security.CapacityReport{ServerUUID: f.server, Database: f.database, ObservedAt: observed, AllocatedBytes: 1 << 20, AvailableBytes: 4 << 30})
	if os.WriteFile(capacityFile, capacity, 0600) != nil {
		t.Fatal("named capacity input fixture")
	}
	now := time.Now().UTC().Add(-time.Second)
	// Only the controller gets the original finite controller table/verb role.
	user := "ad_d_six_ctl_" + run
	password := make([]byte, 24)
	rand.Read(password)
	pass := hex.EncodeToString(password)
	clear(password)
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	grants, err := c.ControlEvidenceGrantSQL(f.database, user, "127.0.0.1", false, true, true, options.PublicationForward)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if _, err = admin.Exec(grant); err != nil {
			t.Fatal("original finite controller grants", err)
		}
	}
	connection.User, connection.Passwd = user, pass
	// Match the dedicated public metadata constructor's driver transport.
	// All TLS/UTC/account pins, SQL locks and parameter values stay original.
	connection.InterpolateParams = true
	if options.ControlCommitACKLoss == nil && options.ControlBeforeQuery == nil && options.ControlAfterQuery == nil {
		f.control, err = sql.Open("mysql", connection.FormatDSN())
	} else {
		connector, connectorErr := mysql.NewConnector(connection)
		err = connectorErr
		if connectorErr == nil {
			var controlConnector driver.Connector = connector
			if options.ControlCommitACKLoss != nil {
				controlConnector = aCertificateWriteACKConnector{Connector: controlConnector, lose: options.ControlCommitACKLoss}
			}
			if options.ControlBeforeQuery != nil || options.ControlAfterQuery != nil {
				controlConnector = dOriginalGateQueryConnector{Connector: controlConnector, before: options.ControlBeforeQuery, after: options.ControlAfterQuery}
			}
			f.control = sql.OpenDB(controlConnector)
		}
	}
	connection.Passwd = ""
	pass = ""
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.control.Close() })
	if err = (c.SQLControlEvidenceGrantProbe{DB: f.control, Schema: f.database, User: user, Runtime: true, ProviderPermits: true, Publication: options.PublicationForward}).Check(ctx); err != nil {
		t.Fatal("original controller direct grants", err)
	}
	sourceUser := "ad_d_six_src_" + run
	secret := make([]byte, 24)
	rand.Read(secret)
	sourcePassword := hex.EncodeToString(secret)
	clear(secret)
	if _, err = admin.Exec("CREATE USER '" + sourceUser + "'@'127.0.0.1' IDENTIFIED BY '" + sourcePassword + "'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + sourceUser + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	for _, table := range domain.BusinessCaptureTables() {
		var present int
		if f.db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&present) != nil {
			t.Fatal("original source metadata")
		}
		if present == 1 {
			if _, err = admin.Exec("GRANT SELECT ON `" + f.database + "`.`" + table + "` TO '" + sourceUser + "'@'127.0.0.1'"); err != nil {
				t.Fatal(err)
			}
		}
	}
	definer, _, _, census, _ := installLockedSourceCensusFixture(t, f.db, f.database, sourceUser, nonce)
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + definer + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	f.sourceSpec = worker.DatabaseSpec{Address: connection.Addr, Name: f.database, ServerUUID: f.server, TLSServerName: credential.TLSServerName, RootCA: ca, MaxRows: 100000, MaxMemoryBytes: 32 << 20, SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &census}
	credentialRaw, _ := json.Marshal(metadataSourceCredential{Username: sourceUser, Password: []byte(sourcePassword)})
	f.sourceMount.CredentialFile = filepath.Join(f.directory, "original-sql-source-credential.json")
	f.sourceMount.CredentialSHA256 = hash(credentialRaw)
	if os.WriteFile(f.sourceMount.CredentialFile, credentialRaw, 0600) != nil {
		t.Fatal("private original source credential")
	}
	clear(credentialRaw)
	sourceCredential := worker.DatabaseCredential{Username: sourceUser, Password: []byte(sourcePassword)}
	workerSource, err := worker.OpenDatabase(&f.sourceSpec, &sourceCredential)
	clear(sourceCredential.Password)
	sourcePassword = ""
	if err != nil {
		t.Fatal("actual original SQL worker TLS opener", err)
	}
	t.Cleanup(func() { workerSource.Close() })
	var sourceAccount, sourceRole, sourceDatabase, sourceUUID string
	if workerSource.QueryRow("SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid").Scan(&sourceAccount, &sourceRole, &sourceDatabase, &sourceUUID) != nil || sourceAccount != sourceUser+"@127.0.0.1" || sourceRole != "NONE" || sourceDatabase != f.database || sourceUUID != f.server {
		t.Fatal("original SQL worker TLS identity")
	}
	if _, err = workerSource.Query("SELECT * FROM system_backup_v2_configs"); err == nil {
		t.Fatal("source collector could read control metadata")
	}
	observedSchema, err := domain.ObserveBusinessCaptureSchema(ctx, workerSource, census)
	if err != nil {
		t.Fatal("original complete source metadata", err)
	}
	f.sourceSpec.CaptureSchema = &observedSchema
	if err = (root.Gate{DB: f.db}).EnsureScope(ctx, "installation"); err != nil {
		t.Fatal(err)
	}
	if err = (c.SQLGateInitializer{DB: f.db}).Ensure(ctx, installation, c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	recordKey := make([]byte, 32)
	rand.Read(recordKey)
	defer clear(recordKey)
	if os.WriteFile(filepath.Join(f.directory, "record-v1"), recordKey, 0600) != nil {
		t.Fatal("record key")
	}
	core := runtimeDeploymentFixture(t)
	core.CaptureScope = "six-part"
	// Declare the full ten-part bound BEFORE core signing/Prepare. No frozen
	// hold or old key lease is extended when a shorter run fails closed.
	core.HoldSeconds = 300
	core.InstallationID, core.ControllerOwner, core.ApplicationScope = installation, "d-six-controller-"+run, "installation"
	core.SourceDatabase, core.SourceServerUUID = f.database, f.server
	core.SourceUser = sourceUser
	core.Workspace.MaxFiles, core.Workspace.MaxFileBytes, core.Workspace.MaxArchiveBytes, core.Workspace.MaxCompressedBytes = 100, 4<<20, 16<<20, 16<<20
	// Pin the original observed PVC/PV content before the core is signed.
	core.Security.Volumes[0].Volume, core.Security.Volumes[1].Volume = "workspace", "staging"
	core.Security.Volumes[0].SHA256 = kube.ContentHash(corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "source", Namespace: core.Namespace, UID: "source-uid"}})
	core.Security.Volumes[1].SHA256 = kube.ContentHash(corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "staging", Namespace: core.Namespace, UID: "stage-uid"}})
	core.CapacityFile = capacityFile
	core.RuntimeSources.Supported = append(core.RuntimeSources.Supported, b.AgentKind{Type: "hermes", Mode: "pro", Variant: "linux", OS: "linux"})
	core.StagingDirectory = filepath.Join(f.directory, "staging")
	if options.PublicationForward {
		configurePublicationStagingFixture(t, &core)
		core.StagingLocation.Container, core.StagingLocation.Volume = "platform", "staging"
	}
	if os.MkdirAll(core.StagingDirectory, 0700) != nil {
		t.Fatal("private task staging")
	}
	core.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(f.directory, "capture-materials.json")}
	core.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(f.directory, "formal-verifier.json")}
	core.ProfileFile, core.KeyDirectory = filepath.Join(f.directory, "profile.json"), f.directory
	core.ForwardGrant = GrantReference{Path: filepath.Join(f.directory, "forward.json"), PublicKey: base64.StdEncoding.EncodeToString(public)}
	core.RecoveryGrant = GrantReference{Path: filepath.Join(f.directory, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(public)}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(issuerPrivate) })
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "D original same-task worker issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	issuerPKCS8, err := x509.MarshalPKCS8PrivateKey(issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuerPKCS8)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(serverPrivate) })
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "D original control endpoint"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, issuer, serverPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPKCS8, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverPKCS8)
	core.IssuerCertificate, core.IssuerKey, core.IssuerSHA256 = filepath.Join(f.directory, "worker-issuer.pem"), filepath.Join(f.directory, "worker-issuer-key.pem"), hash(issuerDER)
	core.ServerCertificate, core.ServerKey = filepath.Join(f.directory, "control-server.pem"), filepath.Join(f.directory, "control-server-key.pem")
	for path, raw := range map[string][]byte{core.IssuerCertificate: issuerPEM, core.IssuerKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerPKCS8}), core.ServerCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), core.ServerKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPKCS8})} {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("original local control PKI")
		}
		clear(raw)
	}
	// Keep the issuer public bytes for the original worker issuer, independently
	// of the temporary serialized buffers cleared above.
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(issuer)
	controlServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.service == nil || f.service.Runtime == nil || f.service.Runtime.Control == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, permitCosts := permitdiag.WithProviderPermitTiming(r.Context())
		r = r.WithContext(ctx)
		defer func() {
			if snapshot := permitCosts.Snapshot(); len(snapshot) != 0 {
				// Numeric diagnostics with fixed labels only; no request or material.
				encoded, err := json.Marshal(snapshot)
				if err == nil {
					t.Logf("provider-permit-stage-timing DATA %s", encoded)
				}
			}
		}()
		r = r.WithContext(context.WithValue(r.Context(), originalControlTimingContextKey{}, &f.controlCosts))
		serveDOriginalControlWithAuthorizer(f, options, w, r)
	}))
	controlServer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverPrivate}}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: issuerRoots}
	controlServer.StartTLS()
	t.Cleanup(controlServer.Close)
	core.ControlURL = controlServer.URL
	if os.WriteFile(core.ProfileFile, profileRaw, 0600) != nil {
		t.Fatal("profile")
	}
	scenario.configureCore(t, f, &core)
	coreRaw, _ := json.Marshal(core)
	f.sealedCore = append([]byte(nil), coreRaw...)
	corePath := filepath.Join(f.directory, "core.json")
	if os.WriteFile(corePath, coreRaw, 0600) != nil {
		t.Fatal("core")
	}
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: installation, ControllerOwner: core.ControllerOwner, DatabaseAccount: user + "@127.0.0.1", ServerUUID: f.server, Database: f.database, ConfigVersion: 1, ConfigSHA256: hash(f.config), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(coreRaw), WorkerIssuerSHA256: hash(issuerDER), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(recordKey)}}}
	makeIdentity := func(record c.ExecutionGrant, path string) *c.PinnedExecutionIdentity {
		body, _ := json.Marshal(record)
		envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
		if os.WriteFile(path, envelope, 0600) != nil {
			t.Fatal("identity")
		}
		identity, err := c.NewPinnedExecutionIdentity(path, hash(envelope), f.directory, public)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	forward := makeIdentity(grant, core.ForwardGrant.Path)
	grant.Actions, grant.WorkerIssuerSHA256 = []string{"recover"}, ""
	recovery := makeIdentity(grant, core.RecoveryGrant.Path)
	f.service = &DeploymentService{ForwardEnabled: true, Config: core, ConfigPath: corePath, ConfigDigest: hash(coreRaw), Forward: forward, Recovery: recovery, profile: f.profile, profileHash: profileSHA, Source: workerSource, captureMaterials: &productionCaptureMaterials{Operations: map[string]productionCaptureOperation{"capture-database": {Request: worker.Request{Database: &f.sourceSpec}}}}}
	if err = f.service.checkSource(ctx); err != nil {
		t.Fatal("original service finite source/census admission", err)
	}
	gate := f.service.captureGate(f.control)
	stage, err := os.OpenRoot(core.StagingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage.Close() })
	client := scenario.installAPI(t, core)
	f.owner = &PublicJobOwner{Gate: gate, Identity: forward, Client: client, Dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme()), Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, TrustDomain: core.TrustDomain, Security: core.Security, Staging: stage, AllowKubeletStopWitness: true}
	f.owner.Issuer = control.IdentityIssuer{Certificate: issuer, Signer: issuerPrivate, ServerRoots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), TrustDomain: core.TrustDomain}
	f.owner.SealCustodyMaxBytes = core.SealCustodyMaxBytes
	f.service.tlsConfig = controlServer.TLS.Clone()
	// The original platform guard resolves its client through this same owner.
	// This component-only owner link is not NewPublicCapture composition or an
	// execution/readiness success declaration.
	f.service.Runtime = &PublicCapture{Owner: f.owner}
	if err = (root.Gate{DB: f.db}).RegisterParticipant(ctx, core.ApplicationScope, "application-mutations"); err != nil {
		t.Fatal("original application mutation participant registration", err)
	}
	profile, err := f.service.platformProfile(f.owner)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = f.service.attachRuntimeSources(f.owner, profile)
	if err != nil {
		t.Fatal("original Runtime composition", err)
	}
	profile = b.WithSkillCaptureInventory(b.WithTeamsSourceFacts(profile))
	var instances []b.InstanceIdentity
	var users []int
	tx, err := workerSource.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	userRows, err := tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if err != nil {
		tx.Rollback()
		t.Fatal("original source users", err)
	}
	for userRows.Next() {
		var id int
		if userRows.Scan(&id) != nil || len(users) >= 10000 {
			userRows.Close()
			tx.Rollback()
			t.Fatal("original source user projection")
		}
		users = append(users, id)
	}
	err = userRows.Err()
	userRows.Close()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	instances, err = domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	inventory := b.SourceInventory{Database: f.database, ServerUUID: f.server, Users: users, Instances: instances}
	inventory.TeamFacts, err = profile.ReadTeamFacts(ctx, tx, inventory)
	if err == nil {
		inventory.Skills, err = profile.ReadSkills(ctx, tx, inventory)
	}
	tx.Rollback()
	if err != nil || inventory.TeamFacts == nil || inventory.Skills == nil {
		t.Fatal("same original RR Teams/Skills source readers", err)
	}
	f.sourceInventory = inventory
	if err = f.service.validateRuntimeInventory(inventory); err != nil {
		t.Fatal("original runtime inventory binding", err)
	}
	if err = f.service.checkRuntimeWorkspace(ctx, client, instances); err != nil {
		t.Fatal("original runtime workspace aliases", err)
	}
	if err = f.service.RuntimeControl.Ready(ctx); err != nil {
		t.Fatal("original runtime SQL schema readiness", err)
	}
	if options.AfterOwnerReady != nil {
		if err := options.AfterOwnerReady(ctx, t, f); err != nil {
			t.Fatal("declared publication materials after original owner setup", err)
		}
		if err := checkDOriginalCoreUnchanged(f.service, f.sealedCore); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
