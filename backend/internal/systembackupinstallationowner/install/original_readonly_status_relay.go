package install

import (
	"clawreef/internal/mysqltls"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"flag"
	"github.com/go-sql-driver/mysql"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type OriginalReadOnlyRelayInputs struct {
	Version                                                       string
	Material, Signature, CapacityConfig, CapacityDSN, CapacityTLS BootstrapSourceFilePin
}

// This pre-C1 listener performs actual authenticated read-only SQL status IO.
// It accepts no backup/worker relay writes and possesses neither admin password
// nor worker-issuer key nor execution grant. Full task relay remains the real
// DeploymentService handler after normal authorized runtime activation.
func RunOriginalReadOnlyStatusRelay(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-c1-native-inputs relay-serve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	v := map[string]*string{}
	for _, n := range []string{"plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "kubeconfig-file", "kubeconfig-sha256", "inputs-file", "inputs-sha256"} {
		v[n] = f.String(n, "", "")
	}
	pod := f.String("pod-name", os.Getenv("POD_NAME"), "")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 || *pod == "" {
		return 2
	}
	for _, p := range v {
		if *p == "" {
			return 2
		}
	}
	get := func(n string) string { return *v[n] }
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("plan-file"), get("plan-sha256")}, 262144)
	if e != nil {
		return 1
	}
	plan, e := DecodePlan(raw, get("plan-sha256"))
	if e != nil {
		return 1
	}
	pub, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("issuer-public-file"), get("issuer-public-sha256")}, 32)
	if e != nil || hash(pub) != plan.IssuerPublicKeySHA256 {
		return 1
	}
	inraw, e := readBootstrapSourcePin(BootstrapSourceFilePin{get("inputs-file"), get("inputs-sha256")}, 262144)
	var in OriginalReadOnlyRelayInputs
	if e != nil || decodeExact(inraw, &in) != nil || in.Version != "original-readonly-status-relay-inputs.v1" {
		return 1
	}
	material, e := readBootstrapSourcePin(in.Material, 262144)
	if e != nil {
		return 1
	}
	sig, e := readBootstrapSourcePin(in.Signature, 64)
	var m originalRelayPKIManifest
	if e != nil || !ed25519.Verify(pub, append([]byte(originalRelayPKIDomain), material...), sig) || decodeExact(material, &m) != nil || m.PlanSHA256 != get("plan-sha256") || !time.Now().Before(m.Until) || m.Version != "original-relay-pki-material.v1" {
		return 1
	}
	cRaw, e := readBootstrapSourcePin(in.CapacityConfig, 65536)
	var config sec.CapacityCollectorConfig
	if e != nil || decodeExact(cRaw, &config) != nil || config.Validate() != nil || config.ServerUUID != plan.Target.ServerUUID || config.Database != plan.Target.Database {
		return 1
	}
	tRaw, e := readBootstrapSourcePin(in.CapacityTLS, 65536)
	var mat mysqltls.Material
	if e != nil || decodeExact(tRaw, &mat) != nil || !mat.Selected() {
		return 1
	}
	dsn, e := readBootstrapSourcePin(in.CapacityDSN, 16384)
	if e != nil {
		return 1
	}
	defer clear(dsn)
	cfg, e := mysql.ParseDSN(strings.TrimSpace(string(dsn)))
	if e != nil || cfg.User != config.User || cfg.Net != "tcp" || cfg.DBName != config.Database || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || cfg.TLSConfig != "" || cfg.TLS != nil || mat.Apply(cfg) != nil {
		return 1
	}
	cfg.ParseTime = true
	cfg.Logger = silentDatabaseSourceLogger{}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return 1
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(2)
	kube, _, _, e := openOriginalEnrollmentKubernetes(BootstrapSourceFilePin{get("kubeconfig-file"), get("kubeconfig-sha256")})
	if e != nil {
		return 1
	}
	i, e := New(db, kube, raw, get("plan-sha256"), pub, get("issuer-public-sha256"))
	if e != nil {
		return 1
	}
	ca, e := readBootstrapSourcePin(m.Files["relay-ca.pem"], 65536)
	if e != nil {
		return 1
	}
	server, e := readBootstrapSourcePin(m.Files["relay-server.pem"], 65536)
	if e != nil {
		return 1
	}
	private, e := readBootstrapSourcePin(m.Files["relay-server-key.pem"], 16384)
	if e != nil {
		return 1
	}
	defer clear(private)
	pair, e := tls.X509KeyPair(server, private)
	if e != nil {
		return 1
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return 1
	}
	client, e := readBootstrapSourcePin(m.Files["relay-client.pem"], 65536)
	if e != nil {
		return 1
	}
	block, _ := pem.Decode(client)
	if block == nil {
		return 1
	}
	clientSHA := hash(block.Bytes)
	snapshot := func(call context.Context) (map[string]any, error) {
		if !time.Now().Before(m.Until) {
			return nil, ErrInstall
		}
		namespace, e := kube.CoreV1().Namespaces().Get(call, plan.Target.Namespace, metav1.GetOptions{})
		if e != nil || string(namespace.UID) != plan.Target.NamespaceUID || namespace.DeletionTimestamp != nil {
			return nil, ErrInstall
		}
		cluster, e := kube.CoreV1().Namespaces().Get(call, "kube-system", metav1.GetOptions{})
		if e != nil || string(cluster.UID) != plan.Target.ClusterID {
			return nil, ErrInstall
		}
		cm, e := kube.CoreV1().ConfigMaps(plan.Target.Namespace).Get(call, plan.EnrollmentName, metav1.GetOptions{})
		if e != nil || cm.DeletionTimestamp != nil || string(cm.UID) != m.EnrollmentConfigMapUID || cm.Immutable == nil || !*cm.Immutable || hash([]byte(cm.Data["enrollment.json"])) != m.EnrollmentSHA256 {
			return nil, ErrInstall
		}
		actor, e := i.originalPublicationActor(call, m.Source.ControllerDeployment, *pod)
		if e != nil || actor.ServiceAccountUID != m.Controller.ServiceAccountUID || actor.NamespaceUID != m.Controller.NamespaceUID {
			return nil, ErrInstall
		}
		dep, e := kube.AppsV1().Deployments(plan.Target.Namespace).Get(call, m.Source.ControllerDeployment, metav1.GetOptions{})
		if e != nil || string(dep.UID) != m.DeploymentUID {
			return nil, ErrInstall
		}
		svc, e := kube.CoreV1().Services(plan.Target.Namespace).Get(call, m.Source.Service, metav1.GetOptions{})
		if e != nil || string(svc.UID) != m.ServiceUID || svc.DeletionTimestamp != nil {
			return nil, ErrInstall
		}
		currentPod, e := kube.CoreV1().Pods(plan.Target.Namespace).Get(call, *pod, metav1.GetOptions{})
		if e != nil || string(currentPod.UID) != actor.PodUID || len(svc.Spec.Selector) == 0 {
			return nil, ErrInstall
		}
		for k, v := range svc.Spec.Selector {
			if currentPod.Labels[k] != v {
				return nil, ErrInstall
			}
		}
		conn, e := db.Conn(call)
		if e != nil {
			return nil, ErrInstall
		}
		defer conn.Close()
		var uuid, database, user, role, tlsName, tlsVersion string
		if conn.QueryRowContext(call, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE()").Scan(&uuid, &database, &user, &role) != nil || uuid != config.ServerUUID || database != config.Database || !strings.HasPrefix(user, config.User+"@") || role != "NONE" {
			return nil, ErrInstall
		}
		if conn.QueryRowContext(call, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&tlsName, &tlsVersion) != nil || tlsVersion != "TLSv1.3" {
			return nil, ErrInstall
		}
		rows, e := conn.QueryContext(call, "SHOW GRANTS")
		if e != nil {
			return nil, ErrInstall
		}
		var grants []string
		for rows.Next() {
			var g string
			if rows.Scan(&g) != nil {
				rows.Close()
				return nil, ErrInstall
			}
			grants = append(grants, g)
		}
		re := rows.Err()
		ce := rows.Close()
		if re != nil || ce != nil || sec.ValidateCapacityGrants(config, grants) != nil {
			return nil, ErrInstall
		}
		tx, e := conn.BeginTx(call, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if e != nil {
			return nil, ErrInstall
		}
		defer tx.Rollback()
		var heads, configs uint64
		var observed time.Time
		if tx.QueryRowContext(call, "SELECT UTC_TIMESTAMP(6)").Scan(&observed) != nil || tx.QueryRowContext(call, "SELECT COUNT(*) FROM system_backup_installation_owner_heads").Scan(&heads) != nil || tx.QueryRowContext(call, "SELECT COUNT(*) FROM system_backup_v2_configs").Scan(&configs) != nil || tx.Rollback() != nil {
			return nil, ErrInstall
		}
		return map[string]any{"version": "original-readonly-status-relay-status.v1", "server_uuid": uuid, "database": database, "pod_uid": actor.PodUID, "service_uid": m.ServiceUID, "owner_head_rows": heads, "config_rows": configs, "observed_at": observed, "task_mutations_enabled": false}, nil
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, e = snapshot(check)
	cancel()
	if e != nil {
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || hash(r.TLS.PeerCertificates[0].Raw) != clientSHA {
			w.WriteHeader(403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		call, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		data, e := snapshot(call)
		if e != nil {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(data)
		}
	})
	listener, e := net.Listen("tcp", ":9443")
	if e != nil {
		return 1
	}
	process, e := originalRelayReadNativeProcess(os.Getpid())
	if e != nil {
		listener.Close()
		return 1
	}
	actualPod, e := kube.CoreV1().Pods(plan.Target.Namespace).Get(ctx, *pod, metav1.GetOptions{})
	if e != nil {
		listener.Close()
		return 1
	}
	cid := ""
	for _, c := range actualPod.Status.ContainerStatuses {
		if c.Name == "installation-owner" && c.Ready && c.State.Running != nil {
			cid = c.ContainerID
		}
	}
	if cid == "" {
		listener.Close()
		return 1
	}
	record := originalRelayProcessRecord{Version: "original-readonly-relay-process.v1", PlanSHA256: get("plan-sha256"), PKIMaterialSHA256: in.Material.SHA256, ServeInputsSHA256: get("inputs-sha256"), Pod: *pod, PodUID: string(actualPod.UID), ContainerID: cid, ServiceUID: m.ServiceUID, ServerCertificateSHA256: m.Files["relay-server.pem"].SHA256, Process: process}
	recordRaw, e := canonical(record)
	if e != nil || writeNewFiles(filepath.Dir(in.Material.File), map[string][]byte{"readonly-relay.process.json": recordRaw}) != nil {
		listener.Close()
		return 1
	}
	srv := http.Server{Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	e = srv.Serve(tls.NewListener(listener, srv.TLSConfig))
	if e != http.ErrServerClosed {
		return 1
	}
	return 0
}
