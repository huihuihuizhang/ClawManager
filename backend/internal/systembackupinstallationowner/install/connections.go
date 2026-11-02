package install

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func validEndpoint(endpoint string) bool {
	u, e := url.Parse(endpoint)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

// ReadPrivateFile never returns file-specific errors that could disclose a
// private path or credentials through the CLI. Symlinks are not input sources.
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || limit < 1 || limit > 262144 {
		return nil, ErrInstall
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return nil, ErrInstall
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, ErrInstall
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if e != nil || statErr != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(raw)) > limit {
		clear(raw)
		return nil, ErrInstall
	}
	return raw, nil
}

// OpenConnections uses only actual pinned TLS connections. It cannot obtain
// an operator identity from kubeconfig fields or SQL credentials alone.
// Authentication and permission checks happen on every Installer action.
func OpenConnections(p Plan, kubeconfigFile, kubeconfigSHA, dsnFile, databaseCAFile string) (*sql.DB, kubernetes.Interface, error) {
	if !validPlan(p) || !digestPattern.MatchString(kubeconfigSHA) {
		return nil, nil, ErrInstall
	}
	kubeRaw, e := ReadPrivateFile(kubeconfigFile, 262144)
	if e != nil {
		return nil, nil, e
	}
	defer clear(kubeRaw)
	if hash(kubeRaw) != kubeconfigSHA {
		return nil, nil, ErrInstall
	}
	cfg, e := clientcmd.RESTConfigFromKubeConfig(kubeRaw)
	if e != nil || cfg.Host != p.KubernetesAPI || cfg.Insecure || cfg.Proxy != nil || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) != 0 || len(cfg.Impersonate.Extra) != 0 {
		return nil, nil, ErrInstall
	}
	// A nil client-go Proxy would inherit HTTP(S)_PROXY from the environment.
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if cfg.CAFile != "" {
		if len(cfg.CAData) != 0 {
			return nil, nil, ErrInstall
		}
		cfg.CAData, e = ReadPrivateFile(cfg.CAFile, 65536)
		if e != nil {
			return nil, nil, e
		}
		cfg.CAFile = ""
	}
	if len(cfg.CAData) == 0 || hash(cfg.CAData) != p.KubernetesCASHA256 {
		return nil, nil, ErrInstall
	}
	if cfg.BearerTokenFile != "" {
		if cfg.BearerToken != "" {
			return nil, nil, ErrInstall
		}
		token, e := ReadPrivateFile(cfg.BearerTokenFile, 16384)
		if e != nil {
			return nil, nil, e
		}
		cfg.BearerToken = strings.TrimSpace(string(token))
		clear(token)
		cfg.BearerTokenFile = ""
	}
	if cfg.CertFile != "" {
		if len(cfg.CertData) != 0 {
			return nil, nil, ErrInstall
		}
		cfg.CertData, e = ReadPrivateFile(cfg.CertFile, 65536)
		if e != nil {
			return nil, nil, e
		}
		cfg.CertFile = ""
	}
	if cfg.KeyFile != "" {
		if len(cfg.KeyData) != 0 {
			return nil, nil, ErrInstall
		}
		cfg.KeyData, e = ReadPrivateFile(cfg.KeyFile, 65536)
		if e != nil {
			return nil, nil, e
		}
		cfg.KeyFile = ""
	}
	if (cfg.BearerToken == "") == (len(cfg.CertData) == 0 && len(cfg.KeyData) == 0) {
		return nil, nil, ErrInstall
	}
	if len(cfg.CertData) != 0 || len(cfg.KeyData) != 0 {
		if _, e := tls.X509KeyPair(cfg.CertData, cfg.KeyData); e != nil {
			return nil, nil, ErrInstall
		}
	}
	cfg.Timeout = 10 * time.Second
	kube, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		return nil, nil, ErrInstall
	}
	dsn, e := ReadPrivateFile(dsnFile, 16384)
	if e != nil {
		return nil, nil, e
	}
	defer clear(dsn)
	mc, e := mysql.ParseDSN(strings.TrimSpace(string(dsn)))
	if e != nil || mc.Net != "tcp" || mc.DBName != p.Target.Database || mc.MultiStatements || mc.AllowAllFiles || mc.AllowCleartextPasswords || mc.AllowOldPasswords || mc.AllowFallbackToPlaintext {
		return nil, nil, ErrInstall
	}
	ca, e := ReadPrivateFile(databaseCAFile, 65536)
	if e != nil {
		return nil, nil, e
	}
	roots := x509.NewCertPool()
	if hash(ca) != p.DatabaseCASHA256 || !roots.AppendCertsFromPEM(ca) {
		return nil, nil, ErrInstall
	}
	mc.TLSConfig = ""
	mc.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: p.DatabaseTLSServerName}
	mc.ParseTime = true
	mc.Loc = time.UTC
	mc.Timeout = 5 * time.Second
	mc.ReadTimeout = 10 * time.Second
	mc.WriteTimeout = 10 * time.Second
	if mc.Params == nil {
		mc.Params = map[string]string{}
	}
	mc.Params["time_zone"] = "'+00:00'"
	connector, e := mysql.NewConnector(mc)
	mc.Passwd = ""
	if e != nil {
		return nil, nil, ErrInstall
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, kube, nil
}
