package install

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Native bootstrap uses the same static credential/TLS restrictions as the
// existing OpenConnections. No kubeconfig username, current-context name,
// certificate subject guess, exec plugin or impersonation supplies a user ID.
func openOriginalEnrollmentKubernetes(pin BootstrapSourceFilePin) (kubernetes.Interface, string, string, error) {
	fail := func() (kubernetes.Interface, string, string, error) { return nil, "", "", ErrInstall }
	raw, err := readBootstrapSourcePin(pin, 262144)
	if err != nil {
		return fail()
	}
	defer clear(raw)
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil || !validEndpoint(cfg.Host) || cfg.Insecure || cfg.Proxy != nil || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) != 0 || len(cfg.Impersonate.Extra) != 0 {
		return fail()
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if cfg.CAFile != "" {
		if len(cfg.CAData) != 0 {
			return fail()
		}
		cfg.CAData, err = ReadPrivateFile(cfg.CAFile, 65536)
		if err != nil {
			return fail()
		}
		cfg.CAFile = ""
	}
	if len(cfg.CAData) == 0 {
		return fail()
	}
	if cfg.BearerTokenFile != "" {
		if cfg.BearerToken != "" {
			return fail()
		}
		token, err := ReadPrivateFile(cfg.BearerTokenFile, 16384)
		if err != nil {
			return fail()
		}
		cfg.BearerToken = strings.TrimSpace(string(token))
		clear(token)
		cfg.BearerTokenFile = ""
	}
	if cfg.CertFile != "" {
		if len(cfg.CertData) != 0 {
			return fail()
		}
		cfg.CertData, err = ReadPrivateFile(cfg.CertFile, 65536)
		if err != nil {
			return fail()
		}
		cfg.CertFile = ""
	}
	if cfg.KeyFile != "" {
		if len(cfg.KeyData) != 0 {
			return fail()
		}
		cfg.KeyData, err = ReadPrivateFile(cfg.KeyFile, 65536)
		if err != nil {
			return fail()
		}
		cfg.KeyFile = ""
	}
	if (cfg.BearerToken == "") == (len(cfg.CertData) == 0 && len(cfg.KeyData) == 0) {
		return fail()
	}
	if len(cfg.CertData) != 0 || len(cfg.KeyData) != 0 {
		if _, err := tls.X509KeyPair(cfg.CertData, cfg.KeyData); err != nil {
			return fail()
		}
	}
	cfg.Timeout = 10 * time.Second
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fail()
	}
	return client, cfg.Host, hash(cfg.CAData), nil
}
