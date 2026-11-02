package install

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func consumerSameContext(a, b context.Context) bool {
	return !consumerNil(a) && !consumerNil(b) && reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}
func consumerNil(value any) bool {
	if value == nil {
		return true
	}
	switch v := reflect.ValueOf(value); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Same pinned static credential/TLS restrictions as the installer, without
// opening any SQL DSN, operator password or issuer private key.
func openCaptureConsumerKubernetes(plan Plan, path, expectedSHA string) (kubernetes.Interface, error) {
	if !validPlan(plan) || !digestPattern.MatchString(expectedSHA) {
		return nil, ErrInstall
	}
	raw, e := ReadPrivateFile(path, 262144)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	if hash(raw) != expectedSHA {
		return nil, ErrInstall
	}
	cfg, e := clientcmd.RESTConfigFromKubeConfig(raw)
	if e != nil || cfg.Host != plan.KubernetesAPI || cfg.Insecure || cfg.Proxy != nil || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Username != "" || cfg.Password != "" || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) != 0 || len(cfg.Impersonate.Extra) != 0 {
		return nil, ErrInstall
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if cfg.CAFile != "" {
		if len(cfg.CAData) != 0 {
			return nil, ErrInstall
		}
		cfg.CAData, e = ReadPrivateFile(cfg.CAFile, 65536)
		if e != nil {
			return nil, e
		}
		cfg.CAFile = ""
	}
	if len(cfg.CAData) == 0 || hash(cfg.CAData) != plan.KubernetesCASHA256 {
		return nil, ErrInstall
	}
	if cfg.BearerTokenFile != "" {
		if cfg.BearerToken != "" {
			return nil, ErrInstall
		}
		token, e := ReadPrivateFile(cfg.BearerTokenFile, 16384)
		if e != nil {
			return nil, e
		}
		cfg.BearerToken = strings.TrimSpace(string(token))
		clear(token)
		cfg.BearerTokenFile = ""
	}
	if cfg.CertFile != "" {
		if len(cfg.CertData) != 0 {
			return nil, ErrInstall
		}
		cfg.CertData, e = ReadPrivateFile(cfg.CertFile, 65536)
		if e != nil {
			return nil, e
		}
		cfg.CertFile = ""
	}
	if cfg.KeyFile != "" {
		if len(cfg.KeyData) != 0 {
			return nil, ErrInstall
		}
		cfg.KeyData, e = ReadPrivateFile(cfg.KeyFile, 65536)
		if e != nil {
			return nil, e
		}
		cfg.KeyFile = ""
	}
	if (cfg.BearerToken == "") == (len(cfg.CertData) == 0 && len(cfg.KeyData) == 0) {
		return nil, ErrInstall
	}
	if len(cfg.CertData) != 0 || len(cfg.KeyData) != 0 {
		if _, e := tls.X509KeyPair(cfg.CertData, cfg.KeyData); e != nil {
			return nil, ErrInstall
		}
	}
	cfg.Timeout = 10 * time.Second
	kube, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		return nil, ErrInstall
	}
	return kube, nil
}
