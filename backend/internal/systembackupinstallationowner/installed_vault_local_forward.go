package systembackupinstallationowner

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"k8s.io/client-go/kubernetes"
)

// NewInstalledVaultDependencyObserverWithLocalForward changes only the TCP
// route of this installer observation. The original endpoint, TLS server name,
// CA, cluster identity and persisted configuration remain unchanged. The caller
// owns a bounded, authenticated kubectl forward to the selected provider Pod.
func NewInstalledVaultDependencyObserverWithLocalForward(cfg InstalledVaultDependencyConfig, kube kubernetes.Interface, namespace, namespaceUID, address string) (*InstalledVaultDependencyObserver, error) {
	if address != "" && cfg.IdentityMode != "original-owner-readonly" {
		return nil, ErrOwner
	}
	return newInstalledVaultObserverWithLocalForward(cfg, kube, namespace, namespaceUID, address)
}

// NewInstalledVaultMetadataObserverWithLocalForward is installer-only readback
// of the separately minted metadata identity. The route is not persisted into
// workload inputs and cannot turn an original administrator into that identity.
func NewInstalledVaultMetadataObserverWithLocalForward(cfg InstalledVaultDependencyConfig, kube kubernetes.Interface, namespace, namespaceUID, address string) (*InstalledVaultDependencyObserver, error) {
	if cfg.IdentityMode != "metadata-only" {
		return nil, ErrOwner
	}
	return newInstalledVaultObserverWithLocalForward(cfg, kube, namespace, namespaceUID, address)
}

func newInstalledVaultObserverWithLocalForward(cfg InstalledVaultDependencyConfig, kube kubernetes.Interface, namespace, namespaceUID, address string) (*InstalledVaultDependencyObserver, error) {
	o, err := NewInstalledVaultDependencyObserver(cfg, kube, namespace, namespaceUID)
	if err != nil || address == "" {
		return o, err
	}
	dial, err := installedVaultLocalForwardDial(cfg.Endpoint, address)
	if err != nil {
		o.Close()
		return nil, ErrOwner
	}
	o.transport.client.Transport.(*http.Transport).DialContext = dial
	return o, nil
}

func installedVaultLocalForwardDial(endpoint, address string) (func(context.Context, string, string) (net.Conn, error), error) {
	host, port, err := net.SplitHostPort(address)
	n, parseErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || parseErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return nil, ErrOwner
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, ErrOwner
	}
	p := u.Port()
	if p == "" {
		p = "443"
	}
	expected := net.JoinHostPort(u.Hostname(), p)
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || target != expected {
			return nil, ErrOwner
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	}, nil
}
