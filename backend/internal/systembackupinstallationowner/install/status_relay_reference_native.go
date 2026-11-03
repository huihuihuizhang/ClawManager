package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type statusRelayNative struct {
	identity       string
	started, until time.Time
}
type statusRelayHostFacts struct{ PodUID, PodRV, PodSpecSHA256, ContainerID, ImageID, ServiceUID, ServiceRV, EndpointRV, LeafSHA256, SPKISHA256 string }

func statusRelayHost(ctx context.Context, client kubernetes.Interface, target owner.Target, d StatusRelayReferenceDefinition) (statusRelayHostFacts, error) {
	var out statusRelayHostFacts
	if validateStatusRelayReference(d) != nil || observeBootstrapSourceController(ctx, client, target, d.Controller) != nil {
		return out, ErrInstall
	}
	pod, e := client.CoreV1().Pods(target.Namespace).Get(ctx, d.Controller.Pod, metav1.GetOptions{})
	if e != nil || pod.UID == "" || string(pod.UID) != d.Controller.PodUID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return out, ErrInstall
	}
	raw, e := json.Marshal(pod.Spec)
	if e != nil || len(raw) > 1<<20 || hash(raw) != d.PodSpecSHA256 {
		return out, ErrInstall
	}
	found := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != d.Container {
			continue
		}
		if found || !status.Ready || status.ContainerID == "" || status.ImageID != d.ContainerImageID || status.State.Running == nil {
			return out, ErrInstall
		}
		found = true
		out.ContainerID = status.ContainerID
		out.ImageID = status.ImageID
	}
	if !found {
		return out, ErrInstall
	}
	svc, e := client.CoreV1().Services(target.Namespace).Get(ctx, d.Service, metav1.GetOptions{})
	if e != nil || string(svc.UID) != d.ServiceUID || svc.DeletionTimestamp != nil || svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 {
		return out, ErrInstall
	}
	for key, value := range svc.Spec.Selector {
		if pod.Labels[key] != value {
			return out, ErrInstall
		}
	}
	u, e := url.Parse(d.Endpoint)
	if e != nil {
		return out, ErrInstall
	}
	if u.Hostname() != d.Service+"."+target.Namespace+".svc" && u.Hostname() != svc.Spec.ClusterIP {
		return out, ErrInstall
	}
	port := 443
	if u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
		if e != nil {
			return out, ErrInstall
		}
	}
	var selected *corev1.ServicePort
	for n := range svc.Spec.Ports {
		p := &svc.Spec.Ports[n]
		if p.Protocol == corev1.ProtocolTCP && int(p.Port) == port {
			if selected != nil {
				return out, ErrInstall
			}
			selected = p
		}
	}
	if selected == nil {
		return out, ErrInstall
	}
	endpoints, e := client.CoreV1().Endpoints(target.Namespace).Get(ctx, d.Service, metav1.GetOptions{})
	if e != nil || endpoints.DeletionTimestamp != nil || endpoints.UID == "" {
		return out, ErrInstall
	}
	joined := false
	for _, subset := range endpoints.Subsets {
		portFound := false
		for _, ep := range subset.Ports {
			if ep.Protocol == corev1.ProtocolTCP && ep.Name == selected.Name {
				portFound = true
			}
		}
		if !portFound {
			continue
		}
		for _, address := range subset.Addresses {
			if address.TargetRef != nil && address.TargetRef.Kind == "Pod" && string(address.TargetRef.UID) == d.Controller.PodUID && address.TargetRef.Name == pod.Name && address.IP == pod.Status.PodIP && address.IP != "" {
				joined = true
			}
		}
	}
	if !joined {
		return out, ErrInstall
	}
	out.PodUID, out.PodRV, out.PodSpecSHA256 = string(pod.UID), pod.ResourceVersion, d.PodSpecSHA256
	out.ServiceUID, out.ServiceRV, out.EndpointRV = string(svc.UID), svc.ResourceVersion, endpoints.ResourceVersion
	return out, nil
}

// Real TLS 1.3 mTLS handshake only: server certificate/private-key possession,
// independent CA/SAN and exact leaf/SPKI. No HTTP request, POST, task or Job.
func statusRelayTLS(ctx context.Context, d StatusRelayReferenceDefinition) (string, string, time.Time, error) {
	ca, e := readBootstrapSourcePin(d.CA, 65536)
	if e != nil {
		return "", "", time.Time{}, ErrInstall
	}
	certRaw, e := readBootstrapSourcePin(d.ClientCertificate, 65536)
	if e != nil {
		return "", "", time.Time{}, ErrInstall
	}
	keyRaw, e := readBootstrapSourcePin(d.ClientPrivateKey, 16384)
	defer clear(keyRaw)
	if e != nil {
		return "", "", time.Time{}, ErrInstall
	}
	cert, e := tls.X509KeyPair(certRaw, keyRaw)
	if e != nil || len(cert.Certificate) == 0 {
		return "", "", time.Time{}, ErrInstall
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	now := time.Now().UTC()
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return "", "", time.Time{}, ErrInstall
	}
	if leaf.IsCA {
		return "", "", time.Time{}, ErrInstall
	}
	clientUse := false
	for _, use := range leaf.ExtKeyUsage {
		clientUse = clientUse || use == x509.ExtKeyUsageClientAuth
	}
	for _, identity := range leaf.URIs {
		if strings.HasPrefix(identity.Path, "/backup/") {
			return "", "", time.Time{}, ErrInstall
		}
	}
	if !clientUse {
		return "", "", time.Time{}, ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return "", "", time.Time{}, ErrInstall
	}
	u, e := url.Parse(d.Endpoint)
	if e != nil {
		return "", "", time.Time{}, ErrInstall
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: u.Hostname(), Certificates: []tls.Certificate{cert}}}
	connection, e := dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if e != nil {
		return "", "", time.Time{}, ErrInstall
	}
	defer connection.Close()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return "", "", time.Time{}, ErrInstall
	}
	state := tlsConnection.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", "", time.Time{}, ErrInstall
	}
	server := state.PeerCertificates[0]
	spki, e := x509.MarshalPKIXPublicKey(server.PublicKey)
	if e != nil || hash(server.Raw) != d.ServerLeafSHA256 || hash(spki) != d.ServerSPKISHA256 || now.Before(server.NotBefore) || !time.Now().Before(server.NotAfter) || ctx.Err() != nil {
		return "", "", time.Time{}, ErrInstall
	}
	until := server.NotAfter
	if leaf.NotAfter.Before(until) {
		until = leaf.NotAfter
	}
	return hash(server.Raw), hash(spki), until, nil
}

func observeStatusRelayReference(ctx context.Context, client kubernetes.Interface, target owner.Target, d StatusRelayReferenceDefinition) (statusRelayNative, error) {
	var zero statusRelayNative
	if ctx == nil || ctx.Err() != nil || nilClient(client) || validateStatusRelayReference(d) != nil {
		return zero, ErrInstall
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return zero, ErrInstall
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(15 * time.Second)
	for _, end := range []time.Time{deadline, d.Until} {
		if end.Before(until) {
			until = end
		}
	}
	if started.Before(d.NotBefore) || !started.Before(until) {
		return zero, ErrInstall
	}
	active, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	coreRaw, e := readBootstrapSourcePin(d.Deployment, 262144)
	var core struct {
		Version        string          `json:"schema_version"`
		Installation   string          `json:"installation_id"`
		Namespace      string          `json:"namespace"`
		NamespaceUID   string          `json:"namespace_uid"`
		ControlURL     string          `json:"control_url"`
		RuntimeSources json.RawMessage `json:"runtime_sources"`
	}
	if e != nil || json.Unmarshal(coreRaw, &core) != nil || core.Version != "system-backup-public-deployment.v1" || core.Installation != target.InstallationID || core.Namespace != target.Namespace || core.NamespaceUID != target.NamespaceUID || len(core.RuntimeSources) == 0 || string(core.RuntimeSources) == "null" {
		return zero, ErrInstall
	}
	base, e := url.Parse(core.ControlURL)
	if e != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		return zero, ErrInstall
	}
	base.Path = "/relay"
	if base.String() != d.Endpoint {
		return zero, ErrInstall
	}
	first, e := statusRelayHost(active, client, target, d)
	if e != nil {
		return zero, ErrInstall
	}
	leaf, spki, tlsUntil, e := statusRelayTLS(active, d)
	if e != nil {
		return zero, ErrInstall
	}
	last, e := statusRelayHost(active, client, target, d)
	if e != nil || first != last {
		return zero, ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{d.Deployment, d.CA, d.ClientCertificate, d.ClientPrivateKey} {
		raw, e := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if e != nil {
			return zero, ErrInstall
		}
	}
	if tlsUntil.Before(until) {
		until = tlsUntil
	}
	if active.Err() != nil || !time.Now().Before(until) {
		return zero, ErrInstall
	}
	first.LeafSHA256, first.SPKISHA256 = leaf, spki
	raw, e := canonical(first)
	if e != nil {
		return zero, ErrInstall
	}
	return statusRelayNative{identity: hash(raw), started: started, until: until}, nil
}
