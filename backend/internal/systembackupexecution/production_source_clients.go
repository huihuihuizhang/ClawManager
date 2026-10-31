package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

type productionMetadataClients struct {
	Redis      *root.RedisClient
	Objects    *minio.Client
	Metadata   metadata.Interface
	API        kubernetes.Interface
	transports []*http.Client
}

func (c *productionMetadataClients) Close() {
	if c == nil {
		return
	}
	if c.Redis != nil {
		c.Redis.Close()
	}
	for _, client := range c.transports {
		client.CloseIdleConnections()
	}
}

func sourceMetadataTLS(mapping worker.SourceTLSMapping) (*tls.Config, error) {
	if _, _, err := net.SplitHostPort(mapping.Address); err != nil || mapping.ServerName == "" || strings.ContainsAny(mapping.Address+mapping.ServerName, "/\\@?#\r\n\x00 ") {
		return nil, d.ErrNotReady
	}
	ca, err := pinnedDeploymentFile(mapping.CAFile, mapping.CASHA256, 1<<20)
	if err != nil {
		return nil, d.ErrNotReady
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, d.ErrNotReady
	}
	return &tls.Config{RootCAs: roots, ServerName: mapping.ServerName, MinVersion: tls.VersionTLS12}, nil
}

type metadataSourceCredential struct {
	Username     string `json:"username,omitempty"`
	Password     []byte `json:"password,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	SecretKey    []byte `json:"secret_key,omitempty"`
	SessionToken []byte `json:"session_token,omitempty"`
}

func readMetadataSourceCredential(m worker.FormalSourceMount) (metadataSourceCredential, error) {
	var credential metadataSourceCredential
	raw, err := readPrivate(m.CredentialFile, 64<<10)
	if err != nil {
		return credential, d.ErrNotReady
	}
	defer clear(raw)
	if hash(raw) != m.CredentialSHA256 || decodeMetadataCanonical(raw, &credential) != nil {
		clear(credential.Password)
		clear(credential.SecretKey)
		clear(credential.SessionToken)
		return metadataSourceCredential{}, d.ErrNotReady
	}
	return credential, nil
}

// Source-owner delegation is checked at each original HTTP boundary. This is
// a CONTROLLER metadata client, never a fake worker Invocation or Generate use.
type sourceMetadataTransport struct {
	authority *originalSourceMetadataAuthority
	host      string
	base      http.RoundTripper
}

func (t sourceMetadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil || t.authority.Recheck(r.Context()) != nil {
		return nil, d.ErrNotReady
	}
	if r.Method != "GET" && r.Method != "HEAD" && (r.Method != "POST" || (r.URL.Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" && r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews")) {
		return nil, d.ErrNotReady
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, d.ErrNotReady
	}
	if t.authority.Recheck(r.Context()) != nil {
		response.Body.Close()
		return nil, d.ErrNotReady
	}
	return response, nil
}
func (t sourceMetadataTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (x *originalSourceMetadataAuthority) openClients(ctx context.Context) (result *productionMetadataClients, resultErr error) {
	if x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	m := x.service.captureMaterials
	p := m.Discovery
	clients := &productionMetadataClients{}
	defer func() {
		if resultErr != nil {
			clients.Close()
		}
	}()
	if m.Redis.Redis == nil || m.Objects.Objects == nil {
		return nil, d.ErrNotReady
	}
	redisCredential, err := readMetadataSourceCredential(m.Redis)
	if err != nil {
		return nil, err
	}
	defer clear(redisCredential.Password)
	defer clear(redisCredential.SecretKey)
	defer clear(redisCredential.SessionToken)
	if redisCredential.Username == "" || len(redisCredential.Password) == 0 || redisCredential.AccessKey != "" || len(redisCredential.SecretKey) != 0 || len(redisCredential.SessionToken) != 0 {
		return nil, d.ErrNotReady
	}
	redisTLS, err := sourceMetadataTLS(*m.Redis.Redis)
	if err != nil {
		return nil, err
	}
	clients.Redis, err = root.ConnectRedis(ctx, root.RedisOptions{Address: m.Redis.Redis.Address, Username: redisCredential.Username, Password: string(redisCredential.Password), Database: p.Redis.Policy.DB, TLS: redisTLS, MaxReplyBytes: 1 << 20})
	if err != nil {
		return nil, d.ErrNotReady
	}
	if x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	server, database, err := clients.Redis.Identity(ctx)
	if err != nil || server != p.Redis.ServerID || database != p.Redis.Policy.DB || x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	objectsCredential, err := readMetadataSourceCredential(m.Objects)
	if err != nil {
		return nil, err
	}
	defer clear(objectsCredential.Password)
	defer clear(objectsCredential.SecretKey)
	defer clear(objectsCredential.SessionToken)
	if objectsCredential.AccessKey == "" || len(objectsCredential.SecretKey) == 0 || objectsCredential.Username != "" || len(objectsCredential.Password) != 0 {
		return nil, d.ErrNotReady
	}
	objectsTLS, err := sourceMetadataTLS(*m.Objects.Objects)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: objectsTLS, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32768, DisableCompression: true}
	guarded := sourceMetadataTransport{x, m.Objects.Objects.Address, transport}
	clients.transports = append(clients.transports, &http.Client{Transport: guarded})
	clients.Objects, err = minio.New(m.Objects.Objects.Address, &minio.Options{Secure: true, Creds: credentials.NewStaticV4(objectsCredential.AccessKey, string(objectsCredential.SecretKey), string(objectsCredential.SessionToken)), Transport: guarded})
	if err != nil {
		return nil, d.ErrNotReady
	}
	u, err := url.Parse(p.SourceAPI.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return nil, d.ErrNotReady
	}
	ca, err := pinnedDeploymentFile(p.SourceAPI.CAFile, p.SourceAPI.CASHA256, 1<<20)
	if err != nil {
		return nil, d.ErrNotReady
	}
	token, err := readPrivate(p.SourceAPI.TokenFile, 64<<10)
	if err != nil {
		return nil, d.ErrNotReady
	}
	defer clear(token)
	if hash(token) != p.SourceAPITokenSHA256 {
		return nil, d.ErrNotReady
	}
	value := strings.TrimSpace(string(token))
	if value == "" || strings.ContainsAny(value, " \t\r\n\x00") {
		return nil, d.ErrNotReady
	}
	cfg := &rest.Config{Host: p.SourceAPI.Server, BearerToken: value, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, Timeout: 5 * time.Second, QPS: 5, Burst: 5}
	base, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, d.ErrNotReady
	}
	client := &http.Client{Transport: sourceMetadataTransport{x, u.Host, base}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clients.transports = append(clients.transports, client)
	clients.API, err = kubernetes.NewForConfigAndClient(cfg, client)
	if err != nil {
		return nil, d.ErrNotReady
	}
	clients.Metadata, err = metadata.NewForConfigAndClient(cfg, client)
	if err != nil {
		return nil, d.ErrNotReady
	}
	identity, err := clients.API.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || identity.Status.UserInfo.Username != "system:serviceaccount:"+x.service.Config.Namespace+":"+p.SourceAPIServiceAccount || identity.Status.UserInfo.UID != p.SourceAPIServiceAccountUID || x.Recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	return clients, nil
}

func validMetadataFile(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
