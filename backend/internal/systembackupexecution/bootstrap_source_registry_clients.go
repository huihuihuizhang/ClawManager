package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

type bootstrapSourceReadTransport struct {
	reader *bootstrapSourceRegistryReader
	host   string
	base   http.RoundTripper
}

func (t bootstrapSourceReadTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil || t.reader.access.Check(t.reader.ctx) != nil {
		return nil, install.ErrInstall
	}
	if r.Method != "GET" && r.Method != "HEAD" && (r.Method != "POST" || r.URL.Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" && r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews") {
		return nil, install.ErrInstall
	}
	requestCtx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.reader.physical, cancel)
	response, err := t.base.RoundTrip(r.Clone(requestCtx))
	if err != nil {
		stop()
		cancel()
		return nil, install.ErrInstall
	}
	if t.reader.access.Check(t.reader.ctx) != nil {
		response.Body.Close()
		stop()
		cancel()
		return nil, install.ErrInstall
	}
	response.Body = &bootstrapSourceResponseBody{ReadCloser: response.Body, reader: t.reader, stop: stop, cancel: cancel}
	return response, nil
}
func (t bootstrapSourceReadTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

type bootstrapSourceResponseBody struct {
	io.ReadCloser
	reader *bootstrapSourceRegistryReader
	stop   func() bool
	cancel context.CancelFunc
}

func (b *bootstrapSourceResponseBody) Read(p []byte) (int, error) {
	if b.reader.physical.Err() != nil {
		return 0, install.ErrInstall
	}
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && b.reader.access.Check(b.reader.ctx) != nil {
		return n, install.ErrInstall
	}
	return n, err
}
func (b *bootstrapSourceResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.stop()
	b.cancel()
	if err != nil || b.reader.access.Check(b.reader.ctx) != nil {
		return install.ErrInstall
	}
	return nil
}

func (x *bootstrapSourceRegistryReader) nativeTLS(c install.BootstrapSourceConnection) (*tls.Config, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Hostname() == "" {
		return nil, install.ErrInstall
	}
	ca, err := x.access.Read(x.ctx, c.CA)
	if err != nil {
		return nil, install.ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, install.ErrInstall
	}
	return &tls.Config{RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}, nil
}

func (x *bootstrapSourceRegistryReader) sourceCredential(c install.BootstrapSourceConnection) (metadataSourceCredential, error) {
	var credential metadataSourceCredential
	raw, err := x.access.Read(x.ctx, c.Credential)
	if err != nil {
		return credential, install.ErrInstall
	}
	defer clear(raw)
	if len(raw) > 65536 || decodeMetadataCanonical(raw, &credential) != nil {
		return credential, install.ErrInstall
	}
	return credential, nil
}

func (x *bootstrapSourceRegistryReader) openMetadataClients() (_ *productionMetadataClients, resultErr error) {
	clients := &productionMetadataClients{}
	defer func() {
		if resultErr != nil {
			clients.Close()
		}
	}()
	redis, err := x.connection("source_redis")
	if err != nil {
		return nil, install.ErrInstall
	}
	rc, err := x.sourceCredential(redis)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer clear(rc.Password)
	defer clear(rc.SecretKey)
	defer clear(rc.SessionToken)
	if rc.Username != redis.Account || len(rc.Password) == 0 || rc.AccessKey != "" || len(rc.SecretKey) != 0 || len(rc.SessionToken) != 0 {
		return nil, install.ErrInstall
	}
	rtls, err := x.nativeTLS(redis)
	if err != nil {
		return nil, install.ErrInstall
	}
	ru, _ := url.Parse(redis.Endpoint)
	clients.Redis, err = root.ConnectRedis(x.physical, root.RedisOptions{Address: ru.Host, Username: rc.Username, Password: string(rc.Password), Database: x.materials.Discovery.Redis.Policy.DB, TLS: rtls, MaxReplyBytes: 1 << 20})
	if err != nil || x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	server, database, err := clients.Redis.Identity(x.physical)
	if err != nil || server != x.materials.Discovery.Redis.ServerID || database != x.materials.Discovery.Redis.Policy.DB || x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	objects, err := x.connection("source_objects")
	if err != nil {
		return nil, install.ErrInstall
	}
	oc, err := x.sourceCredential(objects)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer clear(oc.Password)
	defer clear(oc.SecretKey)
	defer clear(oc.SessionToken)
	if oc.AccessKey != objects.Account || len(oc.SecretKey) == 0 || oc.Username != "" || len(oc.Password) != 0 {
		return nil, install.ErrInstall
	}
	otls, err := x.nativeTLS(objects)
	if err != nil {
		return nil, install.ErrInstall
	}
	ou, _ := url.Parse(objects.Endpoint)
	transport := bootstrapSourceReadTransport{reader: x, host: ou.Host, base: &http.Transport{Proxy: nil, TLSClientConfig: otls, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32768, DisableCompression: true}}
	clients.transports = append(clients.transports, &http.Client{Transport: transport})
	clients.Objects, err = minio.New(ou.Host, &minio.Options{Secure: true, Creds: credentials.NewStaticV4(oc.AccessKey, string(oc.SecretKey), string(oc.SessionToken)), Transport: transport})
	if err != nil {
		return nil, install.ErrInstall
	}
	apiBinding, err := x.connection("source_api")
	if err != nil {
		return nil, install.ErrInstall
	}
	ca, err := x.access.Read(x.ctx, apiBinding.CA)
	if err != nil {
		return nil, install.ErrInstall
	}
	token, err := x.access.Read(x.ctx, apiBinding.Credential)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer clear(token)
	value := strings.TrimSpace(string(token))
	if value == "" || strings.ContainsAny(value, " \t\r\n\x00") {
		return nil, install.ErrInstall
	}
	cfg := &rest.Config{Host: apiBinding.Endpoint, BearerToken: value, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, Timeout: 5 * time.Second, QPS: 5, Burst: 5}
	base, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, install.ErrInstall
	}
	au, _ := url.Parse(apiBinding.Endpoint)
	httpClient := &http.Client{Transport: bootstrapSourceReadTransport{reader: x, host: au.Host, base: base}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clients.transports = append(clients.transports, httpClient)
	clients.API, err = kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, install.ErrInstall
	}
	clients.Metadata, err = metadata.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, install.ErrInstall
	}
	clients.Dynamic, err = dynamic.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, install.ErrInstall
	}
	identity, err := clients.API.AuthenticationV1().SelfSubjectReviews().Create(x.physical, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || identity.Status.UserInfo.UID != apiBinding.Account || identity.Status.UserInfo.Username != "system:serviceaccount:"+x.config.Namespace+":"+x.materials.Discovery.SourceAPIServiceAccount || x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	return clients, nil
}

func (x *bootstrapSourceRegistryReader) checkPhysical(_ context.Context) error {
	return x.access.Check(x.ctx)
}
