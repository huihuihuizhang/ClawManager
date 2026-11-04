package systembackup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	mn "clawreef/internal/systembackup/minionative"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/signer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const minioGateMCRelease = "RELEASE.2025-08-13T08-35-41Z"
const minioGateServerVersion = "2025-09-07T16:13:09Z"
const minioGateServerCommit = "07c3a429bfed433e49018cb0f78a52145d4bedeb"

type minioGateNative struct {
	g           *MinIOReadServiceGate
	http        *http.Client
	transport   *http.Transport
	mcInfo      os.FileInfo
	mcDirectory string
}

type minioGateBoundTransport struct {
	g    *MinIOReadServiceGate
	base *http.Transport
}
type minioGateBoundBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *minioGateBoundBody) Close() error { e := b.ReadCloser.Close(); b.cancel(); return e }
func (t minioGateBoundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithDeadline(r.Context(), t.g.until)
	next := r.Clone(ctx)
	response, e := t.base.RoundTrip(next)
	if e != nil {
		cancel()
		return nil, e
	}
	response.Body = &minioGateBoundBody{response.Body, cancel}
	return response, nil
}

type minioGateBuffer struct{ bytes.Buffer }

func (b *minioGateBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}

func minioGateCredentialValid(c MinIOGateCredential, now time.Time) bool {
	return minioGateName(c.AccessKey) && len(c.SecretKey) >= 8 && len(c.SecretKey) <= 4096 && !bytes.ContainsAny(c.SecretKey, "\x00\r\n") && c.Version != "" && c.Version != "latest" && c.Version != "current" && !now.Before(c.NotBefore) && now.Before(c.Until)
}
func minioGateName(s string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(s)
}
func minioGateInputValid(in MinIOReadGateInput) bool {
	u, e := url.Parse(in.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Hostname() != in.ServerName || in.Region == "" || in.DeploymentID == "" || in.Namespace == "" || in.NamespaceUID == "" || in.Pod == "" || in.PodUID == "" || in.Container == "" || in.ImageID == "" || !minioGateName(in.Operation) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.InventorySHA256) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(in.SPKISHA256) || !filepath.IsAbs(in.CustodyDirectory) || filepath.Clean(in.CustodyDirectory) != in.CustodyDirectory || len(in.BusinessBuckets) == 0 || len(in.BusinessBuckets) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, b := range in.BusinessBuckets {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(b) || seen[b] {
			return false
		}
		seen[b] = true
	}
	if len(in.OutputAccounts) > 6 {
		return false
	}
	seen = map[string]bool{}
	for _, name := range in.OutputAccounts {
		if !minioGateName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}
func minioGateReadPin(file, sha string, max int64) ([]byte, error) {
	st, e := os.Lstat(file)
	if e != nil || !filepath.IsAbs(file) || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() < 1 || st.Size() > max {
		return nil, ErrMinIOReadGate
	}
	f, e := os.Open(file)
	if e != nil {
		return nil, ErrMinIOReadGate
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, ErrMinIOReadGate
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max || minioGateBytesHash(b) != sha {
		return nil, ErrMinIOReadGate
	}
	return b, nil
}
func newMinioGateNative(ctx context.Context, g *MinIOReadServiceGate) (*minioGateNative, error) {
	ca, e := minioGateReadPin(g.in.CAFile, g.in.CASHA256, 65536)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrMinIOReadGate
	}
	t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: g.in.ServerName, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || minioGateBytesHash(s.PeerCertificates[0].RawSubjectPublicKeyInfo) != g.in.SPKISHA256 {
			return ErrMinIOReadGate
		}
		return nil
	}}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32768, DisableCompression: true}
	guarded := minioGateBoundTransport{g: g, base: t}
	n := &minioGateNative{g: g, transport: t, http: &http.Client{Transport: guarded, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	u, _ := url.Parse(g.in.Endpoint)
	client := func(c MinIOGateCredential) (*minio.Client, error) {
		return minio.New(u.Host, &minio.Options{Secure: true, Region: g.in.Region, BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4(c.AccessKey, string(c.SecretKey), ""), Transport: guarded})
	}
	g.admin, e = client(g.credentials[1])
	if e != nil {
		n.close()
		return nil, ErrMinIOReadGate
	}
	g.reader, e = client(g.credentials[2])
	if e != nil {
		n.close()
		return nil, ErrMinIOReadGate
	}
	b, e := minioGateReadPin(g.in.MCFile, g.in.MCSHA256, 128<<20)
	clear(b)
	if e != nil {
		n.close()
		return nil, e
	}
	n.mcInfo, e = os.Lstat(g.in.MCFile)
	if e != nil || n.mcInfo.Mode().Perm()&0022 != 0 {
		n.close()
		return nil, ErrMinIOReadGate
	}
	n.mcDirectory = filepath.Join(g.in.CustodyDirectory, "mc-"+g.in.Operation)
	// All components are fixed private directories under the authenticated
	// original custody root, never an arbitrary shell/config/environment.
	for _, dir := range []string{g.in.CustodyDirectory, n.mcDirectory, filepath.Join(n.mcDirectory, "certs"), filepath.Join(n.mcDirectory, "certs", "CAs")} {
		if dir != g.in.CustodyDirectory {
			e = os.Mkdir(dir, 0700)
			if e != nil && !os.IsExist(e) {
				n.close()
				return nil, ErrMinIOReadGate
			}
		}
		st, e := os.Lstat(dir)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !redisGatePrivate(st) {
			n.close()
			return nil, ErrMinIOReadGate
		}
	}
	caPath := filepath.Join(n.mcDirectory, "certs", "CAs", "original-ca.crt")
	f, e := os.OpenFile(caPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		old, re := os.ReadFile(caPath)
		if re != nil || !bytes.Equal(old, ca) {
			n.close()
			return nil, ErrMinIOReadGate
		}
	} else if e != nil {
		n.close()
		return nil, ErrMinIOReadGate
	} else {
		_, we := f.Write(ca)
		se := f.Sync()
		ce := f.Close()
		if we != nil || se != nil || ce != nil {
			n.close()
			return nil, ErrMinIOReadGate
		}
	}
	cmd := exec.CommandContext(ctx, g.in.MCFile, "--version")
	var version minioGateBuffer
	cmd.Stdout = &version
	cmd.Stderr = io.Discard
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	if cmd.Run() != nil || !bytes.Contains(version.Bytes(), []byte("mc version "+minioGateMCRelease+" ")) {
		n.close()
		return nil, ErrMinIOReadGate
	}
	return n, nil
}
func (n *minioGateNative) close() {
	if n != nil && n.http != nil {
		n.http.CloseIdleConnections()
	}
}
func (n *minioGateNative) mc(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithDeadline(ctx, n.g.until)
	defer cancel()
	st, e := os.Lstat(n.g.in.MCFile)
	if e != nil || !os.SameFile(st, n.mcInfo) || st.Size() != n.mcInfo.Size() || !st.ModTime().Equal(n.mcInfo.ModTime()) {
		return nil, ErrMinIOReadGate
	}
	u, _ := url.Parse(n.g.in.Endpoint)
	c := n.g.credentials[1]
	u.User = url.UserPassword(c.AccessKey, string(c.SecretKey))
	cmd := exec.CommandContext(ctx, n.g.in.MCFile, append([]string{"--config-dir", n.mcDirectory, "--json"}, args...)...)
	cmd.Env = []string{"MC_HOST_native=" + u.String(), "MC_CONFIG_DIR=" + n.mcDirectory, "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.Stderr = io.Discard
	var out minioGateBuffer
	cmd.Stdout = &out
	if cmd.Run() != nil {
		clear(out.Bytes())
		return nil, ErrMinIOReadGateUnknown
	}
	return out.Bytes(), nil
}
func (n *minioGateNative) request(ctx context.Context, credential int, method, path string, query url.Values, body []byte) ([]byte, int, error) {
	if ctx == nil || ctx.Err() != nil || credential < 0 || credential > 2 || !minioGateCredentialValid(n.g.credentials[credential], time.Now()) {
		return nil, 0, ErrMinIOReadGate
	}
	ctx, cancel := context.WithDeadline(ctx, n.g.until)
	defer cancel()
	u, _ := url.Parse(n.g.in.Endpoint)
	u.Path = path
	u.RawQuery = query.Encode()
	req, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrMinIOReadGate
	}
	req.Header.Set("X-Amz-Content-Sha256", minioGateBytesHash(body))
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "application/json, text/plain")
	c := n.g.credentials[credential]
	req = signer.SignV4(*req, c.AccessKey, string(c.SecretKey), "", n.g.in.Region)
	var res *http.Response
	if method == "GET" || method == "HEAD" {
		res, e = n.http.Do(req)
	} else {
		res, e = mn.SendOnce(&http.Client{Transport: n.transport, Timeout: 20 * time.Second}, req)
	}
	if e != nil {
		return nil, 0, ErrMinIOReadGateUnknown
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "" || res.Header.Get("X-Next-Token") != "" || res.Header.Get("Link") != "" {
		return nil, 0, ErrMinIOReadGate
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
	if e != nil || len(b) > 4<<20 || res.ContentLength >= 0 && int64(len(b)) != res.ContentLength {
		return nil, 0, ErrMinIOReadGate
	}
	return b, res.StatusCode, nil
}
func (g *MinIOReadServiceGate) identity(ctx context.Context, initial bool) error {
	if ctx == nil || ctx.Err() != nil || g.check(ctx) != nil {
		return ErrMinIOReadGate
	}
	ns, e := g.kube.CoreV1().Namespaces().Get(ctx, g.in.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != g.in.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrMinIOReadGate
	}
	p, e := g.kube.CoreV1().Pods(g.in.Namespace).Get(ctx, g.in.Pod, metav1.GetOptions{})
	if e != nil || string(p.UID) != g.in.PodUID || p.DeletionTimestamp != nil {
		return ErrMinIOReadGate
	}
	found := false
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == g.in.Container {
			if found || s.ImageID != g.in.ImageID || s.ContainerID == "" || s.State.Running == nil || !s.Ready {
				return ErrMinIOReadGate
			}
			found = true
			if initial {
				g.containerID = s.ContainerID
			} else if s.ContainerID != g.containerID {
				return ErrMinIOReadGate
			}
		}
	}
	if !found {
		return ErrMinIOReadGate
	}
	b, status, e := g.native.request(ctx, 1, "GET", "/minio/admin/v3/info", url.Values{"metrics": {"false"}}, nil)
	if e != nil || status != 200 || !minioGateJSON(b) {
		return ErrMinIOReadGate
	}
	var info struct {
		DeploymentID, Region string
		Servers              []struct {
			State, Version string
			CommitID       string `json:"commitID"`
		}
	}
	if json.Unmarshal(b, &info) != nil || info.DeploymentID != g.in.DeploymentID || info.Region != g.in.Region || len(info.Servers) != 1 || info.Servers[0].State != "online" || info.Servers[0].Version != minioGateServerVersion || info.Servers[0].CommitID != minioGateServerCommit {
		return ErrMinIOReadGate
	}
	_, e = minioGateReadPin(g.in.CAFile, g.in.CASHA256, 65536)
	if e != nil || g.check(ctx) != nil {
		return ErrMinIOReadGate
	}
	return nil
}
func (n *minioGateNative) mutate(ctx context.Context, m minioGateMutation) error {
	switch m.Kind {
	case "root_access":
		if m.Target != "on" && m.Target != "off" {
			return ErrMinIOReadGate
		}
		body, e := mn.EncryptAdminData(n.g.credentials[1].SecretKey, []byte("api root_access="+m.Target))
		if e != nil {
			return e
		}
		defer clear(body)
		b, status, e := n.request(ctx, 1, "PUT", "/minio/admin/v3/set-config-kv", nil, body)
		clear(b)
		if e != nil || status != 200 {
			return ErrMinIOReadGateUnknown
		}
		return nil
	case "user_status":
		b, status, e := n.request(ctx, 1, "PUT", "/minio/admin/v3/set-user-status", url.Values{"accessKey": {m.Key}, "status": {m.Target}}, nil)
		clear(b)
		if e != nil || status != 204 && status != 200 {
			return ErrMinIOReadGateUnknown
		}
		return nil
	case "bucket_policy":
		method := "PUT"
		if m.Target == "" {
			method = "DELETE"
		}
		b, status, e := n.request(ctx, 1, method, "/"+m.Key, url.Values{"policy": {""}}, []byte(m.Target))
		clear(b)
		if e != nil || status != 200 && status != 204 {
			return ErrMinIOReadGateUnknown
		}
		return nil
	}
	return ErrMinIOReadGate
}
func (n *minioGateNative) matches(ctx context.Context, m minioGateMutation) (bool, error) {
	switch m.Kind {
	case "root_access":
		_, value, e := n.apiConfig(ctx)
		return value == m.Target, e
	case "user_status":
		u, e := n.user(ctx, m.Key)
		return u.Status == m.Target, e
	case "bucket_policy":
		p, e := n.bucketPolicy(ctx, m.Key)
		return p == m.Target, e
	}
	return false, ErrMinIOReadGate
}
func minioGateS3Missing(e error, code string) bool {
	r := minio.ToErrorResponse(e)
	return r.Code == code && r.StatusCode == 404
}
func (n *minioGateNative) bucketPolicy(ctx context.Context, bucket string) (string, error) {
	p, e := n.g.admin.GetBucketPolicy(ctx, bucket)
	if e != nil && !minioGateS3Missing(e, "NoSuchBucketPolicy") {
		return "", ErrMinIOReadGate
	}
	return p, nil
}
func minioGateXMLCode(raw []byte) (string, bool) {
	var e struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
	}
	err := xml.Unmarshal(raw, &e)
	return e.Code, err == nil && e.XMLName.Local == "Error" && e.Code != ""
}
